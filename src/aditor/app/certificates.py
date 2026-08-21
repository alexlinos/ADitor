"""Look at the certificate chain a domain controller presents — and
authenticate nothing by doing so.

The Connection screen already says the right thing when LDAPS fails to verify:
*install the issuing CA certificate in this machine's Trusted Root store*. What
it does not do is help with the *how*, and the how is where an administrator
loses an afternoon: which certificate, out of the two or three the controller
sent, is the one to trust; where to get it; what to type.

This module closes that gap. **It does not close it with a "Trust this"
button, and it never will.**

Why not — the trap this module is shaped around
----------------------------------------------------------------------------

The obvious implementation is: connect with verification off, capture the
chain, offer a button that drops the root into the trust store. That is
**trust-on-first-use**, and in this particular setting it is worse than
useless. The one situation in which the operator reaches this screen is the
situation in which LDAPS verification *failed*. Two things produce that
failure:

* the ordinary one — this machine has never been given the enterprise root; or
* the one that matters — something is sitting in the middle of the connection
  presenting its own certificate.

Those two look **identical** from here, because the only evidence available is
supplied by whoever is on the other end of the socket. A "Trust this" button
resolves both cases the same way: it installs whatever the far end sent. In the
second case the app would have taken a loud, obvious, correctly-detected
failure and converted it into a permanent silent compromise, with the
operator's own click as the authorisation. So:

* **Nothing here writes to a trust store.** There is no code path in this
  module, in :mod:`aditor.app.trust`, or in the API that calls them, that adds a
  certificate to any store on any platform.
  :func:`aditor.app.trust.export_ca_certificate` writes a ``.crt`` file, and
  :func:`aditor.app.trust.install_commands` returns the *text* of a command for
  the operator to run themselves. The elevation prompt they get is a feature: it
  is the point at which a human decides.
* **Every certificate carries its SHA-256 fingerprint**, and the renderer emits
  the fingerprint and the instruction to confirm it out-of-band as one
  inseparable block (see :mod:`aditor.app.render`). The fingerprint is the only
  thing that makes any of this safe, because it is the one value the operator
  can check against a source that is not this connection.
* **Nothing here reads or writes ``validate_certificate``.** Turning validation
  off stays what it already is on the Connection screen: an explicit, labelled,
  temporary choice the operator makes. The word appears in this module only in
  prose.

Corroboration, which is the part that is better than fingerprint-squinting
----------------------------------------------------------------------------

An enterprise CA publishes its certificates *in the directory*, under
``CN=Public Key Services,CN=Services,CN=Configuration,<base_dn>``. Reading
those and comparing them with the chain the controller presented gives a second
source for the same fact. If the presented chain terminates in a CA that the
directory also publishes, an interceptor would have had to control the TLS
handshake **and** the LDAP responses that carry the directory content — a
materially higher bar than swapping a certificate on the wire.

It is a higher bar, not a proof, and :func:`compare_chain_with_directory` is
careful about which it claims:

* the comparison reports **three** outcomes — agree, disagree, unavailable —
  and "unavailable" is never rendered as agreement. The whole value of the
  check is lost the moment "we could not look" reads like "we looked and it was
  fine";
* the directory read uses the connection **exactly as the operator configured
  it**. If certificate validation is on, the read is itself validated and the
  two sources are genuinely independent. If the operator has turned validation
  off, both the chain and the directory arrived over the same unauthenticated
  channel, and :attr:`Corroboration.independent` is ``False`` so the renderer
  can say so rather than overselling an agreement.
"""

from __future__ import annotations

import base64
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from .credentials import redact

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .settings import ConnectionSettings

# --------------------------------------------------------------------------- #
# Where a certificate came from. Never merged: the whole comparison below is
# about keeping these two apart.
# --------------------------------------------------------------------------- #

SOURCE_PRESENTED = "presented"
SOURCE_DIRECTORY = "directory"

SOURCE_LABELS = {
    SOURCE_PRESENTED: "Presented by the server during the TLS handshake",
    SOURCE_DIRECTORY: "Published in Active Directory",
}

#: A certificate this close to its notAfter is reported as a problem in its own
#: right. Thirty days is the shortest window in which an administrator can
#: realistically get a domain controller certificate reissued through a change
#: process, and an expiring DC certificate produces a *different* LDAPS failure
#: from an untrusted one — one the operator will otherwise chase as a trust
#: problem for an hour.
EXPIRY_WARNING_DAYS = 30

#: The default LDAPS port. 636 is TLS from the first byte; 389 is not.
DEFAULT_LDAPS_PORT = 636


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _now(now: Optional[datetime] = None) -> datetime:
    return _utc(now) if now is not None else datetime.now(timezone.utc)


def format_fingerprint(digest: bytes) -> str:
    """``AB:CD:…`` — the shape ``openssl x509 -fingerprint -sha256`` prints.

    Grouped and upper-cased because this is a value a human has to compare
    against another screen, character by character, and 64 unbroken hex digits
    is where that comparison silently stops happening.
    """
    return ":".join(f"{byte:02X}" for byte in digest)


# --------------------------------------------------------------------------- #
# One certificate, as facts
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class CertificateFacts:
    """What one certificate says about itself, plus where ADitor got it.

    Every field here is **the certificate's own claim**, with the single
    exception of :attr:`source`. A certificate presented by an interceptor
    describes itself just as confidently as a real one does, so nothing on this
    object is evidence of trustworthiness and the renderer must not present it
    as such. :attr:`fingerprint` is the only field that is *useful* against a
    liar, and only because it can be compared with a value obtained somewhere
    else.
    """

    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    #: SHA-256 over the DER, grouped as ``AB:CD:…`` for reading aloud.
    fingerprint: str
    #: The same digest as unbroken lower-case hex. This is what code compares;
    #: :attr:`fingerprint` is what humans compare.
    fingerprint_hex: str
    serial: str
    #: Subject equals issuer, which is what makes a certificate the *anchor* of
    #: a chain rather than a link in it. It is not evidence of anything else: a
    #: self-issued certificate is trivial to generate.
    self_issued: bool
    #: ``basicConstraints: CA:TRUE`` — again, its own claim.
    is_ca: bool
    #: The common name alone, for a short label. Falls back to the full subject.
    common_name: str = ""
    source: str = SOURCE_PRESENTED
    #: Where in the directory this came from, when :attr:`source` is
    #: ``directory``. Empty for a presented certificate.
    directory_dn: str = ""
    #: PEM text, which is what an export writes and what every install command
    #: on every platform accepts.
    pem: str = ""

    # -- validity ------------------------------------------------------------
    #
    # Methods rather than stored booleans: "expired" is a fact about *now*, and
    # a value frozen at inspection time would be stale the moment the panel sat
    # on screen over a boundary. ``now`` is injectable so the boundaries are
    # testable.

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        return _now(now) > self.not_after

    def is_not_yet_valid(self, now: Optional[datetime] = None) -> bool:
        return _now(now) < self.not_before

    def days_until_expiry(self, now: Optional[datetime] = None) -> int:
        """Whole days left. Negative once expired, which is deliberate."""
        delta = self.not_after - _now(now)
        return int(delta.total_seconds() // 86400)

    def expires_soon(self, now: Optional[datetime] = None,
                     within_days: int = EXPIRY_WARNING_DAYS) -> bool:
        """Inside the warning window but not yet expired."""
        return (not self.is_expired(now)
                and self.days_until_expiry(now) <= within_days)

    def needs_expiry_attention(self, now: Optional[datetime] = None) -> bool:
        return (self.is_expired(now) or self.is_not_yet_valid(now)
                or self.expires_soon(now))

    @property
    def label(self) -> str:
        return self.common_name or self.subject

    @property
    def source_label(self) -> str:
        return SOURCE_LABELS.get(self.source, self.source)


def _name_text(name: x509.Name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:                       # pragma: no cover - defensive
        return str(name)


def _common_name(name: x509.Name) -> str:
    try:
        attributes = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    except Exception:                       # pragma: no cover - defensive
        return ""
    if not attributes:
        return ""
    value = attributes[0].value
    return value if isinstance(value, str) else str(value)


def _not_before(certificate: x509.Certificate) -> datetime:
    value = getattr(certificate, "not_valid_before_utc", None)
    return _utc(value if value is not None else certificate.not_valid_before)


def _not_after(certificate: x509.Certificate) -> datetime:
    value = getattr(certificate, "not_valid_after_utc", None)
    return _utc(value if value is not None else certificate.not_valid_after)


def _is_ca(certificate: x509.Certificate) -> bool:
    try:
        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints)
    except x509.ExtensionNotFound:
        return False
    except Exception:                       # pragma: no cover - defensive
        return False
    return bool(constraints.value.ca)


def certificate_facts(der: bytes, source: str = SOURCE_PRESENTED,
                      directory_dn: str = "") -> CertificateFacts:
    """Parse one DER certificate into :class:`CertificateFacts`.

    Raises :class:`ValueError` for anything that is not a certificate, because
    the callers both have somewhere sensible to put that ("this directory entry
    held something that would not parse") and neither should be guessing.
    """
    if not der:
        raise ValueError("empty certificate")
    try:
        certificate = x509.load_der_x509_certificate(bytes(der))
    except Exception as exc:
        raise ValueError(f"not a DER certificate: {exc}") from exc

    digest = certificate.fingerprint(hashes.SHA256())
    return CertificateFacts(
        subject=_name_text(certificate.subject),
        issuer=_name_text(certificate.issuer),
        not_before=_not_before(certificate),
        not_after=_not_after(certificate),
        fingerprint=format_fingerprint(digest),
        fingerprint_hex=digest.hex(),
        serial=f"{certificate.serial_number:x}",
        self_issued=certificate.subject == certificate.issuer,
        is_ca=_is_ca(certificate),
        common_name=_common_name(certificate.subject),
        source=source,
        directory_dn=directory_dn,
        pem=certificate.public_bytes(serialization.Encoding.PEM
                                     ).decode("ascii"),
    )


# --------------------------------------------------------------------------- #
# The presented chain
# --------------------------------------------------------------------------- #

#: Injected in tests: host, port, timeout in, a list of DER certificates out,
#: leaf first. Production passes nothing and gets :func:`_fetch_chain_der`.
ChainFetcher = Callable[[str, int, float], Sequence[bytes]]


@dataclass(frozen=True)
class ChainInspection:
    """The chain a server presented, or the reason there is no chain.

    ``ok`` means *a chain was read*. It does not mean the chain is good, valid,
    trusted or genuine, and no caller may treat it as though it did.
    """

    host: str
    port: int
    ok: bool = False
    certificates: Tuple[CertificateFacts, ...] = ()
    error: str = ""
    #: True when only the leaf could be read — either the server sent nothing
    #: else or this Python could not reach past it. The anchor is then unknown,
    #: which the corroboration has to treat as "could not check".
    leaf_only: bool = False

    @property
    def leaf(self) -> Optional[CertificateFacts]:
        return self.certificates[0] if self.certificates else None

    @property
    def anchor(self) -> Optional[CertificateFacts]:
        """The last certificate the server sent — where the chain *terminates*.

        Named ``anchor`` rather than ``root`` on purpose. A root is something a
        machine trusts; this is merely the far end of what arrived on a socket.
        """
        return self.certificates[-1] if self.certificates else None

    def needs_expiry_attention(self, now: Optional[datetime] = None) -> bool:
        return any(item.needs_expiry_attention(now)
                   for item in self.certificates)


def parse_ldap_url(url: str) -> Tuple[str, int]:
    """``ldaps://dc01.example.com:636`` → ``("dc01.example.com", 636)``.

    Hand-rolled rather than ``urllib.parse``: the field on the Connection
    screen is routinely filled in as a bare host name, and ``urlparse`` reads
    ``dc01.example.com`` as a *path* with no netloc, which would silently
    inspect nothing.
    """
    text = str(url or "").strip()
    if not text:
        return "", DEFAULT_LDAPS_PORT
    scheme = ""
    if "://" in text:
        scheme, _, text = text.partition("://")
        scheme = scheme.lower()
    text = text.split("/", 1)[0]
    port = DEFAULT_LDAPS_PORT if scheme != "ldap" else 389
    if text.startswith("["):                       # bracketed IPv6 literal
        host, _, rest = text[1:].partition("]")
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
        return host, port
    host = text
    if ":" in text:
        head, _, tail = text.rpartition(":")
        if tail.isdigit():
            host, port = head, int(tail)
    return host, port


def _der_from_chain_entry(entry: Any) -> Optional[bytes]:
    """DER bytes out of whatever this Python's ssl module handed back.

    ``get_unverified_chain`` is a moving target across the versions ADitor has
    to run on: 3.13 exposes it publicly, 3.12 only on the private ``_sslobj``,
    and the elements are DER ``bytes`` in some versions and ``_ssl.Certificate``
    objects in others. Normalising here — with a unit test per shape — keeps
    that mess in one function instead of spread through the caller.
    """
    if isinstance(entry, (bytes, bytearray, memoryview)):
        return bytes(entry)
    public_bytes = getattr(entry, "public_bytes", None)
    if public_bytes is None:
        return None
    # 3.13 puts the constant on ``ssl``; 3.12 only has it on ``_ssl``.
    encoding_der = getattr(ssl, "ENCODING_DER", None)
    if encoding_der is None:
        try:
            import _ssl

            encoding_der = getattr(_ssl, "ENCODING_DER", None)
        except Exception:
            encoding_der = None
    if encoding_der is not None:
        try:
            return bytes(public_bytes(encoding_der))
        except Exception:
            pass
    try:
        text = public_bytes()
    except Exception:
        return None
    if isinstance(text, (bytes, bytearray)):
        try:
            text = bytes(text).decode("ascii")
        except Exception:
            return bytes(text)
    try:
        return x509.load_pem_x509_certificate(
            str(text).encode("ascii")).public_bytes(
                serialization.Encoding.DER)
    except Exception:
        return None


def _unverified_chain(tls: Any) -> List[bytes]:
    """Every certificate the peer sent, leaf first, or just the leaf.

    Falls back through: the public API, the private one, then
    ``getpeercert(binary_form=True)`` — which is guaranteed present and returns
    the leaf alone. A leaf-only result is reported as such rather than being
    passed off as a complete chain, because "the chain terminates in a
    directory-published CA" cannot be answered from the leaf.
    """
    for holder, name in ((tls, "get_unverified_chain"),
                         (getattr(tls, "_sslobj", None),
                          "get_unverified_chain")):
        getter = getattr(holder, name, None) if holder is not None else None
        if getter is None:
            continue
        try:
            entries = getter()
        except Exception:
            continue
        ders = [der for der in (_der_from_chain_entry(entry)
                                for entry in entries or ()) if der]
        if ders:
            return ders
    leaf = tls.getpeercert(binary_form=True)
    return [bytes(leaf)] if leaf else []


def _fetch_chain_der(host: str, port: int, timeout: float) -> List[bytes]:
    """Open TLS with verification off and take what the peer sends.

    The one function in ADitor that deliberately disables certificate
    verification, and it does so to *look at* a certificate, never to move data
    over the resulting socket: it sends no bind, no credentials and no bytes of
    its own, and closes immediately. Nothing about the connection succeeding
    means anything about the certificate being genuine.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            return _unverified_chain(tls)


def inspect_ldaps_chain(host: str, port: int = DEFAULT_LDAPS_PORT, *,
                        timeout: float = 10.0,
                        fetch: Optional[ChainFetcher] = None
                        ) -> ChainInspection:
    """Read the certificate chain at ``host:port``. **This authenticates
    nothing.**

    Verification is switched off for the duration of the handshake, which is
    the only way to see a chain this machine does not trust — and which means
    every value returned is an unverified claim made by whoever answered the
    socket. If someone is intercepting this connection, what comes back is
    *their* certificate, described in exactly as much detail and with exactly
    as much confidence as the real one. A successful return proves that
    something on that port speaks TLS, and no more than that.

    Consequently nothing downstream of this function may treat its result as a
    reason to trust anything. The result exists to be *compared* — against the
    CA certificates published in the directory
    (:func:`ca_certificates_from_directory`), and against a SHA-256 fingerprint
    the operator reads off the CA server itself.

    Args:
        host: Host name to connect to, as typed on the Connection screen. Used
            as SNI so a controller with more than one certificate sends the
            right one.
        port: TCP port. 636 for LDAPS.
        timeout: Seconds for the TCP connect and the handshake.
        fetch: Injected chain reader, for tests. Production passes nothing.

    Returns:
        A :class:`ChainInspection`. ``ok`` is False, with the error text, when
        nothing could be read — a closed port, a plain-LDAP port, a timeout.
    """
    host = str(host or "").strip()
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = DEFAULT_LDAPS_PORT
    if not host:
        return ChainInspection(
            host=host, port=port, ok=False,
            error="No server name to inspect. Fill in the LDAPS server field.")

    reader = fetch or _fetch_chain_der
    try:
        ders = list(reader(host, port, timeout) or [])
    except Exception as exc:
        return ChainInspection(host=host, port=port, ok=False,
                               error=redact(f"{type(exc).__name__}: {exc}"))

    certificates: List[CertificateFacts] = []
    problems: List[str] = []
    for der in ders:
        try:
            certificates.append(certificate_facts(der, SOURCE_PRESENTED))
        except ValueError as exc:
            problems.append(str(exc))

    if not certificates:
        detail = ("; ".join(problems) if problems
                  else "the server sent no certificate")
        return ChainInspection(host=host, port=port, ok=False,
                               error=redact(detail))

    return ChainInspection(host=host, port=port, ok=True,
                           certificates=tuple(certificates),
                           error=redact("; ".join(problems)),
                           leaf_only=len(certificates) == 1)


# --------------------------------------------------------------------------- #
# The second source: what the directory itself publishes
# --------------------------------------------------------------------------- #
#
# An enterprise CA writes its own certificates into the configuration naming
# context, and every domain member reads them from there. Three containers
# matter, and they are listed separately rather than swept up in one subtree
# search because they mean different things and an operator reading the panel
# needs to know which one a certificate came from:
#
#   CN=Certification Authorities   the trusted *roots* the forest publishes.
#                                  This is the container whose contents a
#                                  domain member ends up with in Trusted Root.
#   CN=NTAuthCertificates          the CAs permitted to issue certificates that
#                                  authenticate to AD. A CA here but not in the
#                                  container above is a different mistake.
#   CN=Enrollment Services         one entry per issuing CA that is actually
#                                  online and enrolling -- which is where a
#                                  domain controller's own certificate comes
#                                  from, so this is normally where the
#                                  intermediate in the presented chain appears.

PKI_SERVICES_RDN = "CN=Public Key Services,CN=Services"

CONTAINER_ROOTS = "Certification Authorities"
CONTAINER_NTAUTH = "NTAuthCertificates"
CONTAINER_ENROLLMENT = "Enrollment Services"

#: The attribute holding the DER certificate on every one of those objects.
CA_CERTIFICATE_ATTRIBUTE = "cACertificate"

#: Only entries that actually carry a certificate. A CA object with no
#: ``cACertificate`` is not evidence of anything and would render as an empty
#: row.
_CA_FILTER = f"({CA_CERTIFICATE_ATTRIBUTE}=*)"

_SEARCH_ATTRIBUTES = ("cn", CA_CERTIFICATE_ATTRIBUTE, "objectClass")


def configuration_dn(base_dn: str) -> str:
    """``DC=example,DC=com`` → ``CN=Configuration,DC=example,DC=com``.

    Derived rather than asked for. The configuration naming context is always
    ``CN=Configuration`` under the forest root, and a Connection screen that
    made an operator type a fourth DN to look at a certificate would be asking
    for input with one correct answer.
    """
    base = str(base_dn or "").strip()
    return f"CN=Configuration,{base}" if base else ""


def pki_container_dns(base_dn: str) -> Tuple[Tuple[str, str], ...]:
    """``((label, dn), …)`` for the three containers, in reading order."""
    configuration = configuration_dn(base_dn)
    if not configuration:
        return ()
    services = f"{PKI_SERVICES_RDN},{configuration}"
    return tuple(
        (label, f"CN={label},{services}")
        for label in (CONTAINER_ROOTS, CONTAINER_NTAUTH, CONTAINER_ENROLLMENT))


def _der_candidates(value: Any) -> List[bytes]:
    """Every plausible DER body inside one ``cACertificate`` attribute value.

    ldap3 hands binary attributes back as ``bytes`` most of the time, as a
    ``list`` of them when the attribute is multi-valued — ``NTAuthCertificates``
    routinely holds several — and occasionally as text, because
    :meth:`LDAPManager.search` stringifies anything without a ``.value``. All
    three shapes appear against real directories, so all three are handled and
    the caller decides what parses.
    """
    if value is None:
        return []
    if isinstance(value, (bytes, bytearray, memoryview)):
        return [bytes(value)]
    if isinstance(value, (list, tuple, set)):
        out: List[bytes] = []
        for item in value:
            out.extend(_der_candidates(item))
        return out
    text = str(value).strip()
    if not text:
        return []
    if "-----BEGIN CERTIFICATE-----" in text:
        try:
            return [x509.load_pem_x509_certificate(
                text.encode("ascii")).public_bytes(serialization.Encoding.DER)]
        except Exception:
            return []
    candidates: List[bytes] = []
    try:
        candidates.append(base64.b64decode(text, validate=True))
    except Exception:
        pass
    try:
        candidates.append(text.encode("latin-1"))
    except Exception:
        pass
    return candidates


@dataclass(frozen=True)
class ContainerResult:
    """One PKI container: what it held, or why it could not be read.

    Per container rather than one aggregate, so a permissions problem on
    ``NTAuthCertificates`` does not silently discard the roots that were read
    fine — and so the panel can say which container each certificate came from.
    """

    label: str
    dn: str
    ok: bool = False
    count: int = 0
    error: str = ""


@dataclass(frozen=True)
class DirectoryCertificates:
    """The CA certificates the directory publishes, or why there are none.

    ``ok`` means *the directory was read*. ``ok`` with an empty
    :attr:`certificates` is a real and different state — an AD deployment with
    no enterprise CA at all — and the comparison treats it as "could not check",
    never as agreement.
    """

    ok: bool = False
    certificates: Tuple[CertificateFacts, ...] = ()
    error: str = ""
    containers: Tuple[ContainerResult, ...] = ()
    #: Whether the LDAP connection that carried this read validated the
    #: controller's certificate. When False, the directory content and the
    #: presented chain arrived over the *same* unauthenticated channel, and an
    #: agreement between them is worth much less. Read from the operator's
    #: setting; never set by this module.
    validated: bool = False
    base_dn: str = ""

    @property
    def fingerprints(self) -> Dict[str, CertificateFacts]:
        return {item.fingerprint_hex: item for item in self.certificates}


def _connection_is_dead(error: Exception) -> bool:
    """Is this failure the connection itself, rather than one container?

    A permission problem on one container is worth stepping over — that is why
    the containers are searched separately. A dead connection is not: every
    remaining search will fail the same way, and after a TLS failure ldap3's
    ``Server`` reports a downstream symptom instead of the real cause.
    """
    from ..core.ldap_manager import TerminalConnectionError, is_terminal_connection_error
    if isinstance(error, TerminalConnectionError):
        return True
    return is_terminal_connection_error(error)


def ca_certificates_from_directory(settings: "ConnectionSettings",
                                   password: str,
                                   factory: Optional[Any] = None
                                   ) -> DirectoryCertificates:
    """Read the CA certificates Active Directory publishes for this forest.

    Uses the ordinary read-only LDAP connection the rest of the app uses —
    :func:`aditor.app.connection.build_manager`, with the operator's settings
    **exactly as configured**. In particular this function does not turn
    certificate validation off to get its answer, and does not turn it on:
    whichever the operator chose is what is used, and the choice is reported
    back in :attr:`DirectoryCertificates.validated` so the comparison can say
    how independent the two sources really were.

    That has a consequence worth being clear about. In the common case —
    validation on, root missing — this read fails for the same certificate
    reason the connection test failed, and the comparison comes back
    "unavailable". That is the honest answer. The operator can knowingly clear
    'Validate certificate' for one diagnostic pass to get a corroboration that
    is weaker but not worthless, and the panel says exactly that; what the app
    will not do is quietly clear it for them.

    Args:
        settings: The connection as it stands on screen.
        password: The bind password, held for this call only.
        factory: Injected manager builder, for tests. Production passes nothing.

    Returns:
        A :class:`DirectoryCertificates`. Never raises for a directory problem —
        a failed read is a rendered outcome, not an exception.
    """
    base_dn = str(getattr(settings, "base_dn", "") or "").strip()
    containers = pki_container_dns(base_dn)
    if not containers:
        return DirectoryCertificates(
            ok=False, base_dn=base_dn,
            validated=bool(getattr(settings, "validate_certificate", False)),
            error="No Base DN, so there is no configuration naming context to "
                  "read. Fill in the Base DN on the Connection screen.")

    from .connection import build_manager

    validated = bool(getattr(settings, "validate_certificate", False))
    try:
        manager = build_manager(settings, password, factory)
    except Exception as exc:
        return DirectoryCertificates(
            ok=False, base_dn=base_dn, validated=validated,
            error=redact(str(exc)))

    results: List[ContainerResult] = []
    certificates: List[CertificateFacts] = []
    seen: Set[str] = set()
    failures: List[str] = []

    try:
        for index, (label, dn) in enumerate(containers):
            try:
                entries = manager.search(
                    search_base=dn,
                    search_filter=_CA_FILTER,
                    attributes=list(_SEARCH_ATTRIBUTES)) or []
            except Exception as exc:
                message = redact(str(exc))
                failures.append(f"{label}: {message}")
                results.append(ContainerResult(label=label, dn=dn, ok=False,
                                               error=message))
                if _connection_is_dead(exc):
                    # The connection itself failed, not this container's ACL.
                    # The remaining searches cannot succeed, and after a TLS
                    # failure ldap3's Server is unusable, so they report
                    # "invalid server address" instead of the real cause —
                    # log noise that sends a reader after DNS. Stop, and say
                    # the rest went unchecked rather than letting an omission
                    # read as "checked, found nothing".
                    for skipped_label, skipped_dn in containers[index + 1:]:
                        results.append(ContainerResult(
                            label=skipped_label, dn=skipped_dn, ok=False,
                            error="Not checked: the connection had already "
                                  "failed, so this search was not attempted."))
                    break
                continue
            found = 0
            for entry in entries:
                entry = entry if isinstance(entry, dict) else {}
                attributes = entry.get("attributes")
                attributes = attributes if isinstance(attributes, dict) else {}
                entry_dn = str(entry.get("dn") or dn)
                raw = attributes.get(CA_CERTIFICATE_ATTRIBUTE)
                for candidate in _der_candidates(raw):
                    try:
                        facts = certificate_facts(candidate, SOURCE_DIRECTORY,
                                                  entry_dn)
                    except ValueError:
                        continue
                    found += 1
                    if facts.fingerprint_hex in seen:
                        # The same root legitimately appears in more than one
                        # container. Counted per container, listed once.
                        break
                    seen.add(facts.fingerprint_hex)
                    certificates.append(facts)
                    break
            results.append(ContainerResult(label=label, dn=dn, ok=True,
                                           count=found))
    finally:
        try:
            manager.disconnect()
        except Exception:
            pass

    any_read = any(item.ok for item in results)
    return DirectoryCertificates(
        ok=any_read,
        certificates=tuple(certificates),
        error="; ".join(failures),
        containers=tuple(results),
        validated=validated,
        base_dn=base_dn)


# --------------------------------------------------------------------------- #
# The comparison — three outcomes, and "unavailable" is one of them
# --------------------------------------------------------------------------- #

CORROBORATION_AGREE = "agree"
CORROBORATION_DISAGREE = "disagree"
CORROBORATION_UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class Corroboration:
    """Whether the presented chain terminates in a CA the directory publishes.

    Three outcomes, and the third is not a shade of the first.
    ``unavailable`` means *nobody checked* — no chain, no directory read, or a
    chain whose anchor never arrived. Collapsing it into ``agree`` would turn
    the one part of this feature that is better than trust-on-first-use into
    decoration, so the outcome is a string with three values rather than a
    boolean with a default.
    """

    outcome: str
    headline: str
    detail: str
    #: The directory-published certificate the presented anchor matched.
    match: Optional[CertificateFacts] = None
    #: Certificates that matched somewhere *other* than the anchor. A chain
    #: whose intermediate is published but whose anchor is not is a specific and
    #: alarming shape, and it is not an agreement.
    partial: Tuple[CertificateFacts, ...] = ()
    #: True when the directory read was itself certificate-validated, so the
    #: two sources were genuinely independent.
    independent: bool = False
    #: Why, when the outcome is ``unavailable``. Never rendered as reassurance.
    reason: str = ""

    @property
    def agrees(self) -> bool:
        return self.outcome == CORROBORATION_AGREE

    @property
    def disagrees(self) -> bool:
        return self.outcome == CORROBORATION_DISAGREE

    @property
    def unavailable(self) -> bool:
        return self.outcome == CORROBORATION_UNAVAILABLE


_UNAVAILABLE_HEADLINE = (
    "Not checked against Active Directory — this is not a pass.")


def _unavailable(reason: str, detail: str) -> Corroboration:
    return Corroboration(outcome=CORROBORATION_UNAVAILABLE,
                         headline=_UNAVAILABLE_HEADLINE,
                         detail=detail, reason=reason)


def compare_chain_with_directory(chain: ChainInspection,
                                 directory: DirectoryCertificates
                                 ) -> Corroboration:
    """Compare the presented chain's anchor with the directory's CA list.

    The question is deliberately narrow: **does the chain terminate in a CA
    that Active Directory publishes?** A match there is meaningful because an
    interceptor would have needed to control the TLS handshake *and* the LDAP
    responses carrying the configuration container. A match anywhere else is
    not the same claim and is reported as :attr:`Corroboration.partial` under a
    ``disagree``.
    """
    if not chain.ok or not chain.certificates:
        return _unavailable(
            "no chain was read",
            "No certificate chain could be read from the server, so there is "
            "nothing to compare. The connection error above is the thing to "
            "fix first.")
    anchor = chain.anchor
    if chain.leaf_only and anchor is not None and not anchor.self_issued:
        return _unavailable(
            "the server sent only its own certificate",
            "Only the server's own certificate arrived, not the CA "
            "certificates above it, so the chain has no visible anchor to "
            "compare. A domain controller normally sends the whole chain; if "
            "it does not, get the CA certificate from the CA server itself.")
    if not directory.ok:
        return _unavailable(
            "the directory could not be read",
            "Active Directory could not be read for its published CA "
            f"certificates{': ' + directory.error if directory.error else ''}. "
            "Until that read succeeds, the chain above is corroborated by "
            "nothing except itself.")
    if not directory.certificates:
        return _unavailable(
            "the directory publishes no CA certificates",
            "The configuration naming context was read but published no CA "
            "certificates, so there is nothing to compare against. That is "
            "normal in a domain with no enterprise CA — and it means this "
            "chain cannot be corroborated from the directory at all.")

    published = directory.fingerprints
    match = published.get(anchor.fingerprint_hex) if anchor else None
    partial = tuple(published[item.fingerprint_hex]
                    for item in chain.certificates
                    if item.fingerprint_hex in published
                    and (anchor is None
                         or item.fingerprint_hex != anchor.fingerprint_hex))

    if match is not None:
        detail = (
            "The certificate the chain terminates in is byte-for-byte one of "
            "the CA certificates published in this forest's configuration "
            f"naming context ({match.directory_dn or directory.base_dn}). "
            "Two sources agree.")
        if not directory.validated:
            detail += (
                " Note that certificate validation is currently off for this "
                "connection, so the directory was read over the same "
                "unauthenticated channel as the chain itself. Anything able to "
                "rewrite one could have rewritten both. This raises the bar; "
                "it is not proof.")
        else:
            detail += (
                " The directory read was itself certificate-validated, so the "
                "two sources are independent: an interceptor would have had to "
                "control the TLS handshake and the directory content.")
        return Corroboration(
            outcome=CORROBORATION_AGREE,
            headline="The presented chain terminates in a CA that Active "
                     "Directory also publishes.",
            detail=detail, match=match, partial=partial,
            independent=directory.validated)

    detail = (
        "The certificate this chain terminates in "
        f"({anchor.label if anchor else 'unknown'}) is not any of the "
        f"{len(directory.certificates)} CA certificate(s) published in this "
        "forest's configuration naming context. In a domain with an enterprise "
        "CA that is what an intercepted connection looks like. Do not trust "
        "this certificate on the strength of anything on this screen: confirm "
        "the fingerprint on the CA server itself, and if it does not match, "
        "treat the connection as compromised and stop using it.")
    if partial:
        detail += (
            " One certificate in the chain *is* published in the directory, "
            "but it is not the one the chain ends at — a chain that swaps its "
            "anchor while keeping a genuine intermediate is a deliberate shape, "
            "not a misconfiguration.")
    return Corroboration(
        outcome=CORROBORATION_DISAGREE,
        headline="The presented chain does not terminate in any CA that Active "
                 "Directory publishes.",
        detail=detail, match=None, partial=partial,
        independent=directory.validated)


__all__ = [
    "CA_CERTIFICATE_ATTRIBUTE",
    "CONTAINER_ENROLLMENT",
    "CONTAINER_NTAUTH",
    "CONTAINER_ROOTS",
    "CORROBORATION_AGREE",
    "CORROBORATION_DISAGREE",
    "CORROBORATION_UNAVAILABLE",
    "DEFAULT_LDAPS_PORT",
    "EXPIRY_WARNING_DAYS",
    "PKI_SERVICES_RDN",
    "SOURCE_DIRECTORY",
    "SOURCE_LABELS",
    "SOURCE_PRESENTED",
    "CertificateFacts",
    "ChainInspection",
    "ContainerResult",
    "Corroboration",
    "DirectoryCertificates",
    "ca_certificates_from_directory",
    "certificate_facts",
    "compare_chain_with_directory",
    "configuration_dn",
    "format_fingerprint",
    "inspect_ldaps_chain",
    "parse_ldap_url",
    "pki_container_dns",
]
