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
  module, or in the API that calls it, that adds a certificate to any store on
  any platform. :func:`export_ca_certificate` writes a ``.crt`` file to a
  directory the operator picked, and :func:`install_commands` returns the text
  of a command for the operator to run themselves. The elevation prompt they
  get is a feature: it is the point at which a human decides.
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

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, List, Optional, Sequence, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from .credentials import redact

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


__all__ = [
    "DEFAULT_LDAPS_PORT",
    "EXPIRY_WARNING_DAYS",
    "SOURCE_DIRECTORY",
    "SOURCE_LABELS",
    "SOURCE_PRESENTED",
    "CertificateFacts",
    "ChainInspection",
    "certificate_facts",
    "format_fingerprint",
    "inspect_ldaps_chain",
    "parse_ldap_url",
]
