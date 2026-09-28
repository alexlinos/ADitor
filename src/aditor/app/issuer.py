"""Find the CA certificate that issued the controller's certificate — without
sending a credential anywhere.

The problem this module exists for
----------------------------------

On a domain where LDAPS fails with ``unable to get local issuer certificate``,
the operator needs one file: the CA certificate. Everything in
:mod:`aditor.app.trust` — every platform's install command — begins with a
``{path}`` that points at it. The controller does not send it: an
AD-autoenrolled domain controller certificate is presented alone, leaf only.

Where it looks, and what it never does
--------------------------------------

It never binds to the directory. An earlier version read the CA from Active
Directory over an LDAPS session with certificate validation switched off —
unavoidably, because the certificate that would validate it is the one being
fetched — and that bind carried the operator's password. Anyone able to
intercept the session could have presented any certificate and read the
password out of the bind. Nothing here sends a credential any more.

It looks, in order, in:

1. **This computer's Windows certificate stores** (``CA`` and ``ROOT``). On a
   domain-joined Windows machine Group Policy normally places the enterprise
   CA there already, so this needs no network at all.
2. **The certificate's own web (AIA) address**, when it names an ``http(s)``
   one: a plain download, with no credentials. An ``ldap:///`` AIA address is
   not followed, because reading it needs a bind.

If neither has it, the result says how to export it by hand.

Why a candidate can be trusted to be the right one
--------------------------------------------------

Not because of where it came from. Every candidate is checked to see whether
**its key signed the certificate the controller presented**
(:func:`signed_the_leaf`), and only one that did is offered. A hostile network
cannot substitute a certificate of its choosing — a substitute would have to
have signed the leaf, and if it did, it *is* the issuer. The worst it can do is
withhold the answer. The operator still confirms the fingerprint out of band
before installing anything, which the panel says on every path.

This check is not a formality. On the domain this was written against, the
directory held **four** CA certificates — two expired predecessors and a second
issuing CA — and only one of them had signed the controller's certificate.
Installing any of the others leaves the same error behind while looking like a
fix.

What this module does not do
----------------------------

It does not install, trust, or import anything. It returns bytes and facts;
writing the file is :func:`aditor.app.trust.export_ca_certificate`, and
installing it stays the operator's command to run. It also does not feed
:class:`aditor.app.certificates.Corroboration`.
"""

from __future__ import annotations

import ssl
import sys
import urllib.request
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7

from .certificates import (
    SOURCE_AIA_DOWNLOAD,
    SOURCE_WINDOWS_STORE,
    CertificateFacts,
    certificate_facts,
)
from .credentials import redact

#: Windows certificate stores searched, in order: intermediate CAs, then roots.
WINDOWS_STORES = ("CA", "ROOT")

#: The most an AIA download may return. A CA certificate is a few kilobytes.
MAX_AIA_BYTES = 1_000_000
AIA_TIMEOUT_SECONDS = 10.0

#: ``() -> [(where, der), ...]``, injectable for tests.
StoreReader = Callable[[], List[Tuple[str, bytes]]]
#: ``(url) -> bytes``, injectable for tests.
Downloader = Callable[[str], bytes]

#: Outcomes. ``unavailable`` is a first-class answer here for the same reason it
#: is in the corroboration: "we could not tell" must never render as "no".
FETCH_FOUND = "found"
FETCH_NO_MATCH = "no_match"
FETCH_UNAVAILABLE = "unavailable"


# --------------------------------------------------------------------------- #
# Does this certificate's key actually sign that one?
# --------------------------------------------------------------------------- #

def signed_the_leaf(candidate: x509.Certificate,
                    leaf: x509.Certificate) -> Tuple[bool, str]:
    """Did ``candidate``'s public key sign ``leaf``?

    This is the whole security argument of the module, so it verifies the
    signature rather than comparing names. Comparing ``leaf.issuer`` with
    ``candidate.subject`` would be worthless here: on the domain this was built
    against, three of the four rejected candidates had a plausible-looking
    subject, and one shared the issuer's own name exactly.

    Returns:
        ``(verified, reason)``. ``verified`` is only ever ``True`` off the back
        of a completed signature check. A key type this build of ``cryptography``
        cannot verify returns ``(False, reason)`` with a reason that says so —
        an *unknown* answer, which the caller renders as unavailable rather than
        as a rejection, because "we cannot check" is not "it is wrong".
    """
    try:
        # Inside the guard: a real certificate store holds certificates whose
        # key this build can't even parse (found on a Windows runner's ROOT
        # store), and one of those must not take the whole fetch down.
        key = candidate.public_key()
        algorithm = leaf.signature_hash_algorithm
    except (ValueError, UnsupportedAlgorithm) as exc:
        return False, (f"ADitor could not read this certificate's key "
                       f"({redact(str(exc))}), so this candidate was neither "
                       f"confirmed nor ruled out.")
    try:
        if isinstance(key, rsa.RSAPublicKey):
            if algorithm is None:
                return False, "The certificate names no signature hash."
            key.verify(leaf.signature, leaf.tbs_certificate_bytes,
                       padding.PKCS1v15(), algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            if algorithm is None:
                return False, "The certificate names no signature hash."
            key.verify(leaf.signature, leaf.tbs_certificate_bytes,
                       ec.ECDSA(algorithm))
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(leaf.signature, leaf.tbs_certificate_bytes)
        else:
            return False, (f"ADitor cannot check a {type(key).__name__} "
                           f"signature, so this candidate was neither "
                           f"confirmed nor ruled out.")
    except InvalidSignature:
        return False, "This certificate's key did not sign the one the "\
                      "controller presented."
    except UnsupportedAlgorithm as exc:
        return False, (f"This build cannot check that signature algorithm "
                       f"({redact(str(exc))}), so the candidate was neither "
                       f"confirmed nor ruled out.")
    except Exception as exc:  # pragma: no cover - defensive
        return False, (f"The signature check itself failed: "
                       f"{redact(str(exc))}.")
    return True, "This certificate's key signed the certificate the "\
                 "controller presented."


def _is_indeterminate(reason: str) -> bool:
    """Was a candidate *not checked*, as opposed to checked and rejected?"""
    return "neither confirmed nor ruled out" in reason or "names no " in reason


# --------------------------------------------------------------------------- #
# Where to look
# --------------------------------------------------------------------------- #

def http_aia_urls(leaf: x509.Certificate) -> Tuple[str, ...]:
    """The leaf's ``caIssuers`` AIA addresses that are ``http(s)`` URLs.

    Those are a plain download with no credentials. ``ldap``/``ldaps`` ones
    are not returned: reading them means binding, which is exactly what this
    module no longer does.
    """
    try:
        extension = leaf.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess)
    except x509.ExtensionNotFound:
        return ()
    except Exception:  # pragma: no cover - malformed extension
        return ()
    found: List[str] = []
    for description in extension.value:
        if description.access_method != \
                x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
            continue
        location = description.access_location
        if not isinstance(location, x509.UniformResourceIdentifier):
            continue
        url = str(location.value).strip()
        if urlsplit(url).scheme.lower() in ("http", "https") and \
                url not in found:
            found.append(url)
    return tuple(found)


def windows_store_certificates() -> List[Tuple[str, bytes]]:
    """Every certificate in this computer's CA and ROOT stores, on Windows.

    Empty anywhere else. Reads the stores; changes nothing.
    """
    if not sys.platform.startswith("win"):
        return []
    found: List[Tuple[str, bytes]] = []
    for store in WINDOWS_STORES:
        try:
            entries = ssl.enum_certificates(store)  # type: ignore[attr-defined]
        except Exception:
            continue
        for certificate, encoding, _trust in entries:
            if encoding == "x509_asn":
                found.append((f"This computer's Windows certificate store "
                              f"({store})", bytes(certificate)))
    return found


def download_aia(url: str) -> bytes:
    """GET ``url`` with no credentials, capped in time and size."""
    if urlsplit(url).scheme.lower() not in ("http", "https"):
        raise ValueError(f"not an http(s) address: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "ADitor"})
    with urllib.request.urlopen(  # noqa: S310 - scheme checked above
            request, timeout=AIA_TIMEOUT_SECONDS) as response:
        data = response.read(MAX_AIA_BYTES + 1)
    if len(data) > MAX_AIA_BYTES:
        raise ValueError(f"{url} returned more than {MAX_AIA_BYTES} bytes")
    return data


def certificates_in(data: bytes) -> List[bytes]:
    """The DER certificates in a download: DER, PEM, or a PKCS#7 bundle."""
    for loader in (x509.load_der_x509_certificate,):
        try:
            return [loader(data).public_bytes(serialization.Encoding.DER)]
        except Exception:
            pass
    try:
        return [c.public_bytes(serialization.Encoding.DER)
                for c in x509.load_pem_x509_certificates(data)]
    except Exception:
        pass
    for loader in (pkcs7.load_der_pkcs7_certificates,
                   pkcs7.load_pem_pkcs7_certificates):
        try:
            return [c.public_bytes(serialization.Encoding.DER)
                    for c in loader(data)]
        except Exception:
            pass
    return []


# --------------------------------------------------------------------------- #
# The result
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Candidate:
    """One certificate found in the directory, and what checking it showed."""

    facts: CertificateFacts
    verified: bool
    reason: str

    @property
    def indeterminate(self) -> bool:
        return not self.verified and _is_indeterminate(self.reason)


@dataclass(frozen=True)
class IssuerFetch:
    """The issuing CA, if one could be proved, plus what was ruled out.

    ``validated_transport`` is ``False`` on every successful fetch by design and
    is carried so the renderer can say so. It is the reason this result is never
    described as corroboration.
    """

    outcome: str
    headline: str
    detail: str
    #: The one candidate whose key signed the presented certificate.
    match: Optional[CertificateFacts] = None
    #: Everything found, including the match, in the order examined.
    candidates: Tuple[Candidate, ...] = ()
    #: DNs actually searched, for a reader wondering why nothing turned up.
    searched: Tuple[str, ...] = ()
    validated_transport: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.outcome == FETCH_FOUND and self.match is not None

    @property
    def rejected(self) -> int:
        return sum(1 for item in self.candidates if not item.verified)

    @property
    def unchecked(self) -> int:
        return sum(1 for item in self.candidates if item.indeterminate)


def _unavailable(headline: str, detail: str, *, error: str = "",
                 searched: Sequence[str] = ()) -> IssuerFetch:
    return IssuerFetch(outcome=FETCH_UNAVAILABLE, headline=headline,
                       detail=detail, error=error, searched=tuple(searched))


# --------------------------------------------------------------------------- #
# The fetch
# --------------------------------------------------------------------------- #

#: What to do when neither source has it. The operator's own step.
MANUAL_EXPORT_STEPS = (
    "Export it by hand from any domain-joined Windows PC: open certlm.msc, go "
    "to Trusted Root Certification Authorities (or Intermediate Certification "
    "Authorities), find the CA that issued the controller's certificate, and "
    "export it as a Base-64 .cer file. Then point ADitor at that file with the "
    "CA certificate file setting on the Connection screen.")


def fetch_issuing_ca(leaf: CertificateFacts, *,
                     store_reader: Optional[StoreReader] = None,
                     downloader: Optional[Downloader] = None) -> IssuerFetch:
    """Find and return the CA certificate that signed ``leaf``.

    Takes no settings and no password, deliberately: nothing here binds, so
    there is no credential to leak. See the module docstring.

    Args:
        leaf: The certificate the controller presented, as already shown on the
            panel. Passed in rather than re-fetched so the certificate this
            proves an issuer *for* is the one the operator is looking at.
        store_reader: Injected Windows-store reader, for tests.
        downloader: Injected AIA downloader, for tests.

    Returns:
        An :class:`IssuerFetch`. Never raises for a network problem — a failed
        fetch is a rendered outcome, not an exception.
    """
    if not leaf or not getattr(leaf, "pem", ""):
        return _unavailable(
            "There is no presented certificate to match against.",
            "Inspect the certificate chain first. Without the controller's own "
            "certificate there is nothing to check a candidate against, and an "
            "unchecked candidate is exactly what this must not hand you.")
    try:
        leaf_certificate = x509.load_pem_x509_certificate(
            leaf.pem.encode("ascii"))
    except Exception as exc:
        return _unavailable(
            "The presented certificate could not be re-read.",
            "Inspect the chain again.", error=redact(str(exc)))

    read_stores = store_reader or windows_store_certificates
    download = downloader or download_aia
    candidates: List[Candidate] = []
    seen: set = set()
    failures: List[str] = []
    searched: List[str] = []

    def consider(der: bytes, source: str, where: str) -> None:
        try:
            facts = certificate_facts(der, source, where)
            certificate = x509.load_der_x509_certificate(der)
        except Exception:
            return
        if facts.fingerprint_hex in seen:
            return
        seen.add(facts.fingerprint_hex)
        try:
            verified, reason = signed_the_leaf(certificate, leaf_certificate)
        except Exception as exc:  # pragma: no cover - signed_the_leaf guards
            verified, reason = False, (
                f"The signature check failed ({redact(str(exc))}), so this "
                f"candidate was neither confirmed nor ruled out.")
        candidates.append(Candidate(facts=facts, verified=verified,
                                    reason=reason))

    def proved() -> bool:
        return any(item.verified for item in candidates)

    # 1. This computer's certificate stores. Only CA certificates are worth
    #    checking, but the signature check is what decides, so every
    #    certificate is simply offered to it.
    try:
        stored = read_stores()
    except Exception as exc:
        stored = []
        failures.append(f"Reading this computer's certificate stores failed: "
                        f"{redact(str(exc))}")
    if stored:
        searched.append("This computer's Windows certificate stores")
    for where, der in stored:
        consider(der, SOURCE_WINDOWS_STORE, where)
        if proved():
            break

    # 2. The certificate's own http(s) AIA address.
    if not proved():
        for url in http_aia_urls(leaf_certificate):
            searched.append(url)
            try:
                data = download(url)
            except Exception as exc:
                failures.append(f"{url}: {redact(str(exc))}")
                continue
            for der in certificates_in(data):
                consider(der, SOURCE_AIA_DOWNLOAD, url)
            if proved():
                break

    matches = [item for item in candidates if item.verified]
    error = "; ".join(failures)

    if matches:
        match = matches[0]
        others = len(candidates) - 1
        ruled_out = (f" {others} other certificate(s) were ruled out because "
                     f"their keys did not sign it." if others > 0 else "")
        return IssuerFetch(
            outcome=FETCH_FOUND,
            headline="Found the certificate that issued this controller's.",
            detail=("Proved by signature, not by name: this certificate's "
                    "public key signed the certificate the controller "
                    f"presented. It came from: {match.facts.directory_dn}."
                    + ruled_out +
                    " No password or other credential was sent to find it. "
                    "Confirm its fingerprint out of band before you install "
                    "it — the signature check proves the two certificates "
                    "belong together, not that either one is legitimate."),
            match=match.facts,
            candidates=tuple(candidates),
            searched=tuple(searched),
            validated_transport=False,
            error=error)

    if candidates:
        unchecked = sum(1 for item in candidates if item.indeterminate)
        if unchecked and unchecked == len(candidates):
            return IssuerFetch(
                outcome=FETCH_UNAVAILABLE,
                headline="The candidates could not be checked.",
                detail=("Certificates were found, but this build could not "
                        "verify their signatures, so none of them can be "
                        "offered as the issuer. Not checked is not the same as "
                        "ruled out. " + MANUAL_EXPORT_STEPS),
                candidates=tuple(candidates), searched=tuple(searched),
                error=error)
        if any(item.facts.source == SOURCE_AIA_DOWNLOAD for item in candidates):
            return IssuerFetch(
                outcome=FETCH_NO_MATCH,
                headline="None of the CA certificates found signed this one.",
                detail=("The certificate's own AIA address was downloaded, and "
                        "no certificate from it (or from this computer's "
                        "stores) signed the certificate this controller "
                        "presented. That is worth investigating rather than "
                        "working around: it is what a controller holding a "
                        "certificate from a retired or foreign CA looks like, "
                        "and it is also what an interception would look like."),
                candidates=tuple(candidates), searched=tuple(searched),
                error=error)

    return _unavailable(
        "ADitor couldn't find the issuing CA certificate on its own.",
        ("It isn't in this computer's certificate stores (or this isn't a "
         "domain-joined Windows PC), and the controller's certificate names no "
         "web address to download it from. ADitor doesn't read it from Active "
         "Directory, because that would mean sending your password over a "
         "connection it can't verify. " + MANUAL_EXPORT_STEPS),
        error=error, searched=searched)
