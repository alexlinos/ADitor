"""Fetch the CA certificate that actually issued the controller's certificate.

The problem this module exists for
----------------------------------

On a domain where LDAPS fails with ``unable to get local issuer certificate``,
the operator needs one file: the CA certificate. Everything in
:mod:`aditor.app.trust` — every platform's install command — begins with a
``{path}`` that points at it. Until that file exists the instructions are a
shape with a hole in the middle, and the panel's advice degenerates to "get the
CA certificate from the CA server itself", which is exactly the manual step an
auditing tool should be able to take off the operator's hands.

Two facts make it awkward, and both were confirmed against a live domain rather
than assumed:

1. **The controller does not send it.** An AD-autoenrolled domain controller
   certificate is presented alone — leaf only, no chain. So the TLS handshake,
   which is the one thing reachable without trust, does not carry the answer.
   :attr:`aditor.app.trust.TrustReport.exportable` is correspondingly empty, and
   the existing "Export CA certificate" button never appears.
2. **The only publisher is LDAP.** The leaf's Authority Information Access
   extension names its issuer with an ``ldap:///`` URL, not an ``http://`` one,
   so there is no unauthenticated HTTP endpoint to fetch it from. Reading it
   means an LDAP connection — the very thing that is failing.

So the fetch is deliberately made over a connection whose certificate is **not
validated**, and the safety comes from somewhere else entirely.

Why an unvalidated fetch is nonetheless sound
---------------------------------------------

Because the transport is not what is being trusted. What makes the answer
trustworthy is arithmetic:

* Every candidate is checked to see whether **its key signed the certificate the
  controller presented** (:func:`signed_the_leaf`). Only a candidate that did is
  offered.
* The operator still confirms the fingerprint out of band before installing
  anything, which the panel says on every path and this module does not weaken.

That reduces what a hostile network can achieve to nothing useful. It cannot
substitute a certificate of its choosing, because a substitute would have to
have signed the leaf — and if it did, it *is* the issuer. The worst it can do is
withhold the answer, which shows up as a failure, not as a wrong file.

This check is not a formality. On the domain this was written against, the AIA
container held **four** CA certificates — two expired predecessors and a second
issuing CA — and only one of them had signed the controller's certificate. A
button that downloaded "the CA" without checking would have handed the operator
the wrong file three times out of four, and the wrong root produces the *same*
``unable to get local issuer certificate`` error afterwards. The operator would
reasonably conclude the tool had lied to them.

What this module does not do
----------------------------

It does not install, trust, or import anything, and it does not run the command
that would. It returns bytes and facts; writing the file is
:func:`aditor.app.trust.export_ca_certificate`, and installing it stays the
operator's command to run. It also does not feed
:class:`aditor.app.certificates.Corroboration`: an unvalidated read cannot
corroborate anything, and mixing this result into that one would manufacture the
false independence the corroboration code goes out of its way to avoid claiming.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional, Sequence, Tuple
from urllib.parse import unquote, urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa

from .certificates import (
    CA_CERTIFICATE_ATTRIBUTE,
    SOURCE_DIRECTORY,
    CertificateFacts,
    _der_candidates,
    certificate_facts,
    configuration_dn,
    pki_container_dns,
)
from .credentials import redact

#: The attribute an ``ldap:///`` AIA URL asks for, and the one the CA objects
#: hold. Same attribute the published-roots read uses.
AIA_ATTRIBUTE = CA_CERTIFICATE_ATTRIBUTE

#: Where AD CS publishes issuing-CA certificates for AIA. Searched even when the
#: leaf names no AIA URL at all, because a certificate is not obliged to carry
#: one and the container is at a well-known place under the configuration NC.
AIA_CONTAINER_RDN = "CN=AIA,CN=Public Key Services,CN=Services"

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
    key = candidate.public_key()
    algorithm = leaf.signature_hash_algorithm
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

def aia_dns_from_certificate(leaf: x509.Certificate) -> Tuple[str, ...]:
    """The DNs named by the leaf's own ``caIssuers`` AIA entries.

    An ``ldap:///CN=…?cACertificate?base`` URL carries the DN in its path,
    percent-encoded. Only ``ldap``/``ldaps`` URLs are read, and only ones with
    an empty host: a URL with a host would send this app's credentials to a
    server named by a certificate it has not authenticated, which is a
    credential-disclosure hazard rather than a certificate one. ``http://`` AIA
    URLs are ignored here too — a certificate is a fine thing to fetch over
    plain HTTP, but doing it would add an outbound request to a host the
    certificate chose, and the LDAP path already answers the question.
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
        if description.access_method != x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
            continue
        location = description.access_location
        if not isinstance(location, x509.UniformResourceIdentifier):
            continue
        parts = urlsplit(str(location.value))
        if parts.scheme.lower() not in ("ldap", "ldaps"):
            continue
        if parts.netloc:
            # A host we would have to trust on the strength of the very
            # certificate under suspicion. Not followed.
            continue
        dn = unquote(parts.path).lstrip("/").strip()
        if dn and dn not in found:
            found.append(dn)
    return tuple(found)


def _within(dn: str, suffix: str) -> bool:
    """Is ``dn`` inside ``suffix``? Case-insensitive, whitespace-tolerant."""
    def normalise(value: str) -> str:
        return ",".join(part.strip() for part in value.split(",")).lower()

    if not dn or not suffix:
        return False
    a, b = normalise(dn), normalise(suffix)
    return a == b or a.endswith("," + b)


def search_targets(leaf: x509.Certificate, base_dn: str) -> Tuple[str, ...]:
    """Every DN worth searching for the issuer, most specific first.

    The leaf's own AIA DNs come first — they are the certificate's own statement
    about where its issuer lives, so they are the shortest path to the right
    answer. They are then **confined to this forest's configuration naming
    context**: the URL comes from a certificate presented by a server that has
    not been authenticated, so an attacker chooses that string. Confining it
    means the worst a chosen DN can do is name a container that will be searched
    on the controller the operator typed in, which is where the search was going
    anyway.

    The well-known containers follow, so a certificate carrying no AIA extension
    — or one whose AIA points somewhere else — still gets an answer.
    """
    configuration = configuration_dn(base_dn)
    if not configuration:
        return ()

    targets: List[str] = []

    def add(dn: str) -> None:
        if dn and not any(_within(dn, seen) and _within(seen, dn)
                          for seen in targets):
            targets.append(dn)

    for dn in aia_dns_from_certificate(leaf):
        if _within(dn, configuration):
            add(dn)
        # else: a DN outside the configuration NC. Silently not searched --
        # it is attacker-chosen text, and logging it would put a string of the
        # attacker's choosing into the operator's log.

    add(f"{AIA_CONTAINER_RDN},{configuration}")
    for _label, dn in pki_container_dns(base_dn):
        add(dn)
    return tuple(targets)


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

def _unvalidated_settings(settings: Any) -> Any:
    """``settings`` with certificate validation off, for this fetch only.

    A copy. Turning validation off on the operator's saved settings would be a
    change they did not make, would outlive this call, and would silently weaken
    every later connection — including the scan.
    """
    try:
        return settings.with_values(validate_certificate=False)
    except Exception:  # pragma: no cover - not a ConnectionSettings
        from dataclasses import replace as replace_dataclass
        return replace_dataclass(settings, validate_certificate=False)


def fetch_issuing_ca(settings: Any, password: str,
                     leaf: CertificateFacts,
                     factory: Optional[Any] = None) -> IssuerFetch:
    """Find and return the CA certificate that signed ``leaf``.

    Args:
        settings: The connection as it stands on the Connection screen. Used for
            the server, base DN and bind account; **not** for the certificate
            setting, which is overridden to off for this call and this call only
            — see :func:`_unvalidated_settings` and the module docstring.
        password: The bind password, held for this call only.
        leaf: The certificate the controller presented, as already shown on the
            panel. Passed in rather than re-fetched so the certificate this
            proves an issuer *for* is the one the operator is looking at; a
            second handshake could return something else.
        factory: Injected manager builder, for tests. Production passes nothing.

    Returns:
        An :class:`IssuerFetch`. Never raises for a directory or network
        problem — a failed fetch is a rendered outcome, not an exception.
    """
    base_dn = str(getattr(settings, "base_dn", "") or "").strip()
    if not base_dn:
        return _unavailable(
            "There is no Base DN to search.",
            "The issuing CA is published under the forest's configuration "
            "naming context, which is derived from the Base DN. Fill it in on "
            "the Connection screen.")
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

    targets = search_targets(leaf_certificate, base_dn)
    if not targets:
        return _unavailable(
            "There is nowhere to search.",
            f"No configuration naming context could be derived from "
            f"{base_dn!r}.")

    from .connection import build_manager

    # Deliberately unvalidated. The module docstring is the argument for it; in
    # short, the signature check below is what is being trusted, not this.
    try:
        manager = build_manager(_unvalidated_settings(settings), password,
                               factory)
    except Exception as exc:
        return _unavailable(
            "The connection could not be built.",
            "This fetch uses the server and account from the Connection "
            "screen.", error=redact(str(exc)), searched=targets)

    candidates: List[Candidate] = []
    seen: set = set()
    failures: List[str] = []
    searched: List[str] = []

    try:
        for dn in targets:
            searched.append(dn)
            try:
                entries = manager.search(
                    search_base=dn,
                    search_filter="(objectClass=*)",
                    attributes=[AIA_ATTRIBUTE]) or []
            except Exception as exc:
                failures.append(redact(str(exc)))
                from .certificates import _connection_is_dead
                if _connection_is_dead(exc):
                    # Same reasoning as the published-roots read: after a
                    # terminal failure the remaining searches report a
                    # downstream symptom, not the cause.
                    break
                continue
            for entry in entries:
                entry = entry if isinstance(entry, dict) else {}
                attributes = entry.get("attributes")
                attributes = attributes if isinstance(attributes, dict) else {}
                entry_dn = str(entry.get("dn") or dn)
                for der in _der_candidates(attributes.get(AIA_ATTRIBUTE)):
                    try:
                        facts = certificate_facts(der, SOURCE_DIRECTORY,
                                                  entry_dn)
                    except ValueError:
                        continue
                    if facts.fingerprint_hex in seen:
                        continue
                    seen.add(facts.fingerprint_hex)
                    try:
                        certificate = x509.load_der_x509_certificate(der)
                    except Exception:
                        continue
                    verified, reason = signed_the_leaf(certificate,
                                                       leaf_certificate)
                    candidates.append(Candidate(facts=facts, verified=verified,
                                                reason=reason))
            if any(item.verified for item in candidates):
                # The proof is complete. Every further search would only add
                # certificates already known not to be the answer.
                break
    finally:
        try:
            manager.disconnect()
        except Exception:
            pass

    matches = [item for item in candidates if item.verified]
    error = "; ".join(failures)

    if matches:
        match = matches[0]
        others = len(candidates) - 1
        ruled_out = (f" {others} other certificate(s) in the directory were "
                     f"ruled out because their keys did not sign it."
                     if others > 0 else "")
        return IssuerFetch(
            outcome=FETCH_FOUND,
            headline="Found the certificate that issued this controller's.",
            detail=("Proved by signature, not by name: this certificate's "
                    "public key signed the certificate the controller "
                    "presented." + ruled_out +
                    " It was read over a connection whose certificate was not "
                    "validated, which is why it still has to be confirmed out "
                    "of band before you install it — the signature check "
                    "proves the two certificates belong together, not that "
                    "either one is legitimate."),
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
                        "ruled out."),
                candidates=tuple(candidates), searched=tuple(searched),
                error=error)
        return IssuerFetch(
            outcome=FETCH_NO_MATCH,
            headline="None of the published CA certificates signed this one.",
            detail=(f"{len(candidates)} CA certificate(s) were read from the "
                    f"directory and none of their keys signed the certificate "
                    f"this controller presented. That is worth investigating "
                    f"rather than working around: it is what a controller "
                    f"holding a certificate from a retired or foreign CA looks "
                    f"like, and it is also what an interception would look "
                    f"like."),
            candidates=tuple(candidates), searched=tuple(searched),
            error=error)

    return _unavailable(
        "No CA certificates were found to check.",
        "The containers searched held none, or could not be read. The detail "
        "below is the error from the directory.",
        error=error, searched=searched)
