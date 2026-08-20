"""Throwaway certificates, generated in this process, for the LDAPS-trust tests.

**No certificate from a real domain is in this repository.** Everything the
certificate tests look at is built here, at test time, with keys that exist for
the length of one pytest run and are thrown away — which is also the only way
these tests can assert on an *expired* certificate or one that expires in nine
days without waiting for a real one to age.

Elliptic-curve keys rather than RSA purely for speed: a chain of three RSA-2048
keys costs the better part of a second per build, and this module is called from
several test modules.

The shapes built here mirror what a real AD CS deployment presents on 636:

* a self-issued **enterprise root** (``CA:TRUE``),
* an optional **issuing CA** under it,
* a **domain controller** leaf naming a host.

``chain_der`` returns them leaf-first, which is the order a TLS peer sends them
and therefore the order :func:`aditor.app.certificates.inspect_ldaps_chain`
receives.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def new_key():
    return ec.generate_private_key(ec.SECP256R1())


def _name(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "local"),
        x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "test"),
    ])


def issue(common_name: str, *,
          not_before: datetime,
          not_after: datetime,
          is_ca: bool = False,
          key=None,
          issuer_name: Optional[x509.Name] = None,
          issuer_key=None,
          dns_name: str = "") -> Tuple[x509.Certificate, object]:
    """One certificate plus its private key.

    With no ``issuer_key`` the certificate is self-issued, which is what makes
    it the anchor of a chain.
    """
    key = key or new_key()
    subject = _name(common_name)
    signer = issuer_key or key
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(issuer_name or subject)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(not_before.astimezone(timezone.utc)
                                 .replace(tzinfo=None))
               .not_valid_after(not_after.astimezone(timezone.utc)
                                .replace(tzinfo=None))
               .add_extension(x509.BasicConstraints(ca=is_ca,
                                                    path_length=None),
                              critical=True))
    if dns_name:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(dns_name)]),
            critical=False)
    return builder.sign(signer, hashes.SHA256()), key


def der(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.DER)


def pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


@dataclass
class SyntheticChain:
    """A root, an issuing CA and a DC leaf, plus a second unrelated root.

    ``rogue_root``/``rogue_leaf`` stand in for an interceptor: a chain that is
    internally perfectly consistent and describes itself just as confidently as
    the real one, which is the whole reason the comparison in
    :mod:`aditor.app.certificates` exists.
    """

    root: x509.Certificate
    issuing: x509.Certificate
    leaf: x509.Certificate
    rogue_root: x509.Certificate
    rogue_leaf: x509.Certificate
    expired_leaf: x509.Certificate
    expiring_leaf: x509.Certificate

    def chain_der(self) -> List[bytes]:
        """Leaf first, anchor last — the order a TLS peer sends them."""
        return [der(self.leaf), der(self.issuing), der(self.root)]

    def rogue_chain_der(self) -> List[bytes]:
        return [der(self.rogue_leaf), der(self.rogue_root)]

    def expired_chain_der(self) -> List[bytes]:
        return [der(self.expired_leaf), der(self.issuing), der(self.root)]

    def expiring_chain_der(self) -> List[bytes]:
        return [der(self.expiring_leaf), der(self.issuing), der(self.root)]


def build_chain(now: Optional[datetime] = None) -> SyntheticChain:
    now = now or datetime.now(timezone.utc)
    long_ago = now - timedelta(days=400)
    far_off = now + timedelta(days=3000)

    root, root_key = issue("test-CA-Root", not_before=long_ago,
                           not_after=far_off, is_ca=True)
    issuing, issuing_key = issue("test-CA-Issuing", not_before=long_ago,
                                 not_after=now + timedelta(days=1500),
                                 is_ca=True, issuer_name=root.subject,
                                 issuer_key=root_key)
    leaf, _ = issue("dc01.test.local", not_before=long_ago,
                    not_after=now + timedelta(days=300),
                    issuer_name=issuing.subject, issuer_key=issuing_key,
                    dns_name="dc01.test.local")
    expired_leaf, _ = issue("dc01.test.local", not_before=long_ago,
                            not_after=now - timedelta(days=3),
                            issuer_name=issuing.subject,
                            issuer_key=issuing_key,
                            dns_name="dc01.test.local")
    expiring_leaf, _ = issue("dc01.test.local", not_before=long_ago,
                             not_after=now + timedelta(days=9),
                             issuer_name=issuing.subject,
                             issuer_key=issuing_key,
                             dns_name="dc01.test.local")

    rogue_root, rogue_key = issue("Definitely-Not-An-Interceptor",
                                  not_before=long_ago, not_after=far_off,
                                  is_ca=True)
    rogue_leaf, _ = issue("dc01.test.local", not_before=long_ago,
                          not_after=now + timedelta(days=300),
                          issuer_name=rogue_root.subject,
                          issuer_key=rogue_key,
                          dns_name="dc01.test.local")

    return SyntheticChain(root=root, issuing=issuing, leaf=leaf,
                          rogue_root=rogue_root, rogue_leaf=rogue_leaf,
                          expired_leaf=expired_leaf,
                          expiring_leaf=expiring_leaf)


#: Built once per pytest session. Key generation is cheap on EC but not free,
#: and every test in the suite wants the same chain.
_CACHED: Optional[SyntheticChain] = None


def chain() -> SyntheticChain:
    global _CACHED
    if _CACHED is None:
        _CACHED = build_chain()
    return _CACHED
