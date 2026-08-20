"""Tests for reading an LDAPS certificate chain — and for the fact that doing
so authenticates nothing.

Nothing here opens a socket. Every certificate is generated in-process by
``tests/synthetic_certificates`` and handed to
:func:`aditor.app.certificates.inspect_ldaps_chain` through its injected
``fetch``, so the tests run on a laptop with no domain, no network and no
keychain — which is also the operational constraint this work package was
written under. No certificate from a real domain appears in this repository.
"""

import ssl
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from aditor.app.certificates import (
    CA_CERTIFICATE_ATTRIBUTE,
    CONTAINER_ENROLLMENT,
    CONTAINER_NTAUTH,
    CONTAINER_ROOTS,
    CORROBORATION_AGREE,
    CORROBORATION_DISAGREE,
    CORROBORATION_UNAVAILABLE,
    DEFAULT_LDAPS_PORT,
    EXPIRY_WARNING_DAYS,
    SOURCE_DIRECTORY,
    SOURCE_PRESENTED,
    ChainInspection,
    DirectoryCertificates,
    _der_from_chain_entry,
    ca_certificates_from_directory,
    certificate_facts,
    compare_chain_with_directory,
    configuration_dn,
    format_fingerprint,
    inspect_ldaps_chain,
    parse_ldap_url,
    pki_container_dns,
)
from aditor.app.settings import ConnectionSettings

from .synthetic_certificates import chain, der, issue

NOW = datetime.now(timezone.utc)


def fetcher(ders, calls=None):
    """A stand-in for the TLS handshake that records how it was called."""
    def fetch(host, port, timeout):
        if calls is not None:
            calls.append((host, port, timeout))
        return list(ders)
    return fetch


def raising(exc):
    def fetch(host, port, timeout):
        raise exc
    return fetch


# --------------------------------------------------------------------------- #
# The docstring is part of the contract
# --------------------------------------------------------------------------- #

class TestTheDocstringSaysItAuthenticatesNothing:
    """Acceptance criterion 2, second half.

    The one thing that stops a later reader wiring this into a trust decision
    is the function saying, in its own docstring, that it cannot support one.
    Pinned by test because a docstring is exactly the sort of thing a tidy-up
    shortens.
    """

    def test_the_docstring_states_it_authenticates_nothing(self):
        text = " ".join((inspect_ldaps_chain.__doc__ or "").split())
        assert "authenticates nothing" in text.lower()

    def test_the_docstring_names_the_interception_case(self):
        text = " ".join((inspect_ldaps_chain.__doc__ or "").split()).lower()
        assert "intercepting" in text
        assert "unverified" in text


# --------------------------------------------------------------------------- #
# Facts about one certificate
# --------------------------------------------------------------------------- #

class TestCertificateFacts:
    def test_subject_issuer_validity_and_fingerprint_are_all_returned(self):
        facts = certificate_facts(der(chain().leaf))
        assert "dc01.test.local" in facts.subject
        assert "test-CA-Issuing" in facts.issuer
        assert facts.not_before < NOW < facts.not_after
        # 32 bytes of SHA-256, grouped for reading aloud.
        assert len(facts.fingerprint.split(":")) == 32
        assert len(facts.fingerprint_hex) == 64
        assert facts.source == SOURCE_PRESENTED

    def test_the_fingerprint_is_the_sha256_of_the_der(self):
        import hashlib

        body = der(chain().root)
        expected = hashlib.sha256(body).hexdigest()
        assert certificate_facts(body).fingerprint_hex == expected
        assert certificate_facts(body).fingerprint == format_fingerprint(
            bytes.fromhex(expected))

    def test_a_self_issued_ca_is_marked_as_both(self):
        facts = certificate_facts(der(chain().root))
        assert facts.self_issued is True
        assert facts.is_ca is True

    def test_a_leaf_is_neither_self_issued_nor_a_ca(self):
        facts = certificate_facts(der(chain().leaf))
        assert facts.self_issued is False
        assert facts.is_ca is False

    def test_the_pem_round_trips_to_the_same_certificate(self):
        facts = certificate_facts(der(chain().root))
        reloaded = x509.load_pem_x509_certificate(facts.pem.encode("ascii"))
        assert reloaded.public_bytes(
            serialization.Encoding.DER) == der(chain().root)

    def test_the_source_and_dn_are_carried_through(self):
        facts = certificate_facts(der(chain().root), SOURCE_DIRECTORY,
                                  "CN=test-CA-Root,CN=Certification "
                                  "Authorities,DC=test,DC=local")
        assert facts.source == SOURCE_DIRECTORY
        assert facts.directory_dn.startswith("CN=test-CA-Root")
        assert "Active Directory" in facts.source_label

    @pytest.mark.parametrize("body", [b"", b"not a certificate at all",
                                      b"\x30\x82\x01\x00garbage"])
    def test_rubbish_raises_rather_than_producing_empty_facts(self, body):
        with pytest.raises(ValueError):
            certificate_facts(body)


class TestExpiry:
    """Criterion 7's data half: expiry is a fact about *now*, computed on read.

    Stored booleans would be stale the moment the panel sat on screen over a
    boundary, so these are methods and ``now`` is injectable.
    """

    def test_an_expired_certificate_is_expired_and_days_go_negative(self):
        facts = certificate_facts(der(chain().expired_leaf))
        assert facts.is_expired() is True
        assert facts.days_until_expiry() < 0
        assert facts.needs_expiry_attention() is True
        # Expired is not "expiring soon": they are different sentences on
        # screen and different remedies.
        assert facts.expires_soon() is False

    def test_a_certificate_inside_the_window_expires_soon(self):
        facts = certificate_facts(der(chain().expiring_leaf))
        assert facts.is_expired() is False
        assert facts.expires_soon() is True
        assert 0 <= facts.days_until_expiry() <= EXPIRY_WARNING_DAYS
        assert facts.needs_expiry_attention() is True

    def test_a_healthy_certificate_needs_no_attention(self):
        facts = certificate_facts(der(chain().leaf))
        assert facts.is_expired() is False
        assert facts.expires_soon() is False
        assert facts.needs_expiry_attention() is False

    def test_the_window_boundary_is_where_it_says_it_is(self):
        facts = certificate_facts(der(chain().leaf))
        just_inside = facts.not_after - timedelta(days=EXPIRY_WARNING_DAYS - 1)
        just_outside = facts.not_after - timedelta(days=EXPIRY_WARNING_DAYS + 2)
        assert facts.expires_soon(now=just_inside) is True
        assert facts.expires_soon(now=just_outside) is False

    def test_a_not_yet_valid_certificate_is_its_own_state(self):
        # Clock skew on a freshly-issued DC certificate. It fails verification
        # for a reason that is neither trust nor expiry.
        future = NOW + timedelta(days=5)
        certificate, _ = issue("dc02.test.local", not_before=future,
                               not_after=future + timedelta(days=300))
        facts = certificate_facts(der(certificate))
        assert facts.is_not_yet_valid() is True
        assert facts.is_expired() is False
        assert facts.needs_expiry_attention() is True


# --------------------------------------------------------------------------- #
# Reading the chain
# --------------------------------------------------------------------------- #

class TestInspectChain:
    def test_a_three_certificate_chain_comes_back_leaf_first(self):
        result = inspect_ldaps_chain("dc01.test.local", 636,
                                     fetch=fetcher(chain().chain_der()))
        assert result.ok is True
        assert len(result.certificates) == 3
        assert "dc01.test.local" in result.leaf.subject
        assert "test-CA-Root" in result.anchor.subject
        assert result.anchor.self_issued is True
        assert result.leaf_only is False

    def test_the_host_and_port_are_passed_to_the_handshake(self):
        calls = []
        inspect_ldaps_chain("dc01.test.local", 636, timeout=3.5,
                            fetch=fetcher(chain().chain_der(), calls))
        assert calls == [("dc01.test.local", 636, 3.5)]

    def test_a_leaf_only_response_says_so(self):
        result = inspect_ldaps_chain("dc01.test.local",
                                     fetch=fetcher([der(chain().leaf)]))
        assert result.ok is True
        assert result.leaf_only is True
        # The anchor is the only thing that arrived, and it is not a root.
        assert result.anchor.self_issued is False

    def test_a_refused_port_is_reported_not_raised(self):
        result = inspect_ldaps_chain(
            "dc01.test.local", 636,
            fetch=raising(ConnectionRefusedError("[Errno 61] Connection "
                                                 "refused")))
        assert result.ok is False
        assert "Connection refused" in result.error
        assert result.certificates == ()
        assert result.leaf is None and result.anchor is None

    def test_plain_ldap_on_389_fails_as_a_handshake_error(self):
        result = inspect_ldaps_chain(
            "dc01.test.local", 389,
            fetch=raising(ssl.SSLError("[SSL: WRONG_VERSION_NUMBER] wrong "
                                       "version number")))
        assert result.ok is False
        assert "WRONG_VERSION_NUMBER" in result.error

    def test_an_empty_host_dials_nothing(self):
        def refuse(host, port, timeout):
            raise AssertionError("must not connect with an empty host")

        result = inspect_ldaps_chain("  ", fetch=refuse)
        assert result.ok is False
        assert "LDAPS server" in result.error

    def test_an_unparseable_certificate_does_not_lose_the_others(self):
        result = inspect_ldaps_chain(
            "dc01.test.local",
            fetch=fetcher([der(chain().leaf), b"junk", der(chain().root)]))
        assert result.ok is True
        assert len(result.certificates) == 2
        assert "not a DER certificate" in result.error

    def test_nothing_parseable_is_a_failure_with_the_reason(self):
        result = inspect_ldaps_chain("dc01.test.local", fetch=fetcher([b"junk"]))
        assert result.ok is False
        assert "not a DER certificate" in result.error

    def test_no_certificate_at_all_is_a_failure(self):
        result = inspect_ldaps_chain("dc01.test.local", fetch=fetcher([]))
        assert result.ok is False
        assert "no certificate" in result.error

    def test_a_nonsense_port_falls_back_to_the_ldaps_default(self):
        calls = []
        inspect_ldaps_chain("dc01.test.local", "not-a-port",
                            fetch=fetcher(chain().chain_der(), calls))
        assert calls[0][1] == DEFAULT_LDAPS_PORT

    def test_the_expired_chain_is_read_and_flagged(self):
        result = inspect_ldaps_chain("dc01.test.local",
                                     fetch=fetcher(chain().expired_chain_der()))
        assert result.ok is True
        assert result.needs_expiry_attention() is True

    def test_a_healthy_chain_needs_no_expiry_attention(self):
        result = inspect_ldaps_chain("dc01.test.local",
                                     fetch=fetcher(chain().chain_der()))
        assert result.needs_expiry_attention() is False

    def test_ok_is_not_a_trust_verdict(self):
        # The rogue chain is internally consistent and parses perfectly. ok is
        # True for it, which is the point: this function cannot tell them apart
        # and must not pretend to.
        real = inspect_ldaps_chain("dc01.test.local",
                                   fetch=fetcher(chain().chain_der()))
        rogue = inspect_ldaps_chain("dc01.test.local",
                                    fetch=fetcher(chain().rogue_chain_der()))
        assert real.ok is rogue.ok is True
        assert real.anchor.fingerprint_hex != rogue.anchor.fingerprint_hex


class TestChainInspectionShape:
    def test_an_empty_inspection_has_no_leaf_or_anchor(self):
        empty = ChainInspection(host="h", port=636)
        assert empty.leaf is None
        assert empty.anchor is None
        assert empty.needs_expiry_attention() is False


# --------------------------------------------------------------------------- #
# The two bits of plumbing that are version- and typo-sensitive
# --------------------------------------------------------------------------- #

class TestParseLdapUrl:
    @pytest.mark.parametrize("url,expected", [
        ("ldaps://dc01.example.com:636", ("dc01.example.com", 636)),
        ("ldaps://dc01.example.com", ("dc01.example.com", 636)),
        ("LDAPS://DC01.example.com:3269", ("DC01.example.com", 3269)),
        # A bare host name is what the field routinely contains, and urlparse
        # would read it as a path with no netloc.
        ("dc01.example.com", ("dc01.example.com", 636)),
        ("dc01.example.com:636", ("dc01.example.com", 636)),
        ("ldap://dc01.example.com", ("dc01.example.com", 389)),
        ("ldaps://dc01.example.com:636/", ("dc01.example.com", 636)),
        ("ldaps://192.0.2.10:636", ("192.0.2.10", 636)),
        ("ldaps://[2001:db8::1]:636", ("2001:db8::1", 636)),
        ("ldaps://[2001:db8::1]", ("2001:db8::1", 636)),
        ("", ("", 636)),
        ("   ", ("", 636)),
    ])
    def test_host_and_port(self, url, expected):
        assert parse_ldap_url(url) == expected


class TestDerNormalisation:
    """``get_unverified_chain`` returns a different shape per Python version.

    3.13 exposes it publicly and returns DER bytes; 3.12 has it only on the
    private ``_sslobj`` and returns ``_ssl.Certificate`` objects. Both shapes
    are covered here so the fallback is not discovered on a version upgrade.
    """

    def test_plain_der_bytes_pass_through(self):
        body = der(chain().root)
        assert _der_from_chain_entry(body) == body
        assert _der_from_chain_entry(bytearray(body)) == body

    def test_an_object_with_public_bytes_taking_an_encoding(self):
        body = der(chain().root)

        class Entry:
            def public_bytes(self, encoding=None):
                assert encoding is not None
                return body

        assert _der_from_chain_entry(Entry()) == body

    def test_an_object_that_only_yields_pem(self):
        body = der(chain().root)
        text = x509.load_der_x509_certificate(body).public_bytes(
            serialization.Encoding.PEM).decode("ascii")

        class PemOnly:
            def public_bytes(self, encoding=None):
                if encoding is not None:
                    raise TypeError("no DER here")
                return text

        assert _der_from_chain_entry(PemOnly()) == body

    def test_anything_else_is_none_rather_than_an_exception(self):
        assert _der_from_chain_entry(object()) is None
        assert _der_from_chain_entry(None) is None


# --------------------------------------------------------------------------- #
# The second source of truth: what the directory publishes
# --------------------------------------------------------------------------- #

BASE_DN = "DC=test,DC=local"


def a_connection(**overrides):
    values = {
        "server": "ldaps://dc01.test.local:636",
        "domain": "test.local",
        "base_dn": BASE_DN,
        "bind_dn": f"CN=svc-aditor,OU=Service Accounts,{BASE_DN}",
        "validate_certificate": True,
    }
    values.update(overrides)
    return ConnectionSettings(**values)


class StubDirectory:
    """Stands in for LDAPManager: answers searches from a per-container map."""

    def __init__(self, entries=None, errors=None):
        self._entries = entries or {}
        self._errors = errors or {}
        self.searched = []
        self.disconnected = False

    def search(self, search_base, search_filter, attributes=None, **kwargs):
        self.searched.append((search_base, search_filter))
        for needle, error in self._errors.items():
            if needle in search_base:
                raise error
        for needle, rows in self._entries.items():
            if needle in search_base:
                return rows
        return []

    def disconnect(self):
        self.disconnected = True


def factory_for(manager):
    def factory(active, security, performance):
        manager.ad_config = active
        manager.security_config = security
        manager.performance_config = performance
        return manager
    return factory


def ca_entry(certificate, cn="test-CA-Root", container=CONTAINER_ROOTS,
             attribute=None):
    return {
        "dn": f"CN={cn},CN={container},CN=Public Key Services,CN=Services,"
              f"CN=Configuration,{BASE_DN}",
        "attributes": {
            "cn": cn,
            CA_CERTIFICATE_ATTRIBUTE: (der(certificate) if attribute is None
                                       else attribute),
        },
    }


class TestContainerDns:
    def test_the_configuration_naming_context_is_derived_from_the_base_dn(self):
        assert configuration_dn(BASE_DN) == f"CN=Configuration,{BASE_DN}"
        assert configuration_dn("  ") == ""

    def test_the_three_containers_are_the_documented_ones(self):
        labels = [label for label, _ in pki_container_dns(BASE_DN)]
        assert labels == [CONTAINER_ROOTS, CONTAINER_NTAUTH,
                          CONTAINER_ENROLLMENT]
        first = dict(pki_container_dns(BASE_DN))[CONTAINER_ROOTS]
        assert first == ("CN=Certification Authorities,CN=Public Key Services,"
                         f"CN=Services,CN=Configuration,{BASE_DN}")

    def test_no_base_dn_means_no_containers(self):
        assert pki_container_dns("") == ()


class TestDirectoryRead:
    def test_a_published_root_comes_back_tagged_as_from_the_directory(self):
        manager = StubDirectory(
            {CONTAINER_ROOTS: [ca_entry(chain().root)]})
        result = ca_certificates_from_directory(
            a_connection(), "pw", factory_for(manager))
        assert result.ok is True
        assert len(result.certificates) == 1
        found = result.certificates[0]
        assert found.source == SOURCE_DIRECTORY
        assert found.fingerprint_hex == certificate_facts(
            der(chain().root)).fingerprint_hex
        assert "CN=Certification Authorities" in found.directory_dn
        assert manager.disconnected is True

    def test_all_three_containers_are_searched(self):
        manager = StubDirectory()
        ca_certificates_from_directory(a_connection(), "pw",
                                       factory_for(manager))
        bases = [base for base, _ in manager.searched]
        assert len(bases) == 3
        assert any("CN=Certification Authorities" in base for base in bases)
        assert any("CN=NTAuthCertificates" in base for base in bases)
        assert any("CN=Enrollment Services" in base for base in bases)
        # Only entries that actually carry a certificate.
        assert all(filt == f"({CA_CERTIFICATE_ATTRIBUTE}=*)"
                   for _, filt in manager.searched)

    def test_the_same_root_in_two_containers_is_listed_once(self):
        manager = StubDirectory({
            CONTAINER_ROOTS: [ca_entry(chain().root)],
            CONTAINER_NTAUTH: [ca_entry(chain().root,
                                        container=CONTAINER_NTAUTH)],
        })
        result = ca_certificates_from_directory(a_connection(), "pw",
                                                factory_for(manager))
        assert len(result.certificates) == 1
        # But both containers still report having held one.
        counts = {item.label: item.count for item in result.containers}
        assert counts[CONTAINER_ROOTS] == 1
        assert counts[CONTAINER_NTAUTH] == 1

    def test_one_unreadable_container_does_not_discard_the_others(self):
        manager = StubDirectory(
            {CONTAINER_ROOTS: [ca_entry(chain().root)]},
            {CONTAINER_NTAUTH: RuntimeError("insufficientAccessRights")})
        result = ca_certificates_from_directory(a_connection(), "pw",
                                                factory_for(manager))
        assert result.ok is True
        assert len(result.certificates) == 1
        failed = [item for item in result.containers if not item.ok]
        assert [item.label for item in failed] == [CONTAINER_NTAUTH]
        assert "insufficientAccessRights" in result.error

    def test_every_container_failing_is_not_ok(self):
        manager = StubDirectory(errors={"CN=": RuntimeError(
            "[SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer "
            "certificate")})
        result = ca_certificates_from_directory(a_connection(), "pw",
                                                factory_for(manager))
        assert result.ok is False
        assert "CERTIFICATE_VERIFY_FAILED" in result.error

    def test_no_base_dn_reads_nothing_and_says_why(self):
        def refuse(*args):
            raise AssertionError("must not build a manager without a base DN")

        result = ca_certificates_from_directory(a_connection(base_dn=""), "pw",
                                                refuse)
        assert result.ok is False
        assert "Base DN" in result.error

    def test_the_operators_validation_setting_is_reported_not_changed(self):
        for validate in (True, False):
            settings = a_connection(validate_certificate=validate)
            manager = StubDirectory({CONTAINER_ROOTS: [ca_entry(chain().root)]})
            result = ca_certificates_from_directory(settings, "pw",
                                                    factory_for(manager))
            assert result.validated is validate
            # And the connection it built used exactly that, unaltered.
            assert manager.security_config.validate_certificate is validate
            assert settings.validate_certificate is validate

    @pytest.mark.parametrize("shape", ["bytes", "list", "base64", "pem"])
    def test_the_attribute_shapes_ldap3_actually_returns(self, shape):
        import base64 as b64

        body = der(chain().root)
        value = {
            "bytes": body,
            "list": [body],
            "base64": b64.b64encode(body).decode("ascii"),
            "pem": x509.load_der_x509_certificate(body).public_bytes(
                serialization.Encoding.PEM).decode("ascii"),
        }[shape]
        manager = StubDirectory(
            {CONTAINER_ROOTS: [ca_entry(chain().root, attribute=value)]})
        result = ca_certificates_from_directory(a_connection(), "pw",
                                                factory_for(manager))
        assert [item.fingerprint_hex for item in result.certificates] == [
            certificate_facts(body).fingerprint_hex]

    def test_an_entry_holding_rubbish_is_skipped_not_fatal(self):
        manager = StubDirectory({CONTAINER_ROOTS: [
            ca_entry(chain().root, cn="junk", attribute=b"not a certificate"),
            ca_entry(chain().root)]})
        result = ca_certificates_from_directory(a_connection(), "pw",
                                                factory_for(manager))
        assert result.ok is True
        assert len(result.certificates) == 1


# --------------------------------------------------------------------------- #
# The comparison — three outcomes, and the third is not a shade of the first
# --------------------------------------------------------------------------- #

def a_directory(certificates=(), ok=True, error="", validated=True):
    return DirectoryCertificates(
        ok=ok,
        certificates=tuple(certificate_facts(der(item), SOURCE_DIRECTORY,
                                             f"CN={index},{BASE_DN}")
                           for index, item in enumerate(certificates)),
        error=error, validated=validated, base_dn=BASE_DN)


def an_inspection(ders):
    return inspect_ldaps_chain("dc01.test.local", fetch=fetcher(ders))


class TestComparison:
    def test_the_three_outcomes_are_three_distinct_values(self):
        assert len({CORROBORATION_AGREE, CORROBORATION_DISAGREE,
                    CORROBORATION_UNAVAILABLE}) == 3

    def test_a_chain_terminating_in_a_published_ca_agrees(self):
        result = compare_chain_with_directory(
            an_inspection(chain().chain_der()),
            a_directory([chain().root]))
        assert result.outcome == CORROBORATION_AGREE
        assert result.agrees is True
        assert result.disagrees is False
        assert result.unavailable is False
        assert result.match is not None
        assert result.independent is True

    def test_agreement_over_an_unvalidated_read_is_flagged_as_weaker(self):
        result = compare_chain_with_directory(
            an_inspection(chain().chain_der()),
            a_directory([chain().root], validated=False))
        assert result.outcome == CORROBORATION_AGREE
        assert result.independent is False
        assert "same" in result.detail and "unauthenticated" in result.detail
        assert "not proof" in result.detail

    def test_an_interceptors_chain_disagrees(self):
        result = compare_chain_with_directory(
            an_inspection(chain().rogue_chain_der()),
            a_directory([chain().root]))
        assert result.outcome == CORROBORATION_DISAGREE
        assert result.match is None
        assert "compromised" in result.detail

    def test_a_genuine_intermediate_under_a_rogue_anchor_is_not_agreement(self):
        # The alarming shape: the chain carries a real published CA but ends
        # somewhere else.
        rogue_first = [der(chain().rogue_leaf), der(chain().issuing),
                       der(chain().rogue_root)]
        result = compare_chain_with_directory(
            an_inspection(rogue_first), a_directory([chain().issuing]))
        assert result.outcome == CORROBORATION_DISAGREE
        assert result.partial and result.match is None

    def test_an_unreadable_directory_is_unavailable_not_agreement(self):
        result = compare_chain_with_directory(
            an_inspection(chain().chain_der()),
            a_directory(ok=False, error="insufficientAccessRights"))
        assert result.outcome == CORROBORATION_UNAVAILABLE
        assert result.agrees is False
        assert result.reason
        assert "insufficientAccessRights" in result.detail

    def test_a_directory_with_no_published_ca_is_unavailable(self):
        result = compare_chain_with_directory(
            an_inspection(chain().chain_der()), a_directory([]))
        assert result.outcome == CORROBORATION_UNAVAILABLE
        assert "nothing to compare" in result.detail

    def test_no_chain_at_all_is_unavailable(self):
        result = compare_chain_with_directory(
            inspect_ldaps_chain("dc01.test.local",
                                fetch=raising(TimeoutError("timed out"))),
            a_directory([chain().root]))
        assert result.outcome == CORROBORATION_UNAVAILABLE

    def test_a_leaf_only_chain_cannot_be_corroborated(self):
        result = compare_chain_with_directory(
            an_inspection([der(chain().leaf)]), a_directory([chain().root]))
        assert result.outcome == CORROBORATION_UNAVAILABLE
        assert result.reason == "the server sent only its own certificate"

    def test_a_self_signed_dc_certificate_is_still_compared(self):
        # A DC presenting a single self-issued certificate has an anchor: the
        # certificate itself. That is comparable, and often the real answer.
        self_signed, _ = issue("dc03.test.local", not_before=NOW - timedelta(
            days=10), not_after=NOW + timedelta(days=300), is_ca=True)
        result = compare_chain_with_directory(
            an_inspection([der(self_signed)]), a_directory([self_signed]))
        assert result.outcome == CORROBORATION_AGREE

    def test_every_unavailable_case_carries_a_reason_and_no_match(self):
        cases = [
            compare_chain_with_directory(
                an_inspection(chain().chain_der()), a_directory(ok=False)),
            compare_chain_with_directory(
                an_inspection(chain().chain_der()), a_directory([])),
            compare_chain_with_directory(
                an_inspection([der(chain().leaf)]),
                a_directory([chain().root])),
            compare_chain_with_directory(
                inspect_ldaps_chain("h", fetch=fetcher([])),
                a_directory([chain().root])),
        ]
        for case in cases:
            assert case.outcome == CORROBORATION_UNAVAILABLE
            assert case.reason
            assert case.match is None
            assert case.agrees is False
            # The headline itself has to refuse to read as a pass.
            assert "not a pass" in case.headline
