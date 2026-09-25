"""Tests for the Connection screen's test-connection path.

The thing being guarded is the failure case. A Windows administrator faced with
"something went wrong" has no next step, whereas *invalid credentials*,
*certificate not trusted* and *host unreachable* each have a different one. So
every test below either checks that the real underlying error text survives to
the surface, or that a known error text is classified into the right fix.

No domain controller is contacted: an injected factory returns a stub whose
``test_connection`` reports whatever the test wants. The error strings used are
the ones ldap3, OpenSSL and the OS socket layer actually emit.
"""

import pytest

from aditor.app.connection import (
    KIND_ACCOUNT_DISABLED,
    KIND_ACCOUNT_LOCKED,
    KIND_CERTIFICATE_EXPIRED,
    KIND_CERTIFICATE_HOSTNAME,
    KIND_DNS,
    KIND_INVALID_CREDENTIALS,
    KIND_PASSWORD_EXPIRED,
    KIND_REFUSED,
    KIND_TIMEOUT,
    KIND_TLS,
    KIND_UNKNOWN,
    KIND_UNTRUSTED_CERTIFICATE,
    build_manager,
    classify_error,
    run_connection_test,
)
from aditor.app.credentials import REDACTED, forget_secret, register_secret
from aditor.app.render import render_connection_result
from aditor.app.settings import ConnectionSettings

PASSWORD = "N0t-A-Real-Password-9f3ac1"
BASE_DN = "DC=test,DC=local"


def a_connection(**overrides) -> ConnectionSettings:
    values = {
        "server": "ldaps://dc01.test.local:636",
        "domain": "test.local",
        "base_dn": BASE_DN,
        "bind_dn": f"CN=svc-aditor,OU=Service Accounts,{BASE_DN}",
        "validate_certificate": True,
    }
    values.update(overrides)
    return ConnectionSettings(**values)


class StubManager:
    """Stands in for LDAPManager. Records that it was disconnected."""

    def __init__(self, info=None, raises=None):
        self._info = info or {}
        self._raises = raises
        self.disconnected = False
        self.ad_config = None

    def test_connection(self):
        if self._raises is not None:
            raise self._raises
        return self._info

    def disconnect(self):
        self.disconnected = True


def factory_for(manager):
    def factory(active, security, performance):
        manager.ad_config = active
        manager.security_config = security
        manager.performance_config = performance
        return manager
    return factory


def failing(error):
    """A stub whose bind fails with this exact underlying error text."""
    return factory_for(StubManager({"connected": False, "error": error}))


# --------------------------------------------------------------------------- #
# Classification — every branch, from strings the real stack emits
# --------------------------------------------------------------------------- #

class TestClassification:
    @pytest.mark.parametrize("error,expected", [
        # ldap3's own wording for a rejected simple bind.
        ("automatic bind not successful - invalidCredentials",
         KIND_INVALID_CREDENTIALS),
        # AD's extended error inside the diagnostic message. 52e is the one an
        # administrator will actually meet.
        ("80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext "
         "error, data 52e, v4563", KIND_INVALID_CREDENTIALS),
        ("...comment: AcceptSecurityContext error, data 775, v4563",
         KIND_ACCOUNT_LOCKED),
        ("...comment: AcceptSecurityContext error, data 533, v4563",
         KIND_ACCOUNT_DISABLED),
        ("...comment: AcceptSecurityContext error, data 532, v4563",
         KIND_PASSWORD_EXPIRED),
        ("...comment: AcceptSecurityContext error, data 773, v4563",
         KIND_PASSWORD_EXPIRED),
        ("socket ssl wrapping error: [SSL: CERTIFICATE_VERIFY_FAILED] "
         "certificate verify failed: unable to get local issuer certificate "
         "(_ssl.c:1006)", KIND_UNTRUSTED_CERTIFICATE),
        # Expired is *not* untrusted. OpenSSL wraps both in one message and
        # the specific needle wins, because installing a CA certificate does
        # nothing for a certificate that is out of date.
        ("certificate has expired", KIND_CERTIFICATE_EXPIRED),
        ("socket ssl wrapping error: [SSL: CERTIFICATE_VERIFY_FAILED] "
         "certificate verify failed: certificate has expired (_ssl.c:1006)",
         KIND_CERTIFICATE_EXPIRED),
        ("hostname mismatch, certificate is not valid for 'dc01'",
         KIND_CERTIFICATE_HOSTNAME),
        ("socket ssl wrapping error: [SSL: WRONG_VERSION_NUMBER] wrong "
         "version number", KIND_TLS),
        ("socket connection error while opening: [Errno 8] nodename nor "
         "servname provided, or not known", KIND_DNS),
        ("socket connection error while opening: [Errno 61] Connection "
         "refused", KIND_REFUSED),
        ("socket connection error while opening: timed out", KIND_TIMEOUT),
    ])
    def test_the_right_kind(self, error, expected):
        kind, headline, fix = classify_error(error)
        assert kind == expected
        assert headline and fix

    def test_an_unrecognised_error_is_not_dressed_up(self):
        kind, headline, fix = classify_error(
            "LDAPExtensionError: something entirely new")
        assert kind == KIND_UNKNOWN
        # The point: it says the message above is authoritative rather than
        # pretending to know what happened.
        assert "does not recognise" in fix
        assert "went wrong" not in headline.lower()

    def test_an_empty_error_is_still_classified(self):
        assert classify_error("")[0] == KIND_UNKNOWN
        assert classify_error(None)[0] == KIND_UNKNOWN

    def test_classification_is_case_insensitive(self):
        assert classify_error("INVALIDCREDENTIALS")[0] == \
            KIND_INVALID_CREDENTIALS

    def test_the_credentials_fix_says_read_only_is_enough(self):
        _, _, fix = classify_error("invalidCredentials")
        assert "Domain Admin" in fix

    def test_the_certificate_fix_names_the_correct_remedy_first(self):
        _, _, fix = classify_error("certificate verify failed")
        # Trusting the CA is the fix; turning validation off is the diagnostic
        # step, and must not be presented as the answer.
        assert fix.index("Trusted Root") < fix.index("Validate certificate")

    def test_the_untrusted_fix_points_at_the_panel_that_does_the_work(self):
        _, _, fix = classify_error("unable to get local issuer certificate")
        # The screen told the operator *what* for one work package before it
        # told them *how*. This is the sentence that joins the two.
        assert "Certificate and trust panel" in fix
        assert "SHA-256" in fix
        # And it still refuses to be the thing that installs it.
        assert "will not install it for you" in fix

    def test_an_expired_certificate_is_not_sent_to_the_trust_store(self):
        kind, headline, fix = classify_error(
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "certificate has expired")
        assert kind == KIND_CERTIFICATE_EXPIRED
        assert "validity period" in headline
        # The whole point of splitting this out: the remedy is a reissue on the
        # controller, not anything to do with this machine's trust store.
        assert "Trusted Root" not in fix
        assert "reissued on the domain controller" in fix
        assert "clock" in fix


# --------------------------------------------------------------------------- #
# The real error text reaches the surface
# --------------------------------------------------------------------------- #

class TestFailureSurfacesTheRealError:
    def test_the_underlying_ldap_error_is_returned_verbatim(self):
        raw = ("Failed to connect to any LDAP server after 1 attempts. Last "
               "error: automatic bind not successful - invalidCredentials")
        result = run_connection_test(a_connection(), PASSWORD, failing(raw))
        assert result.ok is False
        assert result.error == raw
        assert result.kind == KIND_INVALID_CREDENTIALS

    def test_the_real_error_is_rendered_into_the_page(self):
        raw = ("socket ssl wrapping error: [SSL: CERTIFICATE_VERIFY_FAILED] "
               "certificate verify failed: unable to get local issuer "
               "certificate")
        result = run_connection_test(a_connection(), PASSWORD, failing(raw))
        html = render_connection_result(result)
        # Escaped, but present: the operator has to be able to read the DC's
        # own words, not only ADitor's reading of them.
        assert "CERTIFICATE_VERIFY_FAILED" in html
        assert "not trusted by this machine" in html

    def test_three_different_failures_produce_three_different_fixes(self):
        fixes = set()
        for raw in ("invalidCredentials",
                    "certificate verify failed: self signed certificate",
                    "[Errno 8] nodename nor servname provided"):
            result = run_connection_test(a_connection(), PASSWORD, failing(raw))
            fixes.add(result.fix)
        assert len(fixes) == 3

    def test_an_exception_from_the_manager_is_surfaced_too(self):
        manager = StubManager(raises=RuntimeError("LDAP layer exploded"))
        result = run_connection_test(a_connection(), PASSWORD,
                                     factory_for(manager))
        assert result.ok is False
        assert "LDAP layer exploded" in result.error

    def test_the_connection_is_always_released(self):
        manager = StubManager({"connected": False,
                               "error": "invalidCredentials"})
        run_connection_test(a_connection(), PASSWORD, factory_for(manager))
        assert manager.disconnected is True

    def test_a_registered_secret_is_redacted_out_of_the_error(self):
        # ldap3 does not put the bind password in its error text, but "does not
        # today" is not a property to render a page on.
        register_secret(PASSWORD)
        try:
            result = run_connection_test(
                a_connection(), PASSWORD,
                failing(f"bind failed for {PASSWORD}"))
            assert PASSWORD not in result.error
            assert REDACTED in result.error
        finally:
            forget_secret(PASSWORD)


# --------------------------------------------------------------------------- #
# Success
# --------------------------------------------------------------------------- #

class TestSuccess:
    def test_a_successful_bind_reports_the_server_facts(self):
        manager = StubManager({
            "connected": True, "server": "dc01.test.local", "port": 636,
            "ssl": True, "bound": True, "search_test": True,
            "user": f"CN=svc-aditor,OU=Service Accounts,{BASE_DN}",
        })
        result = run_connection_test(a_connection(), PASSWORD,
                                     factory_for(manager))
        assert result.ok is True
        assert result.error == ""
        assert result.details["port"] == 636
        assert "dc01.test.local" in render_connection_result(result)

    def test_a_bind_that_cannot_search_the_base_dn_warns(self):
        manager = StubManager({
            "connected": True, "server": "dc01.test.local", "port": 636,
            "ssl": True, "bound": True, "search_test": False,
            "search_error": "noSuchObject", "user": "svc",
        })
        result = run_connection_test(a_connection(), PASSWORD,
                                     factory_for(manager))
        assert result.ok is True
        assert any("Base DN" in warning for warning in result.warnings)
        assert "noSuchObject" in render_connection_result(result)

    def test_certificate_validation_off_is_warned_about_on_success(self):
        manager = StubManager({"connected": True, "server": "dc01",
                               "port": 636, "ssl": True, "bound": True,
                               "search_test": True, "user": "svc"})
        result = run_connection_test(a_connection(validate_certificate=False),
                                     PASSWORD, factory_for(manager))
        assert result.ok is True
        assert any("intercepted" in warning for warning in result.warnings)


# --------------------------------------------------------------------------- #
# Incomplete input
# --------------------------------------------------------------------------- #

class TestIncomplete:
    def test_missing_fields_are_named_and_nothing_is_dialled(self):
        called = []

        def factory(*args):
            called.append(args)
            raise AssertionError("must not build a manager")

        result = run_connection_test(a_connection(base_dn="", domain=""),
                                     PASSWORD, factory)
        assert result.ok is False
        assert result.kind == "incomplete"
        assert "Base DN" in result.fix and "Domain" in result.fix
        assert called == []

    def test_no_password_is_its_own_message(self):
        result = run_connection_test(a_connection(), "", lambda *a: None)
        assert result.kind == "incomplete"
        assert "credential store" in result.fix

    def test_a_bad_server_url_is_a_configuration_error_not_a_network_one(self):
        result = run_connection_test(a_connection(server="dc01.test.local"),
                                     PASSWORD)
        assert result.ok is False
        assert result.kind == "configuration"
        assert "ldaps://" in result.fix


# --------------------------------------------------------------------------- #
# The shared manager builder
# --------------------------------------------------------------------------- #

class TestBuildManager:
    def test_the_scan_and_the_test_are_configured_identically(self):
        # Sharing this builder is what stops a "test passed, scan failed"
        # report being filed against two different configurations.
        captured = {}

        def factory(active, security, performance):
            captured["active"] = active
            captured["security"] = security
            captured["performance"] = performance
            return object()

        build_manager(a_connection(validate_certificate=False), PASSWORD,
                      factory)
        assert captured["active"].password == PASSWORD
        assert captured["active"].base_dn == BASE_DN
        assert captured["security"].validate_certificate is False
        # One attempt, so a wrong password does not count three failed logons
        # toward the domain's lockout policy.
        assert captured["performance"].max_retries == 1

    def test_ssl_is_always_on(self):
        captured = {}

        def factory(active, security, performance):
            captured["security"] = security
            return object()

        build_manager(a_connection(), PASSWORD, factory)
        assert captured["security"].enable_tls is True
