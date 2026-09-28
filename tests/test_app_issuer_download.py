"""The download-the-issuing-CA button, and the checks that make it safe.

The button sends **no credential**: it looks in this computer's Windows
certificate stores and at the certificate's own http(s) AIA address, never in
the directory. (An earlier version bound to the directory with the operator's
password over an unvalidated TLS session; the tests in ``TestItSendsNoCredential``
pin that it cannot again.) Where a candidate came from proves nothing, so the
security argument rests on :func:`aditor.app.issuer.signed_the_leaf`: a
candidate is offered only if its key signed the certificate the controller
presented.

That makes the discrimination test below the most important one in this file. It
is not hypothetical. On the domain this was built against, the AIA container
held four CA certificates — two retired predecessors and a second issuing CA —
and exactly one had signed the controller's certificate. Installing either of
the others leaves the identical ``unable to get local issuer certificate``
error behind while looking, to the operator, like a completed fix.
"""

import datetime

from aditor.app.certificates import CA_CERTIFICATE_ATTRIBUTE, certificate_facts
from aditor.app.issuer import (
    FETCH_FOUND,
    FETCH_NO_MATCH,
    FETCH_UNAVAILABLE,
    MAX_AIA_BYTES,
    certificates_in,
    download_aia,
    fetch_issuing_ca,
    http_aia_urls,
    signed_the_leaf,
    windows_store_certificates,
)
from aditor.app.settings import ConnectionSettings
from aditor.app.trust import PATH_PLACEHOLDER, detect_machine, install_commands
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from .synthetic_certificates import chain, der, issue, new_key

BASE_DN = "DC=test,DC=local"
CONFIG_DN = f"CN=Configuration,{BASE_DN}"


def settings(**overrides):
    values = {"server": "ldaps://dc01.test.local:636",
              "domain": "test.local",
              "base_dn": BASE_DN,
              "bind_dn": f"CN=svc-aditor,{BASE_DN}",
              "validate_certificate": True}
    values.update(overrides)
    return ConnectionSettings(**values)


class FakeDirectory:
    """An LDAP manager that serves ``cACertificate`` from a DN → certs map."""

    def __init__(self, published=None, error=None):
        #: {search_base: [x509.Certificate, ...]}
        self.published = published or {}
        self.error = error
        self.searched = []
        self.disconnected = False

    def search(self, search_base, search_filter, attributes=None, **kwargs):
        self.searched.append(search_base)
        if self.error is not None:
            raise self.error
        certificates = None
        for dn, value in self.published.items():
            if dn.lower() == str(search_base).lower():
                certificates = value
                break
        if certificates is None:
            return []
        return [{"dn": f"CN=published,{search_base}",
                 "attributes": {CA_CERTIFICATE_ATTRIBUTE:
                                [der(c) for c in certificates]}}]

    def disconnect(self):
        self.disconnected = True


def factory(manager):
    def build(active, security, performance):
        manager.security_config = security
        return manager
    return build


def leaf_facts(certificate=None):
    return certificate_facts(der(certificate or chain().leaf))


def with_aia(url, *, cn="dc01.test.local"):
    """A leaf certificate carrying one ``caIssuers`` AIA URL."""
    return leaf_and_issuer(url, cn=cn)[0]


def leaf_and_issuer(url, *, cn="dc01.test.local"):
    """``(leaf, issuer)``: a leaf with one AIA URL, and the CA that signed it."""
    key = new_key()
    root, root_key = issue("aia-test-CA",
                           not_before=datetime.datetime.now(datetime.timezone.utc)
                           - datetime.timedelta(days=10),
                           not_after=datetime.datetime.now(datetime.timezone.utc)
                           + datetime.timedelta(days=100),
                           is_ca=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(
                   x509.oid.NameOID.COMMON_NAME, cn)]))
               .issuer_name(root.subject)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before((now - datetime.timedelta(days=1))
                                 .replace(tzinfo=None))
               .not_valid_after((now + datetime.timedelta(days=90))
                                .replace(tzinfo=None))
               .add_extension(x509.AuthorityInformationAccess([
                   x509.AccessDescription(
                       x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                       x509.UniformResourceIdentifier(url))]),
                   critical=False))
    from cryptography.hazmat.primitives import hashes
    return builder.sign(root_key, hashes.SHA256()), root


def store(*certificates, name="ROOT"):
    """A Windows-store reader holding ``certificates``."""
    return lambda: [(f"This computer's Windows certificate store ({name})",
                     der(c)) for c in certificates]


def empty_store():
    return []


def downloads(mapping):
    """A downloader serving ``{url: bytes or Exception}``; records calls."""
    calls = []

    def download(url):
        calls.append(url)
        value = mapping.get(url, OSError(f"no such address: {url}"))
        if isinstance(value, Exception):
            raise value
        return value
    download.calls = calls
    return download


def fetch(store_reader=empty_store, downloader=None, leaf=None):
    return fetch_issuing_ca(leaf or leaf_facts(), store_reader=store_reader,
                            downloader=downloader or downloads({}))


# --------------------------------------------------------------------------- #
# The signature check
# --------------------------------------------------------------------------- #

class TestSignedTheLeaf:
    def test_the_real_issuer_verifies(self):
        verified, reason = signed_the_leaf(chain().issuing, chain().leaf)
        assert verified is True
        assert "signed" in reason

    def test_the_root_two_hops_up_does_not(self):
        """The root signed the *issuing CA*, not the leaf. A name comparison
        would not tell these apart; this must."""
        verified, _ = signed_the_leaf(chain().root, chain().leaf)
        assert verified is False

    def test_an_unrelated_ca_does_not(self):
        verified, reason = signed_the_leaf(chain().rogue_root, chain().leaf)
        assert verified is False
        assert "did not sign" in reason

    def test_an_rsa_issuer_verifies_too(self):
        """The live domain's CA is RSA; the synthetic fixtures are EC. Both
        branches of the check need to work, so both are exercised."""
        now = datetime.datetime.now(datetime.timezone.utc)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca, ca_key = issue("rsa-CA", not_before=now - datetime.timedelta(days=5),
                           not_after=now + datetime.timedelta(days=500),
                           is_ca=True, key=key)
        child, _ = issue("dc02.test.local",
                         not_before=now - datetime.timedelta(days=5),
                         not_after=now + datetime.timedelta(days=100),
                         issuer_name=ca.subject, issuer_key=ca_key)
        assert signed_the_leaf(ca, child)[0] is True
        assert signed_the_leaf(chain().root, child)[0] is False


# --------------------------------------------------------------------------- #
# Where it looks — and where it refuses to
# --------------------------------------------------------------------------- #

class TestHttpAiaUrls:
    def test_an_http_aia_url_is_returned(self):
        assert http_aia_urls(with_aia("http://pki.example/ca.crt")) == (
            "http://pki.example/ca.crt",)

    def test_an_ldap_aia_url_is_not_followed(self):
        """Reading one means binding, which the fetch never does."""
        dn = "CN=test-CA,CN=AIA,CN=Public Key Services,CN=Services," + CONFIG_DN
        assert http_aia_urls(with_aia(
            f"ldap:///{dn.replace(' ', '%20')}?cACertificate?base")) == ()
        assert http_aia_urls(with_aia(
            f"ldap://elsewhere.example:389/{dn}?cACertificate")) == ()

    def test_a_certificate_with_no_aia_has_no_urls(self):
        assert http_aia_urls(chain().leaf) == ()


# --------------------------------------------------------------------------- #
# The fetch — the test that matters most is the first one
# --------------------------------------------------------------------------- #

class TestFetchIssuingCa:
    def test_it_picks_the_one_certificate_that_signed_the_leaf(self):
        """Four candidates, one right answer, and the right one is not first.

        This is the live case reproduced: a store holding the real issuer
        alongside a root, an unrelated CA and a decoy. Taking the first, or the
        one whose subject matches the leaf's issuer name, gets it wrong.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        decoy, _ = issue("test-CA-Issuing",  # same CN as the real issuer
                         not_before=now - datetime.timedelta(days=100),
                         not_after=now + datetime.timedelta(days=100),
                         is_ca=True)
        result = fetch(store(chain().root, chain().rogue_root, decoy,
                             chain().issuing))

        assert result.outcome == FETCH_FOUND
        assert result.ok is True
        expected = certificate_facts(der(chain().issuing)).fingerprint_hex
        assert result.match.fingerprint_hex == expected
        assert result.rejected == 3, "the three decoys must be counted, not hidden"
        assert "Windows certificate store" in result.detail

    def test_the_decoy_with_the_issuers_name_is_still_rejected(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        decoy, _ = issue("test-CA-Issuing",
                         not_before=now - datetime.timedelta(days=100),
                         not_after=now + datetime.timedelta(days=100),
                         is_ca=True)
        result = fetch(store(decoy))
        assert result.ok is False and result.match is None

    def test_an_unrelated_store_is_unavailable_with_manual_steps(self):
        """A store full of other roots is normal, not a warning."""
        result = fetch(store(chain().rogue_root))
        assert result.outcome == FETCH_UNAVAILABLE
        assert "certlm.msc" in result.detail
        assert "doesn't read it from Active Directory" in result.detail

    def test_the_aia_address_is_downloaded_when_the_store_lacks_it(self):
        leaf, issuer = leaf_and_issuer("http://pki.example/ca.crt")
        download = downloads({"http://pki.example/ca.crt": der(issuer)})
        result = fetch(downloader=download,
                       leaf=certificate_facts(der(leaf)))
        assert result.outcome == FETCH_FOUND
        assert result.match.source == "aia-download"
        assert download.calls == ["http://pki.example/ca.crt"]

    def test_a_downloaded_certificate_that_did_not_sign_it_is_a_no_match(self):
        leaf, _issuer = leaf_and_issuer("http://pki.example/ca.crt")
        result = fetch(downloader=downloads(
            {"http://pki.example/ca.crt": der(chain().rogue_root)}),
            leaf=certificate_facts(der(leaf)))
        assert result.outcome == FETCH_NO_MATCH
        assert "interception" in result.detail

    def test_a_failed_download_is_unavailable_and_says_why(self):
        leaf, _issuer = leaf_and_issuer("http://pki.example/ca.crt")
        result = fetch(leaf=certificate_facts(der(leaf)))
        assert result.outcome == FETCH_UNAVAILABLE
        assert "pki.example" in result.error

    def test_it_stops_once_the_store_proves_it(self):
        leaf, issuer = leaf_and_issuer("http://pki.example/ca.crt")
        download = downloads({})
        fetch(store(issuer), download, leaf=certificate_facts(der(leaf)))
        assert download.calls == []

    def test_a_store_that_cannot_be_read_is_reported_not_raised(self):
        def broken():
            raise PermissionError("access denied")
        result = fetch(broken)
        assert result.outcome == FETCH_UNAVAILABLE
        assert "access denied" in result.error


class TestDownloadsAndStores:
    def test_der_pem_and_pkcs7_are_all_read(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs7
        issuing = chain().issuing
        pem = issuing.public_bytes(serialization.Encoding.PEM)
        bundle = pkcs7.serialize_certificates([issuing],
                                              serialization.Encoding.DER)
        for data in (der(issuing), pem, bundle):
            assert certificates_in(data) == [der(issuing)]
        assert certificates_in(b"not a certificate") == []

    def test_only_http_addresses_are_downloaded(self):
        import pytest
        for url in ("file:///etc/passwd", "ldap:///CN=x", "ftp://x/ca.crt"):
            with pytest.raises(ValueError):
                download_aia(url)

    def test_a_download_is_capped_in_size(self, monkeypatch):
        import io

        import pytest

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False
        monkeypatch.setattr("urllib.request.urlopen",
                            lambda request, timeout: Response(
                                b"x" * (MAX_AIA_BYTES + 10)))
        with pytest.raises(ValueError, match="more than"):
            download_aia("http://pki.example/huge.crt")

    def test_the_windows_stores_are_read_only_on_windows(self, monkeypatch):
        import ssl
        monkeypatch.setattr("sys.platform", "darwin")
        assert windows_store_certificates() == []
        monkeypatch.setattr("sys.platform", "win32")
        monkeypatch.setattr(ssl, "enum_certificates", lambda name: [
            (der(chain().issuing), "x509_asn", True),
            (b"pkcs7", "pkcs_7_asn", True)], raising=False)
        found = windows_store_certificates()
        assert [where for where, _der in found] == [
            "This computer's Windows certificate store (CA)",
            "This computer's Windows certificate store (ROOT)"]


class TestItSendsNoCredential:
    """The HIGH finding: the fetch used to bind with the operator's password
    over a session whose certificate was deliberately not validated."""

    def test_the_fetch_takes_no_password_or_settings(self):
        import inspect
        parameters = set(inspect.signature(fetch_issuing_ca).parameters)
        assert not parameters & {"password", "settings", "factory"}

    def test_the_download_button_never_touches_the_directory(self, tmp_path):
        from aditor.app.api import AditorApi

        from .test_app_certificate_panel import a_report
        from .test_app_password_never_leaks import MemoryStore

        def no_directory(*_args, **_kwargs):
            raise AssertionError("the issuer fetch must not build an LDAP "
                                 "connection")
        api = AditorApi(directory=tmp_path, store=MemoryStore(),
                        ldap_factory=no_directory)
        api._trust_report = a_report(presented=[der(chain().leaf)])
        api._password = "hunter2"
        result = api.download_issuing_ca()
        # Found or not, it answered (an outcome, not an exception) without
        # building a directory connection.
        assert result.get("outcome") in (FETCH_FOUND, FETCH_NO_MATCH,
                                         FETCH_UNAVAILABLE)

    def test_the_result_says_no_credential_was_sent(self):
        result = fetch(store(chain().issuing))
        assert result.ok is True
        assert "No password or other credential was sent" in result.detail
        assert "out of band" in result.detail


# --------------------------------------------------------------------------- #
# The instructions gain the step they used to assume
# --------------------------------------------------------------------------- #

class TestTheInstructionsNameTheStep:
    def test_the_first_step_is_getting_the_file(self):
        steps = install_commands(detect_machine("darwin", {}))
        assert "Save the CA certificate" in steps[0].label
        assert "Download the issuing CA certificate" in steps[0].note
        assert steps[0].command == "", "obtaining the file is not a command"

    def test_once_saved_the_first_step_says_where_it_is(self, tmp_path):
        path = tmp_path / "ca.crt"
        steps = install_commands(detect_machine("darwin", {}), path)
        assert str(path) in steps[0].note
        assert "nothing has been added to a trust store" in steps[0].note

    def test_the_step_does_not_call_the_file_the_fix_on_a_joined_machine(self):
        """On a domain-joined machine the missing root means autoenrollment is
        broken domain-wide. A hand-imported file hides that."""
        joined = detect_machine("win32", {"USERDNSDOMAIN": "test.local"})
        steps = install_commands(joined)
        assert "not the fix" in steps[0].note
        # the existing advice still leads the commands
        assert "find out why it is missing" in steps[1].label

    def test_on_macos_the_file_is_the_fix_and_says_so(self):
        steps = install_commands(detect_machine("darwin", {}))
        assert "what the commands below operate on" in steps[0].note

    def test_every_platform_gains_the_step(self):
        for system, environ in (("darwin", {}), ("linux", {}),
                                ("win32", {"USERDOMAIN": "WS01"}),
                                ("win32", {"USERDNSDOMAIN": "test.local"}),
                                ("win32", {})):
            steps = install_commands(detect_machine(system, environ))
            assert steps, (system, environ)
            assert "CA certificate" in steps[0].label, (system, environ)

    def test_the_placeholder_still_guards_an_unsaved_path(self):
        steps = install_commands(detect_machine("darwin", {}))
        commands = " ".join(step.command for step in steps if step.command)
        assert PATH_PLACEHOLDER in commands


# --------------------------------------------------------------------------- #
# The button: where it appears, and where it deliberately does not
# --------------------------------------------------------------------------- #

class TestTheButtonAppearsWhereItIsNeeded:
    def _panel(self, **kwargs):
        from .test_app_certificate_panel import a_panel
        return a_panel(**kwargs)

    def test_it_appears_when_the_controller_sent_only_its_own_certificate(self):
        """The live case: nothing in the chain is exportable, so without this
        button the instructions open on a path the operator has to go and find.
        """
        panel = self._panel(presented=[der(chain().leaf)],
                            published=[chain().root])
        assert "data-download-issuer" in panel
        assert "Download the issuing CA certificate" in panel

    def test_it_does_not_appear_when_the_chain_already_carries_a_ca(self):
        """There is already an Export button on the certificate itself; a second
        route to the same file is noise."""
        panel = self._panel(published=[chain().root])
        assert "data-download-issuer" not in panel

    def test_the_leaf_only_warning_points_at_the_button(self):
        panel = self._panel(presented=[der(chain().leaf)])
        assert "sent only its own certificate" in panel
        assert "Download the issuing CA certificate" in panel
        # ...and no longer just tells the operator to go and get it themselves
        assert "Get the CA certificate from the CA server itself" not in panel

    def test_the_offer_says_no_credential_is_sent(self):
        panel = self._panel(presented=[der(chain().leaf)])
        assert "sends no password or other credential" in panel
        assert "confirmed out of band" in panel

    def test_the_offer_explains_why_the_right_file_is_the_right_one(self):
        """The reason a naive version of this button would be wrong."""
        panel = self._panel(presented=[der(chain().leaf)])
        assert "installing the wrong one leaves the same error" in panel
        assert "signed the one the" in panel

    def test_the_offer_says_it_does_not_install(self):
        panel = self._panel(presented=[der(chain().leaf)])
        assert "does not add it to any trust store" in panel


class TestTheResultPanel:
    def _render(self, fetch):
        from aditor.app.render import render_certificate_panel

        from .test_app_certificate_panel import a_report
        return render_certificate_panel(
            a_report(presented=[der(chain().leaf)]), fetch=fetch)

    def _fetch(self, published):
        return fetch(store(*published))

    def _no_match(self):
        leaf, _issuer = leaf_and_issuer("http://pki.example/ca.crt")
        return fetch(downloader=downloads(
            {"http://pki.example/ca.crt": der(chain().rogue_root)}),
            leaf=certificate_facts(der(leaf)))

    def test_every_rejected_candidate_is_shown_not_hidden(self):
        """An operator who is told "here is the CA" deserves to see that three
        others were considered and why they lost."""
        html = self._render(self._fetch(
            [chain().root, chain().rogue_root, chain().issuing]))
        assert "Every certificate that was considered" in html
        assert html.count("did not sign") >= 2
        assert "signed it" in html

    def test_a_found_result_still_demands_out_of_band_confirmation(self):
        html = self._render(self._fetch([chain().issuing]))
        assert "Confirm the fingerprint" in html
        assert "does not prove either is legitimate" in html

    def test_no_match_is_rendered_as_bad_not_as_a_shrug(self):
        html = self._render(self._no_match())
        assert "None of the CA certificates found signed this one." in html
        # The banner carrying that headline must be the bad one, not a warning.
        headline = "None of the CA certificates found signed this one."
        before = html[:html.index(headline)]
        assert before.rfind("banner-bad") > before.rfind("banner-warn"), (
            "a controller whose certificate no published CA signed is not a "
            "shrug")
        assert "interception" in html

    def test_the_panel_renders_without_a_fetch(self):
        from aditor.app.render import render_certificate_panel

        from .test_app_certificate_panel import a_report
        html = render_certificate_panel(a_report(presented=[der(chain().leaf)]))
        assert "Every certificate that was considered" not in html
        assert "data-download-issuer" in html


# --------------------------------------------------------------------------- #
# The lockout hazard: one click must not be five failed logons
# --------------------------------------------------------------------------- #

class TestOneClickIsOneFailedLogon:
    """Found in the field, not in review.

    The issuer fetch searches up to five containers, and each search re-enters
    ``LDAPManager.connect()``. A rejected credential therefore produced *five*
    failed logons per button press -- against a live domain whose
    ``lockoutThreshold`` was exactly 5.

    The inner retry loop had already been fixed (#18). What defeated it was the
    aggregation: ``connect()`` catches its attempts and re-raises a plain
    ``LDAPException`` whose text mentions ``invalidCredentials``, and the
    classifier recognised the *type* only. So these tests assert on the wrapped
    form, which is what a caller actually sees.
    """

    #: Exactly what ldap_manager raises after a rejected simple bind.
    WRAPPED = ("Failed to connect to any LDAP server after 1 attempts. Error: "
               "LDAPInvalidCredentialsResult - 49 - invalidCredentials - None "
               "- 80090308: LdapErr: DSID-0C090530, comment: "
               "AcceptSecurityContext error, data 52e, v4563 - bindResponse - "
               "None")

    def test_the_wrapped_credential_failure_is_recognised_as_terminal(self):
        from aditor.core.ldap_manager import is_terminal_connection_error
        from ldap3.core.exceptions import LDAPException as Raw
        assert is_terminal_connection_error(Raw(self.WRAPPED)) is True

    def test_a_wrapped_lockout_is_terminal_too(self):
        """Retrying against a locked account extends the lockout."""
        from aditor.core.ldap_manager import is_terminal_connection_error
        from ldap3.core.exceptions import LDAPException as Raw
        assert is_terminal_connection_error(Raw(
            "Failed to connect to any LDAP server after 1 attempts. Error: "
            "80090308: LdapErr: DSID-0C090530, comment: AcceptSecurityContext "
            "error, data 775, v4563")) is True

    def test_a_refused_socket_is_still_worth_retrying(self):
        """The classifier must not fire on everything, or a network blip
        becomes an unretried failure."""
        from aditor.core.ldap_manager import is_terminal_connection_error
        from ldap3.core.exceptions import LDAPException as Raw
        for transient in ("connection refused", "timed out",
                          "temporary failure in name resolution",
                          "Failed to connect to any LDAP server after 3 "
                          "attempts. Error: socket connection error while "
                          "opening: [Errno 61] Connection refused"):
            assert is_terminal_connection_error(Raw(transient)) is False, transient

    def test_a_bare_result_code_49_does_not_trip_it(self):
        """'49' appears in serial numbers, DNs and timestamps."""
        from aditor.core.ldap_manager import is_terminal_connection_error
        from ldap3.core.exceptions import LDAPException as Raw
        assert is_terminal_connection_error(Raw(
            "socket connection error while opening: serial 49493849")) is False

    def test_the_published_roots_read_binds_once(self):
        """Three containers, one rejected credential, one bind. (The issuer
        fetch no longer binds at all.)"""
        from aditor.app.certificates import ca_certificates_from_directory
        from ldap3.core.exceptions import LDAPException as Raw

        directory = FakeDirectory(error=Raw(self.WRAPPED))
        ca_certificates_from_directory(settings(), "wrong-password",
                                       factory=factory(directory))
        assert len(directory.searched) == 1

    def test_connect_re_raises_a_rejected_credential_as_terminal(self):
        """The structural fix: the aggregation keeps the failure's kind."""
        from aditor.core.ldap_manager import TerminalConnectionError
        assert issubclass(TerminalConnectionError, Exception)
        # The type is preserved through connect()'s aggregation, so a caller
        # that re-enters connect() per search stops on the first refusal
        # regardless of how the message happens to be worded.
        from aditor.core.ldap_manager import is_terminal_connection_error
        assert is_terminal_connection_error(
            TerminalConnectionError("anything at all")) is True


# --------------------------------------------------------------------------- #
# The two steps at the end, and the field that makes one of them work
# --------------------------------------------------------------------------- #

class TestTheSequenceEndsWhereItShould:
    """The instructions used to stop after "trust it system-wide".

    Two things were missing, and between them they account for an operator doing
    everything the panel said and the app still refusing the connection:
    ADitor verifies through Python's OpenSSL, which does not read the macOS
    keychain, and nothing takes effect in a process that is already running.
    """

    def test_the_last_step_is_a_restart(self):
        for system, environ in (("darwin", {}), ("linux", {}),
                                ("win32", {"USERDOMAIN": "WS01"}),
                                ("win32", {"USERDNSDOMAIN": "test.local"})):
            steps = install_commands(detect_machine(system, environ))
            assert steps[-1].label == "Restart ADitor", (system, environ)
            assert "from before the change" in steps[-1].note

    def test_the_restart_step_names_the_check_that_confirms_it_worked(self):
        steps = install_commands(detect_machine("darwin", {}))
        assert "Test connection" in steps[-1].note

    def test_the_step_before_it_points_aditor_at_the_file(self, tmp_path):
        path = tmp_path / "ca.crt"
        steps = install_commands(detect_machine("darwin", {}), path)
        step = steps[-2]
        assert "Point ADitor" in step.label
        assert str(path) in step.command
        assert "ca_cert_file" in step.command

    def test_it_explains_why_the_os_trust_store_is_not_enough(self):
        steps = install_commands(detect_machine("darwin", {}))
        note = steps[-2].note
        assert "does not read the macOS keychain" in note
        assert "OpenSSL" in note

    def test_the_placeholder_guards_that_step_too(self):
        steps = install_commands(detect_machine("darwin", {}))
        assert PATH_PLACEHOLDER in steps[-2].command


class TestTheCaCertFileActuallyReachesTheConnection:
    """A field the config writer hard-coded to None for the whole of WP5.

    Without this the setting could be written into config.json by hand and the
    app would ignore it, which is a worse failure than not offering it at all.
    """

    def test_the_setting_reaches_the_security_config(self):
        from aditor.app.connection import _configs
        _active, security, _perf = _configs(
            settings(ca_cert_file="/etc/pki/example-ca.pem"), "pw")
        assert security.ca_cert_file == "/etc/pki/example-ca.pem"

    def test_an_empty_setting_means_the_platform_store(self):
        from aditor.app.connection import _configs
        _active, security, _perf = _configs(settings(), "pw")
        assert security.ca_cert_file is None

    def test_it_is_written_into_the_generated_config(self):
        from aditor.app.settings import build_config_document
        document = build_config_document(
            settings(ca_cert_file="/etc/pki/example-ca.pem"))
        assert document["security"]["ca_cert_file"] == "/etc/pki/example-ca.pem"

    def test_an_empty_setting_writes_null_not_an_empty_string(self):
        """ldap3 takes a path or nothing; "" is neither."""
        from aditor.app.settings import build_config_document
        assert build_config_document(settings())["security"]["ca_cert_file"] \
            is None

    def test_the_generated_config_still_holds_no_password(self):
        """The one guarantee of that writer, re-checked after touching it."""
        import json

        from aditor.app.settings import build_config_document
        text = json.dumps(build_config_document(
            settings(ca_cert_file="/etc/pki/example-ca.pem")))
        assert "${AD_MCP_PASSWORD}" in text

    def test_it_survives_a_write_and_reload(self, tmp_path):
        """Without load_settings reading it back, a value set in the file is
        silently dropped and the app quietly reverts to the platform store."""
        import json

        from aditor.app.settings import build_config_document, load_settings
        (tmp_path / "config.json").write_text(json.dumps(
            build_config_document(settings(ca_cert_file="/etc/pki/example-ca.pem"))),
            encoding="utf-8")
        assert load_settings(tmp_path).connection.ca_cert_file == \
            "/etc/pki/example-ca.pem"
