"""The four properties that keep this panel from being trust-on-first-use.

This file is the acceptance criteria, and it is deliberately paranoid about
things that read like style rules:

* **No button anywhere installs or trusts a certificate.** Asserted over every
  rendered fragment the panel can produce *and* over the bridge's method list,
  because either one alone could be undone without the other noticing.
* **The out-of-band verification instruction cannot be rendered without the
  fingerprint beside it.** Asserted structurally — over the renderer's AST —
  rather than by looking for the two strings in one output, because the output
  test passes right up until someone adds a second call site.
* **"Could not check" never renders as agreement.** Three outcomes, three
  classes, three banner kinds, and the word "pass" only ever appears in a
  refusal to claim one.
* **``validate_certificate`` is never changed.** Asserted behaviourally through
  the bridge — including when the form says the opposite of the saved value —
  and structurally over the two new modules.

Nothing here reaches a domain controller, a keychain, a trust store or a
port: the chain comes from an injected fetch over synthesized certificates and
the LDAP read from an injected stub.
"""

import ast
import pathlib
import re

import pytest

from aditor.app import render
from aditor.app.api import AditorApi
from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPException,
    LDAPSocketOpenError,
)

from aditor.app.certificates import (
    CORROBORATION_AGREE,
    CORROBORATION_DISAGREE,
    CORROBORATION_UNAVAILABLE,
    CA_CERTIFICATE_ATTRIBUTE,
    ca_certificates_from_directory,
    certificate_facts,
    pki_container_dns,
)
from aditor.app.endpoint import Endpoint
from aditor.app.render import OUT_OF_BAND_INSTRUCTION, render_certificate_panel
from aditor.app.settings import ConnectionSettings
from aditor.app.trust import EXPORT_DIRNAME, build_trust_report

from .synthetic_certificates import chain, der, issue

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = REPO_ROOT / "src" / "aditor" / "app"
BASE_DN = "DC=test,DC=local"

JOINED = {"USERDNSDOMAIN": "test.local"}
STANDALONE = {"USERDOMAIN": "WS01", "COMPUTERNAME": "WS01"}


# --------------------------------------------------------------------------- #
# Scaffolding
# --------------------------------------------------------------------------- #

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
    def __init__(self, certificates=(), error=None):
        self._certificates = list(certificates)
        self._error = error

    def search(self, search_base, search_filter, attributes=None, **kwargs):
        if self._error is not None:
            raise self._error
        if "Certification Authorities" not in search_base:
            return []
        return [{
            "dn": f"CN=published-{index},CN=Certification Authorities,"
                  f"CN=Public Key Services,CN=Services,CN=Configuration,"
                  f"{BASE_DN}",
            "attributes": {"cn": f"published-{index}",
                           CA_CERTIFICATE_ATTRIBUTE: der(certificate)},
        } for index, certificate in enumerate(self._certificates)]

    def disconnect(self):
        pass


def factory(manager):
    def build(active, security, performance):
        manager.security_config = security
        return manager
    return build


def a_report(*, presented=None, published=(), directory_error=None,
             environ=None, system="win32", settings=None, export_path=""):
    presented = presented if presented is not None else chain().chain_der()
    return build_trust_report(
        settings or a_connection(), "N0t-A-Real-Password-9f3ac1",
        factory=factory(StubDirectory(published, directory_error)),
        fetch=lambda host, port, timeout: list(presented),
        system=system,
        environ=dict(STANDALONE if environ is None else environ),
        export_path=export_path)


def a_panel(**kwargs):
    return render_certificate_panel(a_report(**kwargs))


#: Every distinct panel the renderer can produce, so the "no trust button"
#: assertion below is made against all of them rather than the happy one.
def every_panel():
    return {
        "agree": a_panel(published=[chain().root]),
        "disagree": a_panel(presented=chain().rogue_chain_der(),
                            published=[chain().root]),
        "unavailable-no-directory": a_panel(
            directory_error=RuntimeError("CERTIFICATE_VERIFY_FAILED")),
        "unavailable-empty-directory": a_panel(published=[]),
        "unavailable-leaf-only": a_panel(presented=[der(chain().leaf)],
                                         published=[chain().root]),
        "no-chain": render_certificate_panel(build_trust_report(
            a_connection(), "pw", factory=factory(StubDirectory()),
            fetch=lambda h, p, t: (_ for _ in ()).throw(
                ConnectionRefusedError("refused")),
            system="darwin", environ={})),
        "expired": a_panel(presented=chain().expired_chain_der(),
                           published=[chain().root]),
        "expiring": a_panel(presented=chain().expiring_chain_der(),
                            published=[chain().root]),
        "joined": a_panel(published=[chain().root], environ=JOINED),
        "macos": a_panel(published=[chain().root], system="darwin",
                         environ={}),
        "unknown-machine": a_panel(published=[chain().root], environ={}),
        "exported": a_panel(published=[chain().root],
                            export_path="/tmp/aditor-test/root.crt"),
    }


BUTTON = re.compile(r"<button\b([^>]*)>(.*?)</button>", re.S)
DATA_ATTRIBUTE = re.compile(r"\bdata-([a-z-]+)=")


# --------------------------------------------------------------------------- #
# Criterion 3 — nothing here installs or trusts anything
# --------------------------------------------------------------------------- #

#: Verbs that would mean the app is doing the thing the operator must do. A
#: button carrying any of these is the failure this work package exists to
#: prevent.
FORBIDDEN_ON_A_BUTTON = ("trust", "install", "import", "addstore", "add store",
                         "add to root", "accept", "approve", "allow",
                         "keychain", "ignore")

#: The only data-* hooks the panel's buttons are allowed to carry. A new one is
#: a deliberate act, which is the point of writing them down.
ALLOWED_BUTTON_HOOKS = {"export-ca", "copy-text", "copy", "open-report"}


class TestNoButtonInstallsOrTrusts:
    def test_no_rendered_button_is_labelled_with_a_trusting_verb(self):
        for name, panel in every_panel().items():
            for attributes, label in BUTTON.findall(panel):
                text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", label)).lower()
                for verb in FORBIDDEN_ON_A_BUTTON:
                    assert verb not in text, (name, text, verb)

    def test_the_only_buttons_are_export_and_copy(self):
        labels = set()
        for panel in every_panel().values():
            for _, label in BUTTON.findall(panel):
                labels.add(re.sub(r"\s+", " ",
                                  re.sub(r"<[^>]+>", "", label)).strip())
        assert labels <= {"Export CA certificate", "Copy command"}, labels

    def test_no_button_carries_an_unexpected_hook(self):
        for name, panel in every_panel().items():
            for attributes, _ in BUTTON.findall(panel):
                hooks = set(DATA_ATTRIBUTE.findall(attributes))
                assert hooks <= ALLOWED_BUTTON_HOOKS, (name, hooks)

    def test_a_copy_button_copies_and_does_not_run(self):
        # The install command *text* appears on the panel -- that is the whole
        # deliverable -- and the button beside it is labelled "Copy command"
        # and hands the string to the clipboard. The distinction between
        # printing a command and running it is the design, so it is asserted
        # rather than assumed: the command lives in a data attribute and a
        # <pre>, and no button label mentions installing.
        panel = a_panel(published=[chain().root])
        assert "certutil -addstore" in panel
        for attributes, label in BUTTON.findall(panel):
            if "data-copy-text" in attributes:
                assert "Copy" in label

    def test_the_bridge_exposes_no_method_that_could_install(self, tmp_path):
        api = AditorApi(directory=tmp_path, endpoint=Endpoint(port=9301))
        public = {name for name in dir(api) if not name.startswith("_")}
        for verb in ("trust", "install", "import", "addstore", "keychain",
                     "store_certificate", "add_root"):
            assert not any(verb in name for name in public), verb
        # And the two methods that do exist say what they do.
        assert "certificate_screen" in public
        assert "export_ca_certificate" in public

    def test_the_script_has_no_trust_handler(self):
        script = (APP / "web" / "app.js").read_text(encoding="utf-8")
        for forbidden in ("trustCert", "installCert", "data-trust",
                          "data-install", "add-trusted", "addstore"):
            assert forbidden not in script, forbidden

    def test_the_page_itself_offers_no_trust_button(self):
        index = (APP / "web" / "index.html").read_text(encoding="utf-8")
        buttons = [re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", label)).lower()
                   for _, label in BUTTON.findall(index)]
        for label in buttons:
            for verb in FORBIDDEN_ON_A_BUTTON:
                assert verb not in label, (label, verb)


# --------------------------------------------------------------------------- #
# Criterion 4 — the fingerprint and the instruction are one thing
# --------------------------------------------------------------------------- #

def functions_referencing(name, module_path):
    """Which top-level functions in a module mention this name."""
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for inner in ast.walk(node):
                if isinstance(inner, ast.Name) and inner.id == name:
                    found.add(node.name)
    return found


class TestTheInstructionCannotRenderWithoutTheFingerprint:
    def test_only_one_function_can_render_the_instruction(self):
        # The structural guarantee. A second call site is how the instruction
        # ends up somewhere without a fingerprint next to it, so there is one.
        assert functions_referencing("OUT_OF_BAND_INSTRUCTION",
                                     APP / "render.py") == {
                                         "_fingerprint_block"}

    def test_that_function_always_emits_the_fingerprint_too(self):
        source = ast.parse((APP / "render.py").read_text(encoding="utf-8"))
        block = [node for node in ast.walk(source)
                 if isinstance(node, ast.FunctionDef)
                 and node.name == "_fingerprint_block"][0]
        attributes = {node.attr for node in ast.walk(block)
                      if isinstance(node, ast.Attribute)}
        assert "fingerprint" in attributes
        # One return, so there is no branch that emits the instruction alone.
        returns = [node for node in ast.walk(block)
                   if isinstance(node, ast.Return)]
        assert len(returns) == 1

    def test_every_instruction_in_the_output_has_a_fingerprint_beside_it(self):
        needle = render.esc(OUT_OF_BAND_INSTRUCTION)
        for name, panel in every_panel().items():
            blocks = re.findall(
                r'<div class="fingerprint">(.*?)</div>', panel, re.S)
            assert panel.count(needle) == len(blocks), name
            for block in blocks:
                assert needle in block
                # 32 colon-separated hex pairs, in the same div.
                assert re.search(r"(?:[0-9A-F]{2}:){31}[0-9A-F]{2}", block), name

    def test_every_certificate_on_the_panel_carries_its_fingerprint(self):
        panel = a_panel(published=[chain().root])
        cards = re.findall(r'<article class="cert-card">(.*?)</article>',
                           panel, re.S)
        # Three presented plus one published.
        assert len(cards) == 4
        for card in cards:
            assert '<div class="fingerprint">' in card
            assert render.esc(OUT_OF_BAND_INSTRUCTION) in card

    def test_the_instruction_says_where_to_confirm_and_why(self):
        text = OUT_OF_BAND_INSTRUCTION.lower()
        assert "out of band" in text
        assert "certutil -store root" in text
        assert "keychain" in text
        # And it says what the fingerprint on screen is *not* evidence of.
        assert "corroborates nothing on its own" in text
        assert "intercepting" in text


# --------------------------------------------------------------------------- #
# Criterion 5 — three outcomes, and "unavailable" is not a pass
# --------------------------------------------------------------------------- #

class TestThreeOutcomesRenderDistinctly:
    def test_each_outcome_gets_its_own_class(self):
        assert 'corroboration-agree' in a_panel(published=[chain().root])
        assert 'corroboration-disagree' in a_panel(
            presented=chain().rogue_chain_der(), published=[chain().root])
        assert 'corroboration-unavailable' in a_panel(published=[])

    def test_disagreement_is_rendered_as_a_warning(self):
        panel = a_panel(presented=chain().rogue_chain_der(),
                        published=[chain().root])
        block = re.search(r'<div class="corroboration corroboration-disagree">'
                          r"(.*?)$", panel, re.S).group(1)
        assert "banner-bad" in block
        assert "Warning" in block
        assert "does not terminate" in block

    @pytest.mark.parametrize("panel_name", [
        "unavailable-no-directory", "unavailable-empty-directory",
        "unavailable-leaf-only", "no-chain"])
    def test_unavailable_is_never_rendered_as_agreement(self, panel_name):
        panel = every_panel()[panel_name]
        assert "corroboration-agree" not in panel
        assert "corroboration-unavailable" in panel
        block = re.search(
            r'<div class="corroboration corroboration-unavailable">(.*?)</div>',
            panel, re.S).group(1)
        # Not an ok banner, and the headline refuses the reading outright.
        assert "banner-ok" not in block
        assert "banner-warn" in block
        assert "could not check" in block.lower()
        assert "not a pass" in block

    def test_agreement_over_an_unvalidated_read_keeps_its_caveat(self):
        panel = a_panel(published=[chain().root],
                        settings=a_connection(validate_certificate=False))
        assert "corroboration-agree" in panel
        assert "weaker than it looks" in panel

    def test_the_three_panels_are_not_the_same_markup(self):
        agree = a_panel(published=[chain().root])
        disagree = a_panel(presented=chain().rogue_chain_der(),
                           published=[chain().root])
        unavailable = a_panel(published=[])
        assert len({agree, disagree, unavailable}) == 3

    def test_a_failed_directory_read_says_what_failed(self):
        panel = a_panel(directory_error=RuntimeError("insufficientAccessRights"))
        assert "insufficientAccessRights" in panel
        assert "could not be read" in panel


# --------------------------------------------------------------------------- #
# Criterion 6 — the two machines get different guidance
# --------------------------------------------------------------------------- #

class TestGuidanceDiffersByMachine:
    def test_joined_and_unjoined_windows_render_differently(self):
        joined = a_panel(published=[chain().root], environ=JOINED)
        alone = a_panel(published=[chain().root], environ=STANDALONE)
        assert joined != alone
        assert "gpupdate /target:computer /force" in joined
        assert "certutil -pulse" in joined
        assert "gpupdate" not in alone

    def test_the_joined_machine_is_told_not_to_import_by_hand_first(self):
        joined = a_panel(published=[chain().root], environ=JOINED)
        assert "Do not import it by hand first" in joined
        assert "autoenrollment" in joined
        assert "every other domain member" in joined

    def test_the_unjoined_machine_is_told_manual_trust_is_correct(self):
        alone = a_panel(published=[chain().root], environ=STANDALONE)
        assert "not joined to the domain" in alone
        assert "correct" in alone
        assert "certutil -addstore -f Root" in alone

    def test_macos_gets_keychain_guidance_and_the_openssl_caveat(self):
        panel = a_panel(published=[chain().root], system="darwin", environ={})
        assert "security add-trusted-cert" in panel
        assert "does not read the login or System keychain" in panel
        # No Windows remedy on a Mac. certutil is still *named* in the
        # out-of-band instruction, because that is how you read the
        # fingerprint off a Windows CA server -- but not as a step to run here.
        assert "certutil -addstore" not in panel
        assert "gpupdate" not in panel

    def test_an_undetectable_machine_gets_both_paths(self):
        panel = a_panel(published=[chain().root], environ={})
        assert "could not tell" in panel
        assert "PartOfDomain" in panel

    def test_the_panel_says_how_it_decided(self):
        joined = a_panel(published=[chain().root], environ=JOINED)
        assert "How ADitor worked that out" in joined
        assert "USERDNSDOMAIN" in joined


# --------------------------------------------------------------------------- #
# Criterion 7 — expiry is flagged, and not as a trust problem
# --------------------------------------------------------------------------- #

class TestExpiryIsItsOwnFailure:
    def test_an_expired_certificate_gets_its_own_alert(self):
        panel = a_panel(presented=chain().expired_chain_der(),
                        published=[chain().root])
        assert '<div class="expiry-alert">' in panel
        assert "Expired" in panel
        assert "installing a CA certificate will not fix it" in panel

    def test_a_near_expiry_certificate_is_warned_about_before_it_lapses(self):
        panel = a_panel(presented=chain().expiring_chain_der(),
                        published=[chain().root])
        assert '<div class="expiry-alert">' in panel
        assert "Expires in" in panel
        assert "30-day window" in panel

    def test_a_healthy_chain_has_no_expiry_alert(self):
        panel = a_panel(published=[chain().root])
        assert "expiry-alert" not in panel

    def test_the_expiry_alert_is_not_the_untrusted_issuer_wording(self):
        expired = a_panel(presented=chain().expired_chain_der(),
                          published=[chain().root])
        alert = re.search(r'<div class="expiry-alert">(.*?)</div>\s*<h3',
                          expired, re.S)
        alert = alert.group(1) if alert else expired
        # The expiry banner must not be the one that sends the operator to the
        # trust store, because that is not the fix.
        assert "reissued on the server" in alert
        assert "Trusted Root" not in alert

    def test_the_alert_leads_the_panel(self):
        panel = a_panel(presented=chain().expired_chain_der(),
                        published=[chain().root])
        assert panel.index("expiry-alert") < panel.index("cert-card")

    def test_an_expiring_published_ca_is_flagged_too(self):
        soon, _ = issue("test-CA-Expiring",
                        not_before=certificate_facts(
                            der(chain().root)).not_before,
                        not_after=certificate_facts(
                            der(chain().expiring_leaf)).not_after,
                        is_ca=True)
        panel = a_panel(published=[soon])
        assert '<div class="expiry-alert">' in panel
        assert "test-CA-Expiring" in panel

    def test_a_not_yet_valid_certificate_names_the_clock(self):
        future = certificate_facts(der(chain().root)).not_after
        skewed, _ = issue("dc99.test.local", not_before=future,
                          not_after=future.replace(year=future.year + 1))
        panel = a_panel(presented=[der(skewed)], published=[chain().root])
        assert "Not valid yet" in panel
        assert "clock" in panel


# --------------------------------------------------------------------------- #
# Criterion 8 — validate_certificate is never changed
# --------------------------------------------------------------------------- #

def assignments_to(name, module_path):
    """Every place this module *writes* the named attribute or keyword."""
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    writes = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute) and target.attr == name:
                    writes.append(node.lineno)
                if isinstance(target, ast.Name) and target.id == name:
                    writes.append(node.lineno)
        elif isinstance(node, ast.keyword) and node.arg == name:
            writes.append(node.lineno)
        elif isinstance(node, ast.AnnAssign):
            target = node.target
            if isinstance(target, ast.Attribute) and target.attr == name:
                writes.append(node.lineno)
    return writes


class TestValidateCertificateIsUntouched:
    def test_the_new_modules_never_write_it(self):
        for module in ("certificates.py", "trust.py", "render.py"):
            assert assignments_to("validate_certificate", APP / module) == [], \
                module

    def test_the_certificate_screen_does_not_change_the_saved_setting(
            self, tmp_path):
        for saved in (True, False):
            api = AditorApi(directory=tmp_path / str(saved),
                            endpoint=Endpoint(port=9302),
                            chain_fetch=lambda h, p, t: chain().chain_der(),
                            ldap_factory=factory(
                                StubDirectory([chain().root])))
            api._settings.connection = api._connection.with_values(
                server="ldaps://dc01.test.local:636", domain="test.local",
                base_dn=BASE_DN, bind_dn=f"CN=a,{BASE_DN}",
                validate_certificate=saved)
            before = api.state()["connection"]["validate_certificate"]
            assert before is saved
            # The form says the opposite of what is saved -- which is exactly
            # the case in which a careless implementation would persist it.
            api.certificate_screen({
                "server": "ldaps://dc01.test.local:636",
                "domain": "test.local", "base_dn": BASE_DN,
                "bind_dn": f"CN=a,{BASE_DN}",
                "validate_certificate": not saved, "password": "pw"})
            assert api.state()["connection"]["validate_certificate"] is saved

    def test_exporting_does_not_change_the_saved_setting(self, tmp_path):
        api = AditorApi(directory=tmp_path, endpoint=Endpoint(port=9303),
                        chain_fetch=lambda h, p, t: chain().chain_der(),
                        ldap_factory=factory(StubDirectory([chain().root])))
        api._settings.connection = api._connection.with_values(
            server="ldaps://dc01.test.local:636", domain="test.local",
            base_dn=BASE_DN, bind_dn=f"CN=a,{BASE_DN}",
            validate_certificate=True)
        api.certificate_screen({"server": "ldaps://dc01.test.local:636",
                                "domain": "test.local", "base_dn": BASE_DN,
                                "bind_dn": f"CN=a,{BASE_DN}",
                                "validate_certificate": True,
                                "password": "pw"})
        facts = certificate_facts(der(chain().root))
        result = api.export_ca_certificate(facts.fingerprint_hex)
        assert result["ok"] is True
        assert api.state()["connection"]["validate_certificate"] is True

    def test_no_written_config_file_appears_from_looking_at_a_certificate(
            self, tmp_path):
        api = AditorApi(directory=tmp_path, endpoint=Endpoint(port=9304),
                        chain_fetch=lambda h, p, t: chain().chain_der(),
                        ldap_factory=factory(StubDirectory([chain().root])))
        api.certificate_screen({"server": "ldaps://dc01.test.local:636",
                                "domain": "test.local", "base_dn": BASE_DN,
                                "bind_dn": f"CN=a,{BASE_DN}",
                                "validate_certificate": True})
        assert not (tmp_path / "config.json").exists()


# --------------------------------------------------------------------------- #
# The bridge, end to end, with no domain controller
# --------------------------------------------------------------------------- #

def an_api(tmp_path, port, presented=None, published=(), directory_error=None):
    api = AditorApi(
        directory=tmp_path, endpoint=Endpoint(port=port),
        chain_fetch=lambda h, p, t: list(
            presented if presented is not None else chain().chain_der()),
        ldap_factory=factory(StubDirectory(published, directory_error)))
    return api


FORM = {"server": "ldaps://dc01.test.local:636", "domain": "test.local",
        "base_dn": BASE_DN, "bind_dn": f"CN=a,{BASE_DN}",
        "validate_certificate": True, "password": "pw"}


class TestTheBridge:
    def test_the_screen_reports_the_outcome_as_a_scalar(self, tmp_path):
        api = an_api(tmp_path, 9310, published=[chain().root])
        result = api.certificate_screen(FORM)
        assert result["ok"] is True
        assert result["corroboration"] == CORROBORATION_AGREE
        assert result["chain_read"] is True
        assert result["expiry_warning"] is False
        assert "fingerprint" in result["html"]

    def test_a_rogue_chain_comes_back_as_disagree(self, tmp_path):
        api = an_api(tmp_path, 9311, presented=chain().rogue_chain_der(),
                     published=[chain().root])
        assert api.certificate_screen(FORM)["corroboration"] == \
            CORROBORATION_DISAGREE

    def test_an_unreadable_directory_comes_back_as_unavailable(self, tmp_path):
        api = an_api(tmp_path, 9312,
                     directory_error=RuntimeError("verify failed"))
        assert api.certificate_screen(FORM)["corroboration"] == \
            CORROBORATION_UNAVAILABLE

    def test_an_expiring_chain_sets_the_scalar(self, tmp_path):
        api = an_api(tmp_path, 9313, presented=chain().expiring_chain_der(),
                     published=[chain().root])
        assert api.certificate_screen(FORM)["expiry_warning"] is True

    def test_export_writes_a_crt_under_the_app_directory(self, tmp_path):
        api = an_api(tmp_path, 9314, published=[chain().root])
        api.certificate_screen(FORM)
        facts = certificate_facts(der(chain().root))
        result = api.export_ca_certificate(facts.fingerprint)   # colon form
        assert result["ok"] is True
        written = pathlib.Path(result["path"])
        assert written.parent == tmp_path / EXPORT_DIRNAME
        assert written.read_text().startswith("-----BEGIN CERTIFICATE-----")
        # And the panel now carries the real path in the commands.
        assert str(written) in result["html"]
        assert "<path to the exported .crt>" not in result["html"]

    def test_export_before_inspecting_is_refused(self, tmp_path):
        api = an_api(tmp_path, 9315)
        result = api.export_ca_certificate("deadbeef")
        assert result["ok"] is False
        assert "Inspect the certificate chain first" in result["message"]

    def test_only_a_certificate_on_screen_can_be_exported(self, tmp_path):
        api = an_api(tmp_path, 9316, published=[chain().root])
        api.certificate_screen(FORM)
        stranger = certificate_facts(der(chain().rogue_root))
        result = api.export_ca_certificate(stranger.fingerprint_hex)
        assert result["ok"] is False
        assert "not one of the certificates on screen" in result["message"]

    def test_the_leaf_is_not_offered_for_export(self, tmp_path):
        # Exporting the DC's own certificate and installing it as a root is a
        # mistake the app should not make available; it fixes nothing.
        api = an_api(tmp_path, 9317, published=[chain().root])
        api.certificate_screen(FORM)
        leaf = certificate_facts(der(chain().leaf))
        result = api.export_ca_certificate(leaf.fingerprint_hex)
        assert result["ok"] is False

    def test_a_chain_that_cannot_be_read_is_reported_not_raised(self, tmp_path):
        def refused(host, port, timeout):
            raise ConnectionRefusedError("[Errno 61] Connection refused")

        api = AditorApi(directory=tmp_path, endpoint=Endpoint(port=9318),
                        chain_fetch=refused,
                        ldap_factory=factory(StubDirectory()))
        result = api.certificate_screen(FORM)
        assert result["ok"] is True          # the call worked
        assert result["chain_read"] is False  # the chain did not
        assert "Connection refused" in result["html"]
        assert result["corroboration"] == CORROBORATION_UNAVAILABLE


# --------------------------------------------------------------------------- #
# Escaping — a certificate subject is attacker-influenceable text
# --------------------------------------------------------------------------- #

class TestEverythingIsEscaped:
    def test_a_hostile_subject_reaches_the_page_inert(self):
        hostile = '<img src=x onerror="alert(1)">'
        certificate, _ = issue(hostile,
                               not_before=certificate_facts(
                                   der(chain().root)).not_before,
                               not_after=certificate_facts(
                                   der(chain().root)).not_after,
                               is_ca=True)
        panel = a_panel(presented=[der(certificate)],
                        published=[certificate])
        assert hostile not in panel
        assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in panel
        assert "onerror=\"alert" not in panel

    def test_a_hostile_directory_dn_is_escaped(self):
        panel = a_panel(directory_error=RuntimeError(
            'failed: <script>alert("dn")</script>'))
        assert "<script>" not in panel
        assert "&lt;script&gt;" in panel

    def test_the_export_button_carries_only_hex(self):
        panel = a_panel(published=[chain().root])
        for value in re.findall(r'data-export-ca="([^"]*)"', panel):
            assert re.fullmatch(r"[0-9a-f]{64}", value), value


class TestADeadConnectionStopsTheContainerSearch:
    """One container's ACL is worth stepping over. A dead connection is not.

    The three PKI containers are searched separately so a permission problem on
    one does not hide the others. But after a TLS failure ldap3's ``Server`` is
    unusable, so searches two and three report "invalid server address" — a
    downstream symptom that reads, in the log, as a DNS or hostname problem and
    sends the reader after the wrong fault entirely.
    """

    #: A real TLS rejection, in the shape ldap3 actually wraps it.
    def _tls_failure(self):
        return LDAPSocketOpenError(
            "socket ssl wrapping error: [SSL: CERTIFICATE_VERIFY_FAILED] "
            "certificate verify failed: unable to get local issuer "
            "certificate (_ssl.c:1006)")

    def _counting_manager(self, error):
        searched = []

        class Manager:
            def search(self, search_base, search_filter, attributes=None,
                       **kwargs):
                searched.append(search_base)
                raise error

            def disconnect(self):
                pass

        return Manager(), searched

    def test_a_certificate_failure_stops_after_the_first_container(self):
        manager, searched = self._counting_manager(self._tls_failure())
        ca_certificates_from_directory(a_connection(), "pw",
                                       factory=factory(manager))

        assert len(searched) == 1, (
            f"searched {len(searched)} containers after the connection died; "
            "each extra search logs a misleading downstream error")

    def test_the_real_cause_is_what_gets_reported(self):
        manager, _ = self._counting_manager(self._tls_failure())
        result = ca_certificates_from_directory(a_connection(), "pw",
                                               factory=factory(manager))

        assert result.ok is False
        assert "CERTIFICATE_VERIFY_FAILED" in result.error
        assert "invalid server address" not in result.error.lower()

    def test_the_unattempted_containers_say_so_rather_than_vanishing(self):
        """An omission would read as "checked, found nothing"."""
        manager, _ = self._counting_manager(self._tls_failure())
        result = ca_certificates_from_directory(a_connection(), "pw",
                                               factory=factory(manager))

        assert len(result.containers) == len(pki_container_dns(BASE_DN)), (
            "every container must still have a row")
        not_checked = [item for item in result.containers
                       if "Not checked" in (item.error or "")]
        assert len(not_checked) == len(pki_container_dns(BASE_DN)) - 1
        for item in not_checked:
            assert item.ok is False
            assert item.count == 0
            # and the row must not be mistaken for the real failure
            assert "CERTIFICATE_VERIFY_FAILED" not in (item.error or "")

    def test_a_bind_failure_also_stops_the_search(self):
        """A wrong password is terminal too — and retrying risks a lockout."""
        manager, searched = self._counting_manager(
            LDAPBindError("invalidCredentials"))
        ca_certificates_from_directory(a_connection(), "pw",
                                       factory=factory(manager))

        assert len(searched) == 1

    def test_a_permission_failure_on_one_container_still_tries_the_rest(self):
        """The behaviour that must not regress: a per-container ACL problem.

        Searching the containers separately is the whole point — a reader who
        cannot see Enrollment Services can still see the published roots.
        """
        manager, searched = self._counting_manager(
            LDAPException("insufficientAccessRights"))
        result = ca_certificates_from_directory(a_connection(), "pw",
                                               factory=factory(manager))

        assert len(searched) == len(pki_container_dns(BASE_DN)), (
            "a permission failure on one container must not stop the others")
        assert not any("Not checked" in (item.error or "")
                       for item in result.containers)

    def test_the_panel_says_not_read_rather_than_showing_a_zero(self):
        """A "0" in the Certificates column would read as a real count."""
        panel = a_panel(directory_error=self._tls_failure())

        # The distinctive phrase, not the bare "Not checked" -- the
        # corroboration banner above already says "Not checked against Active
        # Directory", so the short form matches whether or not this fix is in.
        assert "so this search was not attempted" in panel
        assert "not read" in panel
        # the real cause is still the headline error, not one of three
        assert panel.count("invalid server address") == 0
