"""The password must not appear in rendered HTML, in a log record, or on disk.

This is acceptance criterion 7 and it is the one test file that exists to prove a
negative. It drives :class:`aditor.app.api.AditorApi` through the whole app —
save the connection, test it, scan, list history, diff, generate snippets, start
the server — with one distinctive password, and then goes looking for that string
in every place it could have leaked:

* every HTML fragment any API method returned;
* every value any API method returned at all, at any depth;
* every log record emitted on any logger during the run;
* every byte of every file under the settings directory and the snapshot
  archive;
* the child server process's ``argv``.

The password is a fixed, distinctive literal so a substring match cannot pass by
accident, and it is chosen to contain characters that HTML-escaping would alter
(``&``, ``<``, ``"``) — so the search looks for the escaped form too. A leak that
survived only in escaped form would still be a leak.

Nothing here touches a real credential store, a real domain controller, or a
real port.
"""

import json
import logging
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from aditor.app.api import AditorApi
from aditor.app.credentials import (
    REDACTED,
    CredentialStore,
    install_redaction,
)
from aditor.app.endpoint import Endpoint
from aditor.app.render import esc
from aditor.tools.gpo import GPOTools

# Distinctive, and deliberately full of characters HTML-escaping changes, so the
# search below can look for both the raw and the escaped form.
PASSWORD = 'Zq7!&<Kestrel>"Marmalade"-42-9f3ac1'

BASE_DN = "DC=test,DC=local"
BIND_DN = f"CN=svc-aditor,OU=Service Accounts,{BASE_DN}"
POLICIES_DN = f"CN=Policies,CN=System,{BASE_DN}"

FORM = {
    "server": "ldaps://dc01.test.local:636",
    "domain": "test.local",
    "base_dn": BASE_DN,
    "bind_dn": BIND_DN,
    "password": PASSWORD,
    "validate_certificate": True,
}


class MemoryStore(CredentialStore):
    """An in-memory credential store. The real keychain is out of bounds."""

    name = "In-memory Store (test)"
    where = "memory"

    def __init__(self):
        self.items = {}

    def available(self):
        return True

    def set_password(self, ref, password):
        self.items[ref.target] = password

    def get_password(self, ref):
        return self.items.get(ref.target)

    def delete_password(self, ref):
        return self.items.pop(ref.target, None) is not None


class CapturingHandler(logging.Handler):
    """Every record emitted anywhere, formatted, for inspection afterwards."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.lines = []

    def emit(self, record):
        try:
            self.lines.append(self.format(record))
        except Exception:  # pragma: no cover - defensive
            self.lines.append(str(record.msg))


def gpo_entry(guid, display_name):
    return {
        "dn": f"CN={{{guid}}},CN=Policies,CN=System,{BASE_DN}",
        "attributes": {
            "cn": "{" + guid + "}",
            "displayName": display_name,
            "gPCFileSysPath":
                rf"\\test.local\SysVol\test.local\Policies\{{{guid}}}",
        },
    }


def sysvol_contents():
    return {
        "smb_source": r"\\dc01.test.local\SYSVOL",
        "files": [{"path": "GPT.INI", "size": 59}],
        "gpt_ini": {"General": ["Version=3"]},
        "machine_registry_pol": {"entry_count": 0, "entries_truncated": False,
                                 "entries": []},
        "user_registry_pol": None,
        "applocker": None,
        "security_templates": [{
            "path": r"Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf",
            "sections": {
                "Unicode": ["Unicode=yes"],
                "Registry Values": [
                    "MACHINE\\System\\CurrentControlSet\\Services\\NTDS"
                    "\\Parameters\\LdapEnforceChannelBinding=4,2"],
            },
        }],
        "scripts": [],
    }


class FakeManager:
    """An LDAP manager that never opens a socket but does hold the password."""

    def __init__(self, active, security, performance):
        self.ad_config = active
        self.security_config = security
        self.performance_config = performance

    def test_connection(self):
        return {"connected": True, "server": "dc01.test.local", "port": 636,
                "ssl": True, "bound": True, "search_test": True,
                "user": BIND_DN}

    def search(self, search_base=None, search_filter=None, **_kwargs):
        if "gPLink" in (search_filter or ""):
            return []
        if search_base == POLICIES_DN:
            return [gpo_entry("11111111-1111-1111-1111-111111111111",
                              "LDAP Hardening"),
                    gpo_entry("22222222-2222-2222-2222-222222222222",
                              "Workstation Baseline")]
        return []

    def disconnect(self):
        return None


class FakePopen:
    """Records the server launch. Nothing is executed and no port is bound."""

    instances = []

    def __init__(self, argv, env=None, **kwargs):
        self.argv = argv
        self.env = env or {}
        self.pid = 4321
        self.stderr = None
        self._returncode = None
        FakePopen.instances.append(self)

    def poll(self):
        return self._returncode

    def terminate(self):
        self._returncode = 0

    def wait(self, timeout=None):
        self._returncode = 0
        return 0

    def kill(self):  # pragma: no cover
        self._returncode = -9


# --------------------------------------------------------------------------- #
# The whole-app exercise
# --------------------------------------------------------------------------- #

@pytest.fixture
def exercised(tmp_path, monkeypatch):
    """Drive every API method that could see the password; collect everything.

    Returns ``(returned, log_lines, settings_dir, archive_dir, launches)``.
    """
    settings_dir = tmp_path / "settings"
    archive = tmp_path / "snapshots"

    # Never probe or bind a real port, and never open a browser.
    monkeypatch.setattr("aditor.app.endpoint.port_is_in_use",
                        lambda host, port, timeout=0.4: False)
    opened = []
    monkeypatch.setattr("aditor.app.api.webbrowser.open", opened.append)

    handler = CapturingHandler()
    handler.setFormatter(logging.Formatter(
        "%(name)s %(levelname)s %(message)s"))
    root = logging.getLogger()
    previous_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    # The app installs redaction in its constructor; make sure the filter is
    # attached before anything can log.
    install_redaction()

    FakePopen.instances = []
    returned = []

    def record(value):
        returned.append(value)
        return value

    try:
        api = AditorApi(directory=settings_dir, endpoint=Endpoint(port=9111),
                        store=MemoryStore())
        form = dict(FORM, snapshot_dir=str(archive))

        record(api.state())
        with patch("aditor.app.connection.build_manager",
                   side_effect=lambda s, p, f=None: FakeManager(
                       *_configs(s, p))):
            record(api.test_connection(form))
        record(api.save_connection(form))
        record(api.state())

        def read_sysvol(sysvol_path, include_registry=True,
                        max_value_chars=6000):
            return sysvol_contents()

        with patch.dict(sys.modules, {"smbclient": Mock()}), \
             patch.object(GPOTools, "_read_gpo_sysvol",
                          side_effect=read_sysvol), \
             patch("aditor.app.scanning.build_manager",
                   side_effect=lambda s, p, f=None: FakeManager(
                       *_configs(s, p))):
            record(api.start_scan())
            api._scan.join(60)
            first = record(api.scan_progress())
            # A second scan so History has two snapshots to diff.
            record(api.start_scan())
            api._scan.join(60)
            second = record(api.scan_progress())

        record(api.history())
        entries = sorted(path.name for path in archive.iterdir())
        assert len(entries) == 2, entries
        record(api.diff(entries[0], entries[1]))
        record(api.open_report(entries[1]))
        record(api.connect_screen())
        record(api.server_status())
        with patch("aditor.app.endpoint.subprocess.Popen", FakePopen):
            record(api.start_server())
            record(api.server_status())
            record(api.stop_server())
        record(api.forget_password())
        api.shutdown()
        assert first["passed"] is True and second["passed"] is True
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)

    return returned, handler.lines, settings_dir, archive, FakePopen.instances


def _configs(settings, password):
    """Build the three config objects a manager takes, holding the password."""
    from aditor.app.connection import _configs as build

    return build(settings, password)


def _walk(value, found):
    """Collect every string anywhere in a returned structure."""
    if isinstance(value, str):
        found.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            _walk(key, found)
            _walk(item, found)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            _walk(item, found)
    elif value is not None:
        found.append(str(value))


def _needles():
    """The forms the password could appear in.

    The escaped form matters: a leak that survived only as
    ``Zq7!&amp;&lt;Kestrel&gt;`` would still be a leak, and a naive search for
    the raw literal would miss it.
    """
    return [PASSWORD, esc(PASSWORD), json.dumps(PASSWORD),
            json.dumps(PASSWORD)[1:-1]]


class TestPasswordNeverLeaks:
    def test_it_appears_in_no_value_the_api_ever_returned(self, exercised):
        returned, _logs, _settings, _archive, _launches = exercised
        strings = []
        _walk(returned, strings)
        assert strings, "the exercise must actually have returned something"
        for needle in _needles():
            offenders = [text for text in strings if needle in text]
            assert offenders == [], \
                f"password leaked into an API return value: {offenders[:1]}"

    def test_it_appears_in_no_rendered_html(self, exercised):
        returned, _logs, _settings, _archive, _launches = exercised
        fragments = []
        for payload in returned:
            if isinstance(payload, dict):
                _collect_html(payload, fragments)
        assert fragments, "the exercise must have rendered some HTML"
        for needle in _needles():
            assert not any(needle in fragment for fragment in fragments)

    def test_it_appears_in_no_log_record(self, exercised):
        _returned, logs, _settings, _archive, _launches = exercised
        assert logs, "the exercise must actually have logged something"
        for needle in _needles():
            offenders = [line for line in logs if needle in line]
            assert offenders == [], \
                f"password leaked into a log record: {offenders[:1]}"

    def test_it_appears_in_no_persisted_file(self, exercised):
        _returned, _logs, settings, archive, _launches = exercised
        files = [path for path in list(_all_files(settings))
                 + list(_all_files(archive))]
        assert files, "the exercise must actually have written files"
        # The settings file specifically, since that is the one the brief names.
        assert (settings / "config.json").is_file()
        for path in files:
            blob = path.read_bytes()
            for needle in _needles():
                assert needle.encode("utf-8") not in blob, \
                    f"password leaked into {path}"

    def test_the_settings_file_holds_the_placeholder_instead(self, exercised):
        _returned, _logs, settings, _archive, _launches = exercised
        document = json.loads(
            (settings / "config.json").read_text(encoding="utf-8"))
        assert document["active_directory"]["password"] == \
            "${AD_MCP_PASSWORD}"

    def test_it_appears_in_no_child_process_argument(self, exercised):
        _returned, _logs, _settings, _archive, launches = exercised
        assert launches, "the exercise must actually have launched the server"
        for launch in launches:
            assert not any(PASSWORD in str(item) for item in launch.argv)
            # The one channel it is allowed to use.
            assert launch.env["AD_MCP_PASSWORD"] == PASSWORD

    def test_the_state_call_reports_only_that_a_password_exists(self, tmp_path,
                                                                monkeypatch):
        monkeypatch.setattr("aditor.app.endpoint.port_is_in_use",
                            lambda host, port, timeout=0.4: False)
        store = MemoryStore()
        api = AditorApi(directory=tmp_path, endpoint=Endpoint(port=9112),
                        store=store)
        api.save_connection(dict(FORM))
        state = api.state()
        assert state["password_present"] is True
        strings = []
        _walk(state, strings)
        assert not any(PASSWORD in text for text in strings)
        # It really is stored -- the absence above is not because nothing
        # happened.
        assert store.items
        assert list(store.items.values()) == [PASSWORD]


class TestRedactionBackstop:
    def test_a_future_edit_that_logs_the_password_still_cannot_leak_it(
            self, tmp_path, monkeypatch, caplog):
        # The filter is the belt to the braces above: nothing in this package
        # logs the password today, and this asserts that a later edit which did
        # would still be scrubbed.
        monkeypatch.setattr("aditor.app.endpoint.port_is_in_use",
                            lambda host, port, timeout=0.4: False)
        api = AditorApi(directory=tmp_path, endpoint=Endpoint(port=9113),
                        store=MemoryStore())
        api.save_connection(dict(FORM))

        handler = CapturingHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger = logging.getLogger("aditor.somewhere.new")
        install_redaction()
        logging.getLogger("aditor").addHandler(handler)
        try:
            logger.error("binding with %s", PASSWORD)
            logger.error(f"binding with {PASSWORD}")
        finally:
            logging.getLogger("aditor").removeHandler(handler)

        assert handler.lines
        for line in handler.lines:
            assert PASSWORD not in line
            assert REDACTED in line


def _collect_html(payload, into):
    for key, value in payload.items():
        if isinstance(value, str) and (key == "html" or key.endswith("_html")):
            into.append(value)
        elif isinstance(value, dict):
            _collect_html(value, into)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _collect_html(item, into)


def _all_files(root: Path):
    if not root.exists():
        return
    for path in root.rglob("*"):
        if path.is_file():
            yield path
