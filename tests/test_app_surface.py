"""What the app exposes, and what it must not.

Two things are asserted here.

**The surface.** The MCP server offers 52 tools, 22 of which write to Active
Directory. The app exposes **none** of the write tools, and it exposes no generic
"call this tool by name" method either — the page cannot reach a write tool by
asking for one. That property is easy to lose by accident (one convenience
passthrough) so it is pinned against the live tool registry rather than against a
hand-written list that could go stale.

**The GUI is optional.** ``pip install -e .`` without the ``gui`` extra has to
keep working and the headless server has to keep starting: pywebview is imported
lazily, in one module, and nothing on the server's import path reaches it. The
tests below simulate its absence.
"""

import builtins
import importlib
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from aditor.app.api import AditorApi
from aditor.app.endpoint import Endpoint
from aditor.registry import TOOLS

REPO_ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- #
# The exposed surface
# --------------------------------------------------------------------------- #

#: Everything the page is allowed to call. Adding to this list is a deliberate
#: act, which is the point of writing it down.
ALLOWED_API_METHODS = {
    "certificate_screen",
    "connect_screen",
    "diff",
    "export_ca_certificate",
    "forget_password",
    "history",
    "open_path",
    "open_report",
    "save_connection",
    "scan_progress",
    "server_status",
    "shutdown",
    "start_scan",
    "start_server",
    "state",
    "stop_server",
    "test_connection",
}

#: Every registry tool that changes the directory. Derived from the registry so
#: a newly added write tool is caught rather than assumed absent.
_WRITE_VERBS = ("create_", "modify_", "delete_", "move_", "add_", "remove_",
                "enable_", "disable_", "reset_")


def write_tool_names():
    return {spec.name for spec in TOOLS
            if spec.name.startswith(_WRITE_VERBS)}


class TestApiSurface:
    def test_the_public_surface_is_exactly_the_four_screens_worth(self,
                                                                  tmp_path):
        api = AditorApi(directory=tmp_path, endpoint=Endpoint(port=9201))
        public = {name for name in dir(api)
                  if not name.startswith("_")
                  and callable(getattr(api, name))}
        # ``connection`` is a property, not a method, so it is not here.
        assert public == ALLOWED_API_METHODS

    def test_the_registry_really_does_hold_write_tools(self):
        # If this ever emptied out, the next test would pass vacuously.
        assert len(write_tool_names()) >= 20

    def test_no_write_tool_is_reachable_from_the_page(self, tmp_path):
        api = AditorApi(directory=tmp_path, endpoint=Endpoint(port=9202))
        exposed = {name for name in dir(api) if not name.startswith("_")}
        assert exposed.isdisjoint(write_tool_names())

    def test_there_is_no_generic_tool_dispatch_method(self, tmp_path):
        api = AditorApi(directory=tmp_path, endpoint=Endpoint(port=9203))
        # One passthrough like this would hand the page all 52 tools at once.
        for name in ("call", "call_tool", "invoke", "run_tool", "dispatch",
                     "execute", "eval", "tool"):
            assert not hasattr(api, name)

    def test_no_api_method_takes_a_tool_name(self, tmp_path):
        import inspect

        api = AditorApi(directory=tmp_path, endpoint=Endpoint(port=9204))
        for name in ALLOWED_API_METHODS:
            parameters = set(
                inspect.signature(getattr(api, name)).parameters)
            assert not parameters & {"tool", "tool_name", "operation",
                                     "method", "name"}, name

    def test_the_page_never_receives_the_password_field_name(self):
        # The form field is write-only: JS reads it and posts it, and nothing
        # sends it back. A round-trip would put it in the DOM.
        script = (REPO_ROOT / "src" / "aditor" / "app" / "web" / "app.js"
                  ).read_text(encoding="utf-8")
        assert "f-password').value = ''" in script
        assert "password_present" in script
        # The only writes to the field are clears.
        assignments = [line for line in script.splitlines()
                       if "f-password').value" in line and "=" in line]
        assert all("''" in line for line in assignments), assignments

    def test_the_javascript_builds_no_markup_from_data(self):
        script = (REPO_ROOT / "src" / "aditor" / "app" / "web" / "app.js"
                  ).read_text(encoding="utf-8")
        # innerHTML is assigned only inside paint(), from a Python-rendered
        # fragment. Any other assignment would be markup built in JS.
        assignments = [line.strip() for line in script.splitlines()
                       if "innerHTML" in line]
        assert assignments == [
            "if (node) { node.innerHTML = html || ''; }"], assignments


def walk_bridge_attributes(obj, prefix="", seen=None):
    """Reproduce how pywebview builds the JavaScript API from an object.

    ``webview.util.get_functions`` iterates every attribute whose name does not
    start with an underscore, collects the callables, and **recurses into the
    ones that are not**. So a public non-callable attribute on the API object
    puts that object -- and the behaviour of its own properties -- inside the
    bridge.

    Mirrored here rather than imported so this runs without pywebview
    installed, which is most of the time.
    """
    seen = seen if seen is not None else []
    for name in dir(obj):
        if name.startswith("_"):
            continue
        attribute = getattr(obj, name)          # a raising property fails here
        full = f"{prefix}{name}"
        if callable(attribute):
            seen.append(full)
        else:
            walk_bridge_attributes(attribute, f"{full}.", seen)
    return seen


class TestBridgeGeneration:
    """Regression tests for a bug found by actually launching the window.

    A public ``connection`` property on the API object let pywebview's
    generator reach ``ConnectionSettings.credential_ref``, which raised on an
    empty bind account -- so the JS bridge failed to build on a fresh install
    and every button was dead. Neither the unit tests nor `--check` could see
    it; only running the app did.
    """

    def test_the_bridge_builds_from_an_untouched_install(self, tmp_path):
        api = AditorApi(directory=tmp_path, endpoint=Endpoint(port=9206))
        assert set(walk_bridge_attributes(api)) == ALLOWED_API_METHODS

    def test_the_api_object_exposes_no_public_non_callable_attribute(self,
                                                                    tmp_path):
        api = AditorApi(directory=tmp_path, endpoint=Endpoint(port=9207))
        walked = {name for name in dir(api) if not name.startswith("_")}
        # Anything here that is not a method is something pywebview would
        # recurse into.
        assert walked == ALLOWED_API_METHODS

    def test_an_empty_bind_account_has_no_credential_reference(self):
        from aditor.app.settings import ConnectionSettings

        # None, not a raise: a blank form is the normal state on first run, and
        # a property that raises there is a trap for anything that walks the
        # object.
        assert ConnectionSettings().credential_ref is None
        assert ConnectionSettings(bind_dn="CN=a,DC=test,DC=local"
                                  ).credential_ref is not None


class TestContentSecurityPolicy:
    """The policy is the measured one, not the strictest one.

    A strict ``script-src 'self'`` was tried first and the web view refused to
    evaluate pywebview's own bridge — ``window.pywebview`` never appeared and
    every button in the window was dead. These tests record both halves of that
    finding so the policy is not "hardened" back into breaking the app, and not
    loosened in the directions that actually matter.
    """

    @staticmethod
    def policy():
        index = (REPO_ROOT / "src" / "aditor" / "app" / "web" / "index.html"
                 ).read_text(encoding="utf-8")
        marker = 'content="default-src'
        start = index.index(marker) + len('content="')
        return index[start:index.index('"', start)]

    def test_the_page_can_make_no_network_request(self):
        policy = self.policy()
        # The part that matters for a window rendering directory content:
        # nothing can be exfiltrated and no CDN can creep in later.
        assert "default-src 'none'" in policy
        assert "connect-src 'none'" in policy
        assert "form-action 'none'" in policy
        assert "base-uri 'none'" in policy

    def test_unsafe_eval_is_present_because_pywebview_needs_it(self):
        assert "script-src 'self' 'unsafe-eval'" in self.policy()

    def test_inline_styles_stay_forbidden(self):
        policy = self.policy()
        assert "style-src 'self'" in policy
        assert "style-src 'self' 'unsafe-inline'" not in policy

    def test_no_element_carries_an_inline_style(self):
        # Which is why style-src can stay strict. A div-based progress bar with
        # style="width:0%" was silently blocked from ever moving.
        index = (REPO_ROOT / "src" / "aditor" / "app" / "web" / "index.html"
                 ).read_text(encoding="utf-8")
        assert 'style="' not in index
        script = (REPO_ROOT / "src" / "aditor" / "app" / "web" / "app.js"
                  ).read_text(encoding="utf-8")
        assert ".style." not in script

    def test_the_progress_bar_is_a_progress_element(self):
        index = (REPO_ROOT / "src" / "aditor" / "app" / "web" / "index.html"
                 ).read_text(encoding="utf-8")
        assert '<progress id="scan-bar"' in index


class TestNoNetworkAtStartup:
    def test_constructing_the_api_contacts_nothing(self, tmp_path,
                                                   monkeypatch):
        # Opening the window must not dial the domain controller or probe a
        # port. A GUI that connects on launch cannot be opened to fix a wrong
        # setting.
        import socket

        def refuse(*args, **kwargs):
            raise AssertionError("the app must not open a socket at startup")

        monkeypatch.setattr(socket.socket, "connect", refuse)
        monkeypatch.setattr(socket.socket, "connect_ex", refuse)
        monkeypatch.setattr(socket, "getaddrinfo", refuse)
        api = AditorApi(directory=tmp_path, endpoint=Endpoint(port=9205))
        assert api.state()["ok"] is True


# --------------------------------------------------------------------------- #
# The GUI extra is optional
# --------------------------------------------------------------------------- #

class TestGuiIsOptional:
    def test_pyproject_declares_pywebview_as_an_extra_not_a_dependency(self):
        document = tomllib.loads(
            (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        project = document["project"]
        runtime = " ".join(project["dependencies"]).lower()
        assert "pywebview" not in runtime
        extras = project["optional-dependencies"]
        assert any("pywebview" in item for item in extras["gui"])

    def test_the_web_assets_travel_in_the_wheel(self):
        document = tomllib.loads(
            (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        patterns = document["tool"]["setuptools"]["package-data"]["aditor"]
        # No bundler, so these ship as files; a missing one is a blank window.
        for suffix in ("html", "css", "js"):
            assert any(f"app/web/*.{suffix}" == pattern
                       for pattern in patterns), suffix

    def test_only_the_shell_module_imports_webview(self):
        app_dir = REPO_ROOT / "src" / "aditor" / "app"
        importers = sorted(
            path.name for path in app_dir.glob("*.py")
            if "import webview" in path.read_text(encoding="utf-8"))
        assert importers == ["shell.py"]

    def test_the_whole_app_package_imports_without_pywebview(self):
        # Every module except the window itself has to be importable, because
        # that is what makes the extra optional rather than notional.
        real_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name == "webview" or name.startswith("webview."):
                raise ImportError("No module named 'webview'")
            return real_import(name, *args, **kwargs)

        modules = ["aditor.app", "aditor.app.api", "aditor.app.credentials",
                   "aditor.app.settings", "aditor.app.connection",
                   "aditor.app.endpoint", "aditor.app.history",
                   "aditor.app.render", "aditor.app.scanning",
                   "aditor.app.shell", "aditor.app.__main__"]
        saved = {name: sys.modules.pop(name, None) for name in modules}
        builtins.__import__ = blocked
        try:
            for name in modules:
                importlib.import_module(name)
        finally:
            builtins.__import__ = real_import
            for name, module in saved.items():
                if module is not None:
                    sys.modules[name] = module

    def test_a_missing_pywebview_gives_the_install_command_not_a_traceback(
            self):
        from aditor.app.shell import WebviewMissing, require_webview

        real_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name == "webview":
                raise ImportError("No module named 'webview'")
            return real_import(name, *args, **kwargs)

        builtins.__import__ = blocked
        try:
            with pytest.raises(WebviewMissing) as caught:
                require_webview()
        finally:
            builtins.__import__ = real_import
        message = str(caught.value)
        assert 'pip install -e ".[gui]"' in message
        # And it points at the thing that still works.
        assert "aditor.server" in message

    def test_the_server_module_does_not_reach_the_app_package(self):
        source = (REPO_ROOT / "src" / "aditor" / "server.py"
                  ).read_text(encoding="utf-8")
        assert "aditor.app" not in source
        assert "from .app" not in source

    def test_the_registry_does_not_reach_the_app_package(self):
        source = (REPO_ROOT / "src" / "aditor" / "registry.py"
                  ).read_text(encoding="utf-8")
        assert "from .app" not in source


class TestEntryPoint:
    def test_check_prints_the_snippets_without_opening_a_window(self):
        # Runs the real entry point in a subprocess, which is the closest thing
        # to the acceptance criterion that does not need a display.
        completed = subprocess.run(
            [sys.executable, "-m", "aditor.app", "--check"],
            cwd=str(REPO_ROOT), capture_output=True, text=True,
            env={"PYTHONPATH": str(REPO_ROOT / "src"), "PATH": "/usr/bin:/bin",
                 "HOME": str(Path.home())},
            check=False)
        assert completed.returncode == 0, completed.stderr
        assert "http://127.0.0.1:8813/activedirectory-mcp/" in completed.stdout
        assert "[mcp_servers.aditor]" in completed.stdout
        assert '"mcpServers"' in completed.stdout

    def test_check_reports_the_exposure_warning_for_a_routable_bind(self):
        completed = subprocess.run(
            [sys.executable, "-m", "aditor.app", "--check",
             "--host", "0.0.0.0"],
            cwd=str(REPO_ROOT), capture_output=True, text=True,
            env={"PYTHONPATH": str(REPO_ROOT / "src"), "PATH": "/usr/bin:/bin",
                 "HOME": str(Path.home())},
            check=False)
        assert completed.returncode == 0, completed.stderr
        assert "New-NetFirewallRule" in completed.stdout
        assert "-RemoteAddress" in completed.stdout
        assert "no authentication" in completed.stdout
        # Even bound to a wildcard, the snippet a client uses is dialable.
        assert "http://localhost:8813/activedirectory-mcp/" in completed.stdout
