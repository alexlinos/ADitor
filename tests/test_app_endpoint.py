"""Tests for the MCP endpoint, its generated snippets, and its exposure.

Three properties are load-bearing here.

1. **The trailing slash.** The server mounts the MCP app with Starlette's
   ``Mount``, so a request to the bare path 307-redirects. A hand-copied URL
   gets this wrong routinely, so the app generates it — and these tests assert
   the slash survives every path shape a config could hold.
2. **The snippets are generated, never written down.** Changing the endpoint has
   to change both snippets, or they can drift from the server they describe.
3. **The exposure warning is present whenever the bind is not loopback.** That
   paragraph is exactly the copy a later tidy-up deletes for being long, so a
   test pins it.

No server is started and no port is bound. ``ServerProcess`` is driven with an
injected launcher.
"""

import json
from pathlib import Path

import pytest

from aditor.app.endpoint import (
    DEFAULT_HOST,
    EXPOSURE_WARNING,
    SERVER_KEY,
    Endpoint,
    ServerControlError,
    ServerProcess,
    assess_exposure,
    claude_code_command,
    claude_code_snippet,
    codex_snippet,
    config_uses_placeholder,
    default_endpoint,
    firewall_command,
    password_is_only_in_environment,
    snippets,
)
from aditor.app.credentials import (
    CONFIG_PASSWORD_PLACEHOLDER,
    PASSWORD_ENV_VAR,
)
from aditor.app.render import (
    render_exposure,
    render_server_status,
    render_snippets,
)
from aditor.app.settings import ConnectionSettings, build_config_document
from aditor.server import DEFAULT_PATH, DEFAULT_PORT

PASSWORD = "N0t-A-Real-Password-9f3ac1"


# --------------------------------------------------------------------------- #
# The URL, and the slash
# --------------------------------------------------------------------------- #

class TestEndpointUrl:
    def test_the_url_ends_with_a_slash(self):
        assert Endpoint().url().endswith("/")

    def test_the_default_is_the_documented_endpoint(self):
        assert Endpoint().url() == \
            f"http://{DEFAULT_HOST}:{DEFAULT_PORT}{DEFAULT_PATH}/"

    @pytest.mark.parametrize("path", [
        "/activedirectory-mcp",
        "activedirectory-mcp",
        "/activedirectory-mcp/",
        "//activedirectory-mcp//",
    ])
    def test_every_path_shape_yields_exactly_one_trailing_slash(self, path):
        url = Endpoint(path=path).url()
        assert url.endswith("/activedirectory-mcp/")
        assert not url.endswith("//")

    def test_a_wildcard_bind_is_never_dialled_as_a_wildcard(self):
        # 0.0.0.0 is a bind address, not a destination. A snippet containing it
        # would be a snippet that does not work.
        assert "0.0.0.0" not in Endpoint(host="0.0.0.0").url()
        assert Endpoint(host="0.0.0.0").client_host() == "localhost"

    def test_an_ipv6_literal_is_bracketed(self):
        assert Endpoint(host="::1").url().startswith("http://[::1]:")

    def test_an_already_bracketed_ipv6_literal_is_left_alone(self):
        assert Endpoint(host="[fe80::1]").client_host() == "[fe80::1]"

    def test_the_port_is_carried(self):
        assert ":9999/" in Endpoint(port=9999).url()


class TestLoopbackDetection:
    @pytest.mark.parametrize("host", ["127.0.0.1", "127.0.1.5", "localhost",
                                      "::1", "[::1]"])
    def test_loopback_hosts(self, host):
        assert Endpoint(host=host).is_loopback() is True

    @pytest.mark.parametrize("host", ["0.0.0.0", "::", "10.0.0.5",
                                      "dc01.example.com", ""])
    def test_non_loopback_hosts(self, host):
        assert Endpoint(host=host).is_loopback() is False

    def test_a_hostname_is_treated_as_exposed_rather_than_guessed_safe(self):
        # It might resolve to loopback, but the app cannot know without
        # resolving it, and guessing "safe" is the wrong way to be wrong.
        assert Endpoint(host="audit-host.example.com").is_loopback() is False

    def test_the_app_default_is_loopback(self):
        # The safe posture has to be what happens when nobody changes anything.
        assert DEFAULT_HOST == "127.0.0.1"
        assert default_endpoint().is_loopback() is True

    def test_the_app_default_diverges_from_the_servers_own_default(self):
        from aditor.server import DEFAULT_HOST as SERVER_DEFAULT

        # The headless server binds 0.0.0.0; a GUI must not put an
        # unauthenticated privileged AD API on the network out of the box.
        assert SERVER_DEFAULT == "0.0.0.0"
        assert DEFAULT_HOST != SERVER_DEFAULT


# --------------------------------------------------------------------------- #
# The generated snippets
# --------------------------------------------------------------------------- #

class TestClaudeCodeSnippet:
    def test_it_is_valid_json_with_the_live_url(self):
        endpoint = Endpoint(host="127.0.0.1", port=8813)
        document = json.loads(claude_code_snippet(endpoint))
        entry = document["mcpServers"][SERVER_KEY]
        assert entry["type"] == "http"
        assert entry["url"] == endpoint.url()

    def test_the_url_in_the_snippet_keeps_its_trailing_slash(self):
        document = json.loads(claude_code_snippet(Endpoint()))
        assert document["mcpServers"][SERVER_KEY]["url"].endswith(
            "/activedirectory-mcp/")

    def test_it_tracks_a_changed_endpoint(self):
        # The anti-drift property: there is no literal to forget to update.
        snippet = claude_code_snippet(Endpoint(host="10.1.2.3", port=9001))
        assert "http://10.1.2.3:9001/activedirectory-mcp/" in snippet
        assert "8813" not in snippet

    def test_the_command_form_carries_the_same_url(self):
        endpoint = Endpoint(port=9001)
        assert endpoint.url() in claude_code_command(endpoint)
        assert "--transport http" in claude_code_command(endpoint)


class TestCodexSnippet:
    def test_it_is_toml_naming_the_server_under_mcp_servers(self):
        snippet = codex_snippet(Endpoint())
        assert snippet.startswith(f"[mcp_servers.{SERVER_KEY}]")
        assert 'url = "' in snippet

    def test_the_url_keeps_its_trailing_slash(self):
        assert '/activedirectory-mcp/"' in codex_snippet(Endpoint())

    def test_it_tracks_a_changed_endpoint(self):
        snippet = codex_snippet(Endpoint(host="10.1.2.3", port=9001))
        assert "http://10.1.2.3:9001/activedirectory-mcp/" in snippet


class TestSnippetBundle:
    def test_both_clients_describe_the_same_endpoint(self):
        endpoint = Endpoint(port=9100)
        data = snippets(endpoint)
        # Two snippets that could disagree about where the server is would be
        # two chances to get it wrong.
        assert endpoint.url() in data["claude_code"]["snippet"]
        assert endpoint.url() in data["codex"]["snippet"]
        assert data["trailing_slash"] is True

    def test_each_client_has_numbered_steps(self):
        data = snippets(Endpoint())
        assert len(data["claude_code"]["steps"]) >= 4
        assert len(data["codex"]["steps"]) >= 3

    def test_the_windows_config_locations_are_named(self):
        data = snippets(Endpoint())
        claude = " ".join(data["claude_code"]["locations"])
        codex = " ".join(data["codex"]["locations"])
        assert "%USERPROFILE%" in claude and ".claude.json" in claude
        assert ".mcp.json" in claude
        assert r"%USERPROFILE%\.codex\config.toml" in codex

    def test_the_two_clients_do_not_share_a_config_file_path(self):
        data = snippets(Endpoint())
        assert set(data["claude_code"]["locations"]).isdisjoint(
            data["codex"]["locations"])

    def test_the_slash_is_explained_rather_than_left_to_chance(self):
        note = snippets(Endpoint())["trailing_slash_note"]
        assert "307" in note
        assert "Copy" in note

    def test_the_rendered_snippets_carry_the_url(self):
        rendered = render_snippets(snippets(Endpoint()))
        assert "http://127.0.0.1:8813/activedirectory-mcp/" in rendered
        assert "Claude Code" in rendered and "Codex" in rendered


# --------------------------------------------------------------------------- #
# Exposure — same box or on the network
# --------------------------------------------------------------------------- #

class TestExposure:
    def test_loopback_says_same_machine_and_no_firewall_change(self):
        assessment = assess_exposure(Endpoint(host="127.0.0.1"))
        assert assessment.loopback is True
        assert "no firewall change" in assessment.headline.lower()
        assert "only from this machine" in assessment.detail
        # No firewall command for a bind that needs none: telling someone to
        # open a port they do not need to open is how ports get opened.
        assert assessment.firewall_command == ""
        assert assessment.warning == ""

    @pytest.mark.parametrize("host", ["0.0.0.0", "10.0.0.5", "::",
                                      "audit-host.example.com"])
    def test_every_non_loopback_bind_carries_the_warning(self, host):
        # The assertion the coordinator asked for: this is the copy that gets
        # tidied away later.
        assessment = assess_exposure(Endpoint(host=host))
        assert assessment.loopback is False
        assert assessment.warning == EXPOSURE_WARNING
        assert assessment.firewall_command

    def test_the_warning_names_what_is_actually_exposed(self):
        assert "no authentication" in EXPOSURE_WARNING
        assert "no TLS" in EXPOSURE_WARNING
        # The app hides the write tools; the server it starts does not.
        assert "22 tools" in EXPOSURE_WARNING
        assert "write" in EXPOSURE_WARNING

    def test_the_warning_agrees_with_the_replatform_brief_rather_than_softening(
            self):
        # REPLATFORM_BRIEF.md section 8 records auth + TLS (WP6) as a hard gate
        # before any non-localhost deployment. The UI must not contradict it.
        assert "planned work and are not in this build" in EXPOSURE_WARNING
        assert "normal setup" in EXPOSURE_WARNING

    def test_the_recommendation_is_loopback_plus_a_tunnel(self):
        assessment = assess_exposure(Endpoint(host="10.0.0.5"))
        assert "loopback" in assessment.recommendation
        assert "SSH" in assessment.recommendation or \
            "VPN" in assessment.recommendation

    def test_the_firewall_rule_is_scoped_to_a_source_address(self):
        command = firewall_command(Endpoint(port=8813))
        assert "New-NetFirewallRule" in command
        assert "-LocalPort 8813" in command
        # The point of the whole function: without -RemoteAddress the rule
        # defaults to Any, which admits the entire network.
        assert "-RemoteAddress" in command
        assert "-RemoteAddress Any" not in command

    def test_the_firewall_note_says_not_to_use_any(self):
        note = assess_exposure(Endpoint(host="0.0.0.0")).firewall_note
        assert "Do not leave -RemoteAddress as Any" in note

    def test_the_rules_port_follows_the_endpoint(self):
        assert "-LocalPort 9100" in firewall_command(Endpoint(port=9100))


class TestExposureRendering:
    def test_a_non_loopback_bind_renders_the_warning_into_the_page(self):
        html = render_exposure(assess_exposure(Endpoint(host="0.0.0.0")))
        assert "no authentication" in html
        assert "New-NetFirewallRule" in html
        assert "banner-bad" in html

    def test_a_loopback_bind_renders_no_warning_and_no_firewall_command(self):
        html = render_exposure(assess_exposure(Endpoint(host="127.0.0.1")))
        assert "New-NetFirewallRule" not in html
        assert "no firewall change" in html.lower()


# --------------------------------------------------------------------------- #
# Starting and stopping — no port is bound and no server is launched
# --------------------------------------------------------------------------- #

class FakePopen:
    """Records the launch and stays "alive" until terminated."""

    instances = []

    def __init__(self, argv, env=None, **kwargs):
        self.argv = argv
        self.env = env or {}
        self.kwargs = kwargs
        self.pid = 4321
        self.stderr = None
        self._returncode = None
        self.terminated = False
        FakePopen.instances.append(self)

    def poll(self):
        return self._returncode

    def terminate(self):
        self.terminated = True
        self._returncode = 0

    def wait(self, timeout=None):
        self._returncode = 0
        return 0

    def kill(self):  # pragma: no cover - only on a stubborn child
        self._returncode = -9


@pytest.fixture
def saved_config(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(build_config_document(ConnectionSettings(
        server="ldaps://dc01.test.local:636", domain="test.local",
        base_dn="DC=test,DC=local",
        bind_dn="CN=svc-aditor,OU=Service Accounts,DC=test,DC=local"))))
    return path


@pytest.fixture(autouse=True)
def no_real_port_probe(monkeypatch):
    """Never probe a real port from this suite.

    The operator may have a live ADitor server on the default port and this
    suite must neither find it nor touch it.
    """
    monkeypatch.setattr("aditor.app.endpoint.port_is_in_use",
                        lambda host, port, timeout=0.4: False)


class TestServerProcess:
    def setup_method(self):
        FakePopen.instances = []

    def test_the_password_reaches_the_child_only_in_the_environment(
            self, saved_config):
        server = ServerProcess(endpoint=Endpoint(), config_path=saved_config)
        server.start(PASSWORD, popen=FakePopen)
        child = FakePopen.instances[-1]
        # argv is visible to every user via ps / Task Manager.
        assert not any(PASSWORD in str(item) for item in child.argv)
        assert child.env[PASSWORD_ENV_VAR] == PASSWORD
        assert password_is_only_in_environment(child.env, PASSWORD)

    def test_the_child_is_told_the_endpoint_the_snippets_describe(
            self, saved_config):
        endpoint = Endpoint(host="127.0.0.1", port=9100)
        server = ServerProcess(endpoint=endpoint, config_path=saved_config)
        server.start(PASSWORD, popen=FakePopen)
        argv = FakePopen.instances[-1].argv
        assert "--host" in argv and "127.0.0.1" in argv
        assert "--port" in argv and "9100" in argv
        assert "--path" in argv and endpoint.normalised_path() in argv
        assert "--config" in argv and str(saved_config) in argv

    def test_status_reports_the_url_the_client_should_use(self, saved_config):
        server = ServerProcess(endpoint=Endpoint(), config_path=saved_config)
        server.start(PASSWORD, popen=FakePopen)
        status = server.status()
        assert status["running"] is True
        assert status["url"].endswith("/activedirectory-mcp/")
        assert status["pid"] == 4321

    def test_stop_terminates_the_child(self, saved_config):
        server = ServerProcess(endpoint=Endpoint(), config_path=saved_config)
        server.start(PASSWORD, popen=FakePopen)
        server.stop()
        assert FakePopen.instances[-1].terminated is True
        assert server.running() is False

    def test_starting_twice_is_refused(self, saved_config):
        server = ServerProcess(endpoint=Endpoint(), config_path=saved_config)
        server.start(PASSWORD, popen=FakePopen)
        with pytest.raises(ServerControlError, match="already running"):
            server.start(PASSWORD, popen=FakePopen)

    def test_no_saved_config_is_refused_with_what_to_do(self, tmp_path):
        server = ServerProcess(endpoint=Endpoint(),
                               config_path=tmp_path / "missing.json")
        with pytest.raises(ServerControlError, match="no saved connection"):
            server.start(PASSWORD, popen=FakePopen)

    def test_no_password_is_refused_before_the_server_starts_and_fails(
            self, saved_config):
        server = ServerProcess(endpoint=Endpoint(), config_path=saved_config)
        with pytest.raises(ServerControlError, match="password"):
            server.start("", popen=FakePopen)
        assert FakePopen.instances == []

    def test_an_occupied_port_is_refused_and_the_other_server_left_alone(
            self, saved_config, monkeypatch):
        # An operator may already be running the server from a shell on this
        # port. Stopping it is not the app's business, so the app says what it
        # found and does nothing.
        monkeypatch.setattr("aditor.app.endpoint.port_is_in_use",
                            lambda host, port, timeout=0.4: True)
        server = ServerProcess(endpoint=Endpoint(), config_path=saved_config)
        with pytest.raises(ServerControlError) as caught:
            server.start(PASSWORD, popen=FakePopen)
        message = str(caught.value)
        assert "already listening" in message
        assert "will not stop it" in message
        assert FakePopen.instances == []

    def test_stopping_a_stopped_server_is_harmless(self, saved_config):
        server = ServerProcess(endpoint=Endpoint(), config_path=saved_config)
        assert server.stop()["running"] is False

    def test_status_renders_without_a_running_process(self):
        html = render_server_status(ServerProcess().status())
        assert "Server stopped" in html


class TestConfigPlaceholderCheck:
    def test_a_config_the_app_wrote_uses_the_placeholder(self, saved_config):
        assert config_uses_placeholder(saved_config) is True

    def test_a_config_with_a_real_password_is_noticed(self, tmp_path):
        path = tmp_path / "config.json"
        document = build_config_document(ConnectionSettings(base_dn="DC=x"))
        document["active_directory"]["password"] = PASSWORD
        path.write_text(json.dumps(document))
        assert config_uses_placeholder(path) is False

    def test_a_missing_file_is_false_rather_than_an_error(self, tmp_path):
        assert config_uses_placeholder(tmp_path / "nope.json") is False

    def test_the_placeholder_constant_is_the_one_the_loader_expands(self):
        assert CONFIG_PASSWORD_PLACEHOLDER == "${" + PASSWORD_ENV_VAR + "}"


class TestPasswordOnlyInEnvironmentHelper:
    def test_it_notices_a_leak_into_another_variable(self):
        env = {PASSWORD_ENV_VAR: PASSWORD, "SOME_OTHER": f"x{PASSWORD}y"}
        assert password_is_only_in_environment(env, PASSWORD) is False

    def test_it_passes_a_clean_environment(self):
        env = {PASSWORD_ENV_VAR: PASSWORD, "PATH": "/usr/bin"}
        assert password_is_only_in_environment(env, PASSWORD) is True

    def test_a_missing_variable_fails(self):
        assert password_is_only_in_environment({"PATH": "/usr/bin"},
                                               PASSWORD) is False


def test_the_web_assets_exist_where_the_shell_expects_them():
    from aditor.app.shell import index_path, web_root

    # No CDN and no bundler, so these files ship as they are; a missing one is
    # a blank window rather than an import error.
    assert index_path().is_file()
    assert (web_root() / "app.css").is_file()
    assert (web_root() / "app.js").is_file()
    assert Path(index_path()).read_text(encoding="utf-8").count("<svg") == 1
