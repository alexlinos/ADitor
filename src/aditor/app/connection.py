"""Test the read-only bind, and say what actually went wrong.

The Connection screen's whole value is in the failure case. "Something went
wrong" is useless to a Windows administrator, because the three failures they
will actually hit have nothing in common:

* **invalid credentials** — retype the password, or check the account is not
  locked out;
* **certificate not trusted** — install the domain's issuing CA on this
  machine, or (knowingly) turn certificate validation off;
* **host unreachable** — wrong hostname, no route, LDAPS port closed.

So this module never invents a message. It calls the same
:meth:`aditor.core.ldap_manager.LDAPManager.test_connection` the scan's own
connection uses, and reports **the underlying error text
verbatim** in :attr:`ConnectionTestResult.error`. On top of that it
*classifies* the error to add a headline and a suggested fix — but the raw text
is always present and always shown, because the classifier is a convenience and
the error is the evidence. A new AD error the classifier has never seen degrades
to "the server rejected the connection" plus the server's own words, which is
still actionable.

The public entry point is :func:`run_connection_test`, which is the app's
call into :meth:`LDAPManager.test_connection`. It is not itself
named ``test_connection`` for a dull but real reason: pytest collects any
module-level ``test_*`` it can see, so a test file importing that name would
have it collected as a broken test case.

Nothing here writes anything, and the password is a parameter — never a field on
a persisted object, never in an error string. Every error string that comes back
from ldap3 passes through :func:`aditor.app.credentials.redact` before it is
returned, because "ldap3 does not put the bind password in its exception text
today" is not a property worth rendering a page on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..config.models import (
    ActiveDirectoryConfig,
    PerformanceConfig,
    SecurityConfig,
)
from .credentials import redact
from .settings import ConnectionSettings

# --------------------------------------------------------------------------- #
# Failure classification
# --------------------------------------------------------------------------- #
#
# Ordered: the first pattern that matches wins, so the specific cases come
# before the general ones. Each entry is (kind, needles, headline, fix).
#
# The needles are matched case-insensitively against the *whole* error string
# ldap3 produced. They are the strings ldap3, OpenSSL and the OS socket layer
# actually emit; where AD's own result code is more reliable than the prose
# (``data 52e`` and friends inside the diagnostic message), the code is the
# needle.

KIND_INVALID_CREDENTIALS = "invalid-credentials"
KIND_ACCOUNT_LOCKED = "account-locked"
KIND_ACCOUNT_DISABLED = "account-disabled"
KIND_PASSWORD_EXPIRED = "password-expired"
KIND_UNTRUSTED_CERTIFICATE = "untrusted-certificate"
KIND_CERTIFICATE_EXPIRED = "certificate-expired"
KIND_CERTIFICATE_HOSTNAME = "certificate-hostname"
KIND_TLS = "tls"
KIND_DNS = "dns"
KIND_REFUSED = "connection-refused"
KIND_TIMEOUT = "timeout"
KIND_UNREACHABLE = "host-unreachable"
KIND_REFERRAL = "referral"
KIND_UNKNOWN = "unknown"

_CLASSIFIERS: Tuple[Tuple[str, Tuple[str, ...], str, str], ...] = (
    (KIND_ACCOUNT_LOCKED,
     ("data 775",),
     "The bind account is locked out.",
     "Active Directory locked this account after too many failed sign-ins. "
     "Unlock it in Active Directory Users and Computers (or wait for the "
     "lockout duration to elapse) before testing again. Note that repeated "
     "tests with a wrong password are what caused this."),
    (KIND_ACCOUNT_DISABLED,
     ("data 533",),
     "The bind account is disabled.",
     "Enable the account in Active Directory Users and Computers. A read-only "
     "audit account still has to be an enabled account."),
    (KIND_PASSWORD_EXPIRED,
     ("data 532", "data 773"),
     "The bind account's password has expired or must be changed.",
     "Set a new password for the account (or clear 'user must change password "
     "at next logon'), then enter the new password here. An account flagged to "
     "change its password at next logon cannot complete an LDAP simple bind."),
    (KIND_INVALID_CREDENTIALS,
     ("invalidcredentials", "data 52e", "data 525", "invalid credentials",
      "80090308"),
     "The domain rejected the user name or password.",
     "Check the bind account and password. The account must be given in a form "
     "the domain accepts — either its full distinguished name "
     "(CN=svc-aditor,OU=Service Accounts,DC=example,DC=com) or "
     "user@domain.example.com. A read-only account is sufficient; it does not "
     "need to be a Domain Admin."),
    (KIND_CERTIFICATE_HOSTNAME,
     ("hostname mismatch", "certificate is not valid for", "does not match"),
     "The server's certificate does not match the host name you connected to.",
     "Connect using the exact name on the domain controller's certificate — "
     "usually its fully-qualified name (dc01.example.com), not its short name "
     "or its IP address."),
    # Before the untrusted-certificate entry, deliberately. An expired
    # certificate is a *different* failure with a different remedy: no amount
    # of installing CA certificates fixes it, and an operator told "not
    # trusted" will spend an hour in the trust store before noticing the date.
    (KIND_CERTIFICATE_EXPIRED,
     ("certificate has expired", "certificate is expired",
      "certificate_expired", "cert_has_expired", "certificate is not yet "
      "valid", "certificate_not_yet_valid"),
     "The domain controller's certificate is outside its validity period.",
     "This is not a trust problem and installing a CA certificate will not fix "
     "it: the certificate itself has expired (or has not started yet). It has "
     "to be reissued on the domain controller — where AD CS is in use, "
     "autoenrollment normally renews it, so 'certutil -pulse' on the "
     "controller and a look at the Certificate Auto Enrollment policy is the "
     "place to start. Check this machine's clock as well: a clock running "
     "ahead of the controller's makes a perfectly valid certificate look "
     "expired. The Certificate and trust panel shows the exact validity "
     "dates."),
    (KIND_UNTRUSTED_CERTIFICATE,
     ("certificate verify failed", "certificate_verify_failed",
      "unable to get local issuer", "self signed certificate",
      "self-signed certificate",
      "unable to verify the first certificate"),
     "The domain controller's certificate is not trusted by this machine.",
     "This is a certificate problem, not a password problem. Install the "
     "issuing CA certificate in this machine's Trusted Root store (that is the "
     "correct fix), or clear 'Validate certificate' to connect without "
     "checking it — which leaves the LDAPS connection open to interception and "
     "should be a temporary diagnostic step only. The Certificate and trust "
     "panel below shows what the controller presented, the SHA-256 "
     "fingerprint to confirm against the certification authority itself, "
     "whether Active Directory publishes that same CA, and the exact command "
     "to run — ADitor will not install it for you, because changing what this "
     "machine trusts is your decision to make."),
    (KIND_TLS,
     ("ssl", "tls", "wrap_socket", "wrong version number",
      "socket ssl wrapping error"),
     "The TLS handshake with the domain controller failed.",
     "Check that the server really speaks LDAPS on this port. Port 636 is "
     "LDAPS (TLS from the first byte); port 389 is plain LDAP and will fail a "
     "TLS handshake. Use ldaps://host:636 for a secure connection."),
    (KIND_DNS,
     ("getaddrinfo", "name or service not known", "nodename nor servname",
      "no such host", "name does not resolve", "temporary failure in name "
      "resolution"),
     "That host name could not be resolved.",
     "Check the spelling of the server name, and that this machine uses the "
     "domain's DNS servers. A domain controller's name normally only resolves "
     "against the domain's own DNS."),
    (KIND_REFUSED,
     ("connection refused", "actively refused", "econnrefused",
      "wsaeconnrefused", "10061"),
     "The host is reachable but refused the connection on that port.",
     "Nothing is listening on that port, or a firewall is rejecting it. "
     "Confirm the port (636 for LDAPS, 389 for LDAP) and that the domain "
     "controller allows LDAPS from this machine."),
    (KIND_TIMEOUT,
     ("timed out", "timeout", "etimedout", "10060"),
     "The connection attempt timed out.",
     "The host did not answer. That is usually a firewall dropping the "
     "traffic, or the wrong address. Check network reachability to the domain "
     "controller on the LDAPS port."),
    (KIND_UNREACHABLE,
     ("network is unreachable", "no route to host", "ehostunreach",
      "socket connection error"),
     "This machine has no route to that host.",
     "Check the address, this machine's network connection, and whether the "
     "domain controller is reachable from this network segment at all (a VPN "
     "or site-to-site link may be down)."),
    (KIND_REFERRAL,
     ("referral", "operationserror",),
     "The domain controller answered but rejected the request.",
     "The bind may have succeeded while the search did not. Check the Base DN: "
     "it must be the domain's own naming context, for example "
     "DC=example,DC=com."),
)

#: What to say when nothing matched. Deliberately not "something went wrong":
#: it names *where* the failure was and hands over the server's own words.
_UNKNOWN_HEADLINE = "The connection failed."
_UNKNOWN_FIX = (
    "ADitor does not recognise this error, so the domain controller's own "
    "message is shown above unchanged. It is the authoritative description of "
    "what happened — the three usual causes are a wrong password, an untrusted "
    "certificate and an unreachable host, and the text normally says which.")


def classify_error(error: Any) -> Tuple[str, str, str]:
    """``(kind, headline, fix)`` for an LDAP error string.

    A pure function of the text, so every branch is testable without a domain
    controller — which is the only way this table gets covered at all, since
    provoking a real ``data 775`` means locking out a real account.
    """
    text = str(error or "").lower()
    if not text.strip():
        return KIND_UNKNOWN, _UNKNOWN_HEADLINE, _UNKNOWN_FIX
    for kind, needles, headline, fix in _CLASSIFIERS:
        if any(needle in text for needle in needles):
            return kind, headline, fix
    return KIND_UNKNOWN, _UNKNOWN_HEADLINE, _UNKNOWN_FIX


# --------------------------------------------------------------------------- #
# The result
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ConnectionTestResult:
    """What the test found. The raw ``error`` is the load-bearing field.

    ``headline`` and ``fix`` are ADitor's reading of it; ``error`` is the domain
    controller's. A renderer must show ``error`` whenever there is one, because
    the classifier can be wrong and the error cannot.
    """

    ok: bool
    headline: str
    #: The underlying LDAP/socket/TLS error, verbatim (redacted of any
    #: registered secret). Empty on success.
    error: str = ""
    kind: str = ""
    fix: str = ""
    #: Server facts on success — host, port, whether TLS was used, whether the
    #: base-DN search worked.
    details: Dict[str, Any] = field(default_factory=dict)
    #: Non-fatal observations: a successful bind whose base-DN search failed,
    #: certificate validation being switched off, and so on.
    warnings: List[str] = field(default_factory=list)


def _configs(settings: ConnectionSettings, password: str
             ) -> Tuple[ActiveDirectoryConfig, SecurityConfig,
                        PerformanceConfig]:
    """The three config objects ``LDAPManager`` wants, built in memory only.

    Nothing here is written anywhere. This is the one place the password enters
    a config object, and that object is a local that goes out of scope when the
    test returns.
    """
    active = ActiveDirectoryConfig(
        server=str(settings.server or "").strip(),
        use_ssl=True,
        domain=str(settings.domain or "").strip(),
        base_dn=str(settings.base_dn or "").strip(),
        bind_dn=str(settings.bind_dn or "").strip(),
        password=password,
        timeout=15,
        receive_timeout=15,
    )
    security = SecurityConfig(
        enable_tls=True,
        validate_certificate=bool(settings.validate_certificate),
        # Without this the scan and the connection test verify against the
        # platform trust store, which on macOS is not the store the operator
        # just imported into -- see ConnectionSettings.ca_cert_file.
        ca_cert_file=str(getattr(settings, "ca_cert_file", "") or "").strip()
        or None,
        require_secure_connection=True,
    )
    # One attempt. Three would triple the failed-logon count of a wrong
    # password against a real lockout policy, and an interactive test wants its
    # answer now.
    performance = PerformanceConfig(max_retries=1, retry_delay=1.0)
    return active, security, performance


#: Signature of the injectable manager factory: the three configs in, something
#: with a ``test_connection()`` and a ``disconnect()`` out.
ManagerFactory = Callable[[ActiveDirectoryConfig, SecurityConfig,
                           PerformanceConfig], Any]


def build_manager(settings: ConnectionSettings, password: str,
                  factory: Optional[ManagerFactory] = None) -> Any:
    """An :class:`LDAPManager` for these settings. Does not connect.

    ``LDAPManager.__init__`` only builds the ldap3 ``Server`` objects; the bind
    happens on first use. Shared with :mod:`aditor.app.scanning` so the scan and
    the connection test cannot end up configured differently — which is exactly
    how a "test passed, scan failed" report gets filed.
    """
    active, security, performance = _configs(settings, password)
    if factory is not None:
        return factory(active, security, performance)
    from ..core.ldap_manager import LDAPManager

    return LDAPManager(active, security, performance)


def run_connection_test(settings: ConnectionSettings, password: str,
                        factory: Optional[ManagerFactory] = None
                        ) -> ConnectionTestResult:
    """Bind read-only, run one base-scoped search, and report what happened.

    Args:
        settings: The connection as it stands in the form — not necessarily the
            saved one, because testing before saving is the normal order.
        password: The password, as typed. Held only for this call.
        factory: Injected manager builder, for tests. Production passes nothing.

    Returns:
        A :class:`ConnectionTestResult`. On failure its ``error`` is the
        underlying LDAP error text, unaltered apart from secret redaction.
    """
    missing = settings.missing_fields()
    if missing:
        return ConnectionTestResult(
            ok=False,
            kind="incomplete",
            headline="This connection is not filled in yet.",
            error="",
            fix=f"Still needed: {', '.join(missing)}.")
    if not password:
        return ConnectionTestResult(
            ok=False,
            kind="incomplete",
            headline="No password entered.",
            error="",
            fix="Enter the bind account's password. ADitor keeps it in the OS "
                "credential store, never in a file.")

    try:
        manager = build_manager(settings, password, factory)
    except Exception as exc:
        # A malformed server URL is caught by the config model's validator, so
        # this is the "ldaps:// or ldap://" case and a handful of others. It is
        # a configuration error, not a network one; report it as itself.
        return ConnectionTestResult(
            ok=False,
            kind="configuration",
            headline="These connection settings are not usable.",
            error=redact(str(exc)),
            fix="Fix the field the message names. The server must be given as "
                "ldaps://host:636 (recommended) or ldap://host:389.")

    try:
        info = manager.test_connection() or {}
    except Exception as exc:  # pragma: no cover - LDAPManager catches its own
        error = redact(str(exc))
        kind, headline, fix = classify_error(error)
        return ConnectionTestResult(ok=False, kind=kind, headline=headline,
                                    error=error, fix=fix)
    finally:
        try:
            manager.disconnect()
        except Exception:
            # A failed disconnect after a failed connect is noise; the failure
            # the operator needs is the one above.
            pass

    if not info.get("connected"):
        error = redact(str(info.get("error") or ""))
        kind, headline, fix = classify_error(error)
        return ConnectionTestResult(ok=False, kind=kind, headline=headline,
                                    error=error, fix=fix)

    warnings: List[str] = []
    if not settings.validate_certificate:
        warnings.append(
            "Certificate validation is switched off for this connection. The "
            "LDAPS session is encrypted but unauthenticated, so it can be "
            "intercepted. Install the domain's issuing CA on this machine and "
            "turn validation back on.")
    if info.get("search_test") is False:
        warnings.append(
            "The bind succeeded but a search of the Base DN did not: "
            f"{redact(str(info.get('search_error') or 'no detail given'))}. "
            "Check the Base DN — a scan reads Group Policy objects under it, "
            "so a wrong Base DN binds fine and then finds nothing.")

    return ConnectionTestResult(
        ok=True,
        kind="ok",
        headline="Connected. The bind and a read of the Base DN both "
                 "succeeded.",
        details={
            "server": info.get("server"),
            "port": info.get("port"),
            "ssl": info.get("ssl"),
            "bound": info.get("bound"),
            "search_test": info.get("search_test"),
            # ``connection.user`` is the bind DN. It is the account, not the
            # secret, and showing it is how an operator spots that they typed
            # the wrong one.
            "bind_account": info.get("user"),
        },
        warnings=warnings)


__all__ = [
    "KIND_ACCOUNT_DISABLED",
    "KIND_ACCOUNT_LOCKED",
    "KIND_CERTIFICATE_EXPIRED",
    "KIND_CERTIFICATE_HOSTNAME",
    "KIND_DNS",
    "KIND_INVALID_CREDENTIALS",
    "KIND_PASSWORD_EXPIRED",
    "KIND_REFUSED",
    "KIND_REFERRAL",
    "KIND_TIMEOUT",
    "KIND_TLS",
    "KIND_UNKNOWN",
    "KIND_UNREACHABLE",
    "KIND_UNTRUSTED_CERTIFICATE",
    "ConnectionTestResult",
    "build_manager",
    "classify_error",
    "run_connection_test",
]
