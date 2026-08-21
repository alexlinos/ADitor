"""What the operator does next — which depends entirely on the machine.

:mod:`aditor.app.certificates` establishes *what* the chain is. This module is
about *what to do about it*, and the answer is genuinely different on the two
machines this app runs on. Offering one answer would be wrong on one of them,
and wrong in a way that costs more than it looks:

**Domain-joined Windows.** The enterprise root is supposed to arrive on its own.
A member computer gets it from Group Policy — this domain has a *Certificate Auto
Enrollment* policy linked at the domain root — and if it has not arrived, then
that mechanism is not working. Importing the certificate by hand *does* fix
LDAPS on this one machine, and that is exactly the problem: it removes the
symptom that was pointing at a broken enterprise PKI. Every other domain member
is in the same state, and so is everything else that depends on it — smartcard
logon, RDP host certificates, 802.1X, the next tool someone points at LDAPS. So
on a joined machine the guidance leads with ``gpupdate`` / ``certutil -pulse``
and the GPO, and offers the manual import only afterwards, labelled as a
stopgap.

**Not joined** — the operator's Mac, or a standalone jump box. Autoenrollment is
not a thing here and never will be, so manual trust is not a workaround, it is
the correct fix. On macOS the guidance also has to say the part that costs an
hour otherwise: adding the certificate to the System keychain does *not* change
what Python's TLS stack trusts, because ADitor's LDAPS connection goes through
OpenSSL, and OpenSSL on macOS does not read the keychain.

**Unknown.** Detection can fail — a Windows machine whose environment does not
carry the usual markers. That is a third state, and it renders as "could not
tell" with both paths and the command to settle it, rather than being rounded to
whichever is more convenient.

Nothing in this module runs any of the commands it returns. It builds strings.
The operator runs them, and the elevation prompt they get on the way is not an
obstacle to be smoothed away — it is the moment a human decides to change what
their machine trusts.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

from .certificates import (
    CertificateFacts,
    ChainInspection,
    Corroboration,
    DirectoryCertificates,
    ca_certificates_from_directory,
    compare_chain_with_directory,
    inspect_ldaps_chain,
    parse_ldap_url,
)

# --------------------------------------------------------------------------- #
# Which machine is this
# --------------------------------------------------------------------------- #

MACHINE_WINDOWS_JOINED = "windows-domain-joined"
MACHINE_WINDOWS_STANDALONE = "windows-standalone"
MACHINE_WINDOWS_UNKNOWN = "windows-unknown"
MACHINE_MACOS = "macos"
MACHINE_OTHER = "other"

#: Where a ``.crt`` written by :func:`export_ca_certificate` goes, relative to
#: the app's own settings directory. Not the snapshot archive: that holds
#: directory content and gets attached to tickets, and a CA certificate is a
#: different kind of thing with a different lifetime.
EXPORT_DIRNAME = "exported-certificates"


@dataclass(frozen=True)
class InstallStep:
    """One thing to run or check, in order.

    ``command`` is text for the operator to copy. Nothing in ADitor executes
    it; there is no code path in this package that runs a shell command against
    a trust store, and the absence is asserted by test.
    """

    label: str
    command: str = ""
    note: str = ""


@dataclass(frozen=True)
class MachineContext:
    """Which of the three situations this machine is in, and what follows.

    :attr:`manual_import_is_the_fix` is the field the renderer keys off, and it
    is deliberately not ``not domain_joined``: an *unknown* machine gets neither
    answer presented as the answer.
    """

    kind: str
    system: str
    #: ``True``/``False``/``None`` — and ``None`` is a real answer.
    domain_joined: Optional[bool]
    #: Which signal decided it. Shown on screen, because a detection the
    #: operator can check is worth more than one they have to believe.
    evidence: str
    headline: str
    manual_import_is_the_fix: bool
    #: What the operator should do, in order.
    steps: Tuple[InstallStep, ...] = ()

    @property
    def is_windows(self) -> bool:
        return self.kind.startswith("windows")


def _windows_join_signal(env: Dict[str, str]) -> Tuple[Optional[bool], str]:
    """Domain-joined or not, from the environment, without running anything.

    Environment variables rather than a WMI query or a ``systeminfo``
    subprocess: this runs on window open, and an app that shells out on a UI
    path is an app that hangs when the thing it shelled out to hangs. The
    signals are the ones a logon actually sets, in order of how much they mean:

    * ``USERDNSDOMAIN`` — set by a domain logon and by nothing else;
    * ``USERDOMAIN`` differing from ``COMPUTERNAME`` — a domain account rather
      than a local one;
    * ``USERDOMAIN`` equal to ``COMPUTERNAME`` — a local account, which on a
      *joined* machine is possible but unusual.

    Returns ``(None, reason)`` when none of them is conclusive, because a wrong
    confident answer here sends the operator down the wrong remedy entirely.
    """
    dns_domain = str(env.get("USERDNSDOMAIN") or "").strip()
    if dns_domain:
        return True, ("the USERDNSDOMAIN environment variable is set, which "
                      "only a domain logon sets")
    user_domain = str(env.get("USERDOMAIN") or "").strip()
    computer = str(env.get("COMPUTERNAME") or "").strip()
    if user_domain and computer:
        if user_domain.upper() != computer.upper():
            return True, ("you are signed in with a domain account "
                          "(USERDOMAIN is not this computer's name)")
        return False, ("you are signed in with a local account and no domain "
                       "markers are present")
    return None, ("this machine's environment carries no domain markers either "
                  "way")


def _joined_steps() -> Tuple[InstallStep, ...]:
    return (
        InstallStep(
            label="Do not import it by hand first — find out why it is "
                  "missing",
            note="On a domain-joined machine the enterprise root arrives "
                 "through Group Policy autoenrollment. If it is missing here, "
                 "that mechanism is not working, and every other domain "
                 "member is in the same state. A manual import fixes LDAPS on "
                 "this one machine and hides the cause."),
        InstallStep(
            label="Re-apply computer policy",
            command="gpupdate /target:computer /force",
            note="Run it from an elevated Command Prompt. Autoenrollment is a "
                 "computer policy, so a user-scope refresh will not do it."),
        InstallStep(
            label="Trigger autoenrollment immediately",
            command="certutil -pulse",
            note="Does not wait for the autoenrollment timer. Also elevated."),
        InstallStep(
            label="Check whether the root arrived",
            command="certutil -store -enterprise Root",
            note="Then compare the SHA-256 fingerprint shown above with what "
                 "this lists. Add -v if you need the full certificate."),
        InstallStep(
            label="Check the Certificate Auto Enrollment policy itself",
            command="gpresult /scope computer /r",
            note="Confirm the Certificate Auto Enrollment GPO is in the "
                 "applied list for this computer. If it is filtered out, "
                 "denied, or its 'Renew expired, update pending' option is "
                 "off, that is the actual fault and it belongs in a ticket of "
                 "its own."),
        InstallStep(
            label="Only if the above is confirmed working and the root still "
                  "does not arrive",
            command='certutil -addstore -f Root "{path}"',
            note="A stopgap on this one machine, from an elevated prompt, and "
                 "only after you have confirmed the fingerprint out of band. "
                 "It does not fix the autoenrollment fault."),
    )


def _standalone_windows_steps() -> Tuple[InstallStep, ...]:
    return (
        InstallStep(
            label="Confirm the fingerprint out of band first",
            command='certutil -hashfile "{path}" SHA256',
            note="This prints the fingerprint of the file ADitor exported. It "
                 "has to match both the fingerprint shown above and the one "
                 "you read off the CA server itself. If you have not checked "
                 "the second of those, stop here."),
        InstallStep(
            label="Import it into the machine's Trusted Root store",
            command='certutil -addstore -f Root "{path}"',
            note="From an elevated Command Prompt. This machine is not joined "
                 "to the domain, so nothing is going to deliver this "
                 "certificate for you and a manual import is the correct fix "
                 "rather than a workaround. It changes trust for every user "
                 "and every program on the machine, which is why it needs "
                 "elevation."),
        InstallStep(
            label="Confirm it landed",
            command="certutil -store Root",
            note="The certificate should now be listed. Test the connection "
                 "again with 'Validate certificate' switched back on — that, "
                 "not the store listing, is the result that matters."),
    )


def _unknown_windows_steps() -> Tuple[InstallStep, ...]:
    return (
        InstallStep(
            label="Settle whether this machine is domain-joined",
            command="(Get-CimInstance Win32_ComputerSystem).PartOfDomain",
            note="True means joined. ADitor could not tell from this "
                 "machine's environment, and the two answers have different "
                 "remedies, so this is worth thirty seconds."),
        InstallStep(
            label="If it is joined",
            command="gpupdate /target:computer /force && certutil -pulse",
            note="The root is supposed to arrive by autoenrollment. Chase "
                 "that before importing anything by hand — a manual import "
                 "would hide a fault that affects every other domain member."),
        InstallStep(
            label="If it is not joined",
            command='certutil -addstore -f Root "{path}"',
            note="Elevated, and only after confirming the fingerprint above "
                 "against the CA server itself. On an unjoined machine this "
                 "is the correct fix, not a workaround."),
    )


def _macos_steps() -> Tuple[InstallStep, ...]:
    return (
        InstallStep(
            label="Confirm the fingerprint out of band first",
            command='openssl x509 -in "{path}" -noout -fingerprint -sha256',
            note="This prints the fingerprint of the file ADitor exported. It "
                 "has to match both the fingerprint shown above and the one "
                 "read off the CA server itself — on the CA, "
                 "'certutil -store Root'. If you have not checked the second "
                 "of those, stop here."),
        InstallStep(
            label="Trust it system-wide",
            command='sudo security add-trusted-cert -d -r trustRoot '
                    '-k /Library/Keychains/System.keychain "{path}"',
            note="This Mac is not under Group Policy, so there is no "
                 "autoenrollment to repair and a manual import is the correct "
                 "fix. The command needs sudo because it changes trust for "
                 "every user on the machine; run it yourself rather than "
                 "expecting an app to."),
        InstallStep(
            label="Know what the keychain does not cover",
            command="python3 -c \"import ssl; "
                    "print(ssl.get_default_verify_paths())\"",
            note="ADitor's own LDAPS connection goes through Python's "
                 "OpenSSL, and OpenSSL on macOS does not read the login or "
                 "System keychain. So the keychain import above fixes Safari, "
                 "curl and the rest of macOS but may leave this app still "
                 "reporting an untrusted issuer. This command prints the CA "
                 "bundle OpenSSL is actually using; the certificate has to "
                 "reach that file (or its openssl_capath directory) for this "
                 "app to verify the controller."),
        InstallStep(
            label="Or run the audit from the domain-joined Windows machine",
            note="Where the enterprise root is already trusted, or should be. "
                 "That is the shorter path if this Mac is only being used to "
                 "drive the scan."),
    )


def _other_steps() -> Tuple[InstallStep, ...]:
    return (
        InstallStep(
            label="Confirm the fingerprint out of band first",
            command='openssl x509 -in "{path}" -noout -fingerprint -sha256',
            note="It has to match the fingerprint shown above and the one "
                 "read off the CA server itself."),
        InstallStep(
            label="Add it to the system trust store",
            command='sudo cp "{path}" /usr/local/share/ca-certificates/ '
                    '&& sudo update-ca-certificates',
            note="Debian and Ubuntu. On RHEL family: copy to "
                 "/etc/pki/ca-trust/source/anchors/ and run "
                 "'update-ca-trust extract'. Either way it is your command to "
                 "run, not ADitor's."),
    )


def detect_machine(system: Optional[str] = None,
                   environ: Optional[Dict[str, str]] = None
                   ) -> MachineContext:
    """Which situation this machine is in, and the guidance that follows.

    ``system`` and ``environ`` are injectable so the Windows branches are
    covered by tests on any machine — the whole point of this function is the
    platform you are *not* developing on, which is otherwise the one that never
    gets exercised.
    """
    name = (system or sys.platform).lower()
    env = dict(os.environ if environ is None else environ)

    if name.startswith("win"):
        joined, evidence = _windows_join_signal(env)
        if joined is True:
            return MachineContext(
                kind=MACHINE_WINDOWS_JOINED, system="Windows",
                domain_joined=True, evidence=evidence,
                headline="This machine is joined to a domain, so the "
                         "enterprise root should already be trusted — and a "
                         "manual import is the wrong first move.",
                manual_import_is_the_fix=False, steps=_joined_steps())
        if joined is False:
            return MachineContext(
                kind=MACHINE_WINDOWS_STANDALONE, system="Windows",
                domain_joined=False, evidence=evidence,
                headline="This machine is not joined to the domain, so "
                         "importing the CA certificate by hand is the correct "
                         "fix.",
                manual_import_is_the_fix=True,
                steps=_standalone_windows_steps())
        return MachineContext(
            kind=MACHINE_WINDOWS_UNKNOWN, system="Windows",
            domain_joined=None, evidence=evidence,
            headline="ADitor could not tell whether this machine is joined to "
                     "the domain, and the two cases have different fixes.",
            manual_import_is_the_fix=False, steps=_unknown_windows_steps())

    if name == "darwin":
        return MachineContext(
            kind=MACHINE_MACOS, system="macOS", domain_joined=False,
            evidence="this is macOS, which is outside Group Policy "
                     "autoenrollment whether or not it is bound to the "
                     "directory",
            headline="This is a Mac, so there is no autoenrollment to repair "
                     "and importing the CA certificate by hand is the correct "
                     "fix.",
            manual_import_is_the_fix=True, steps=_macos_steps())

    return MachineContext(
        kind=MACHINE_OTHER, system=name or "this platform", domain_joined=False,
        evidence="this is not Windows, so Group Policy autoenrollment does not "
                 "apply",
        headline="This machine is outside Group Policy autoenrollment, so "
                 "importing the CA certificate by hand is the correct fix.",
        manual_import_is_the_fix=True, steps=_other_steps())


# --------------------------------------------------------------------------- #
# The commands, with the exported path filled in
# --------------------------------------------------------------------------- #

#: What stands in for the file path before anything has been exported. Kept
#: obviously unrunnable so a half-copied command fails loudly instead of
#: operating on some other file.
PATH_PLACEHOLDER = "<path to the exported .crt>"


def _obtain_step(context: MachineContext,
                 path: Optional[Path]) -> InstallStep:
    """The step that used to be missing: get the file.

    Every platform's guidance below begins with a command containing
    ``{path}``, and until something has been saved that path is
    :data:`PATH_PLACEHOLDER` — an instruction with a hole in it. So the list now
    opens by saying where the file comes from, and once it exists, where it is.

    On a domain-joined machine the wording deliberately does not present the
    file as the fix. There the missing root means autoenrollment is broken for
    every member of the domain, the steps that follow say so, and the
    certificate's value at that point is that it gives the operator a
    fingerprint to compare against.
    """
    if path:
        return InstallStep(
            label="The CA certificate is saved on this machine",
            note=f"ADitor wrote it to {path}. Writing that file is the whole of "
                 f"what it did: nothing has been added to a trust store, and "
                 f"the commands below are still yours to run. The path is "
                 f"filled into them already.")
    tail = ("On this machine that file is what the commands below operate on."
            if context.manual_import_is_the_fix else
            "On a domain-joined machine the file is not the fix — the steps "
            "below are — but having it gives you a fingerprint to compare "
            "against what the machine actually holds.")
    return InstallStep(
        label="Save the CA certificate to this machine first",
        note="Use 'Download the issuing CA certificate' above. ADitor reads it "
             "from Active Directory, offers it only if that certificate's key "
             "signed the one the controller presented, and writes it to a "
             "file. It does not install it. " + tail)


def install_commands(context: MachineContext,
                     path: Optional[Path] = None) -> Tuple[InstallStep, ...]:
    """The obtain-the-file step, then ``context.steps`` with ``{path}`` resolved.

    Returns text. It does not run anything, and there is no variant of this
    function that does.
    """
    where = str(path) if path else PATH_PLACEHOLDER
    return (_obtain_step(context, path),) + tuple(
        InstallStep(label=step.label,
                    command=step.command.replace("{path}", where),
                    note=step.note)
        for step in context.steps)


# --------------------------------------------------------------------------- #
# Writing the .crt
# --------------------------------------------------------------------------- #

class TrustExportError(Exception):
    """The certificate could not be written. Rendered, never raised at the UI."""


#: A certificate subject is attacker-influenceable text and this one becomes a
#: file name, so the name is *built* from an allow-list rather than sanitised by
#: removing things. Anything outside this set becomes an underscore, which
#: leaves no way to express a separator, a parent directory or an absolute path.
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def export_filename(facts: CertificateFacts) -> str:
    """A safe, recognisable file name for this certificate.

    The fingerprint's first eight hex digits are in the name on purpose: an
    operator who exports the root twice, before and after fixing a CA, ends up
    with two files, and the one thing that tells them apart is the fingerprint.
    """
    stem = _SAFE_NAME.sub("_", facts.label or "ca-certificate").strip("._-")
    stem = (stem or "ca-certificate")[:60]
    return f"{stem}-{facts.fingerprint_hex[:8]}.crt"


def export_ca_certificate(facts: CertificateFacts,
                          directory: Path,
                          filename: Optional[str] = None) -> Path:
    """Write ``facts`` as a PEM ``.crt`` and return the path.

    This is the whole of what ADitor does with a certificate on the operator's
    behalf: it writes a file. It does not add it to a trust store, it does not
    ask the OS to trust it, and it does not run the command that would — see
    this module's docstring and :func:`install_commands`.

    PEM rather than DER because every command in :func:`install_commands`
    accepts PEM, and because a PEM file can be opened in a text editor and
    compared, which a DER blob cannot.
    """
    if not facts.pem:
        raise TrustExportError(
            "That certificate has no encoded body to write, which should not "
            "happen — inspect the chain again.")
    target = Path(directory)
    try:
        target.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(target, 0o700)
        except OSError:
            # A non-POSIX filesystem. The file below is a public certificate,
            # so this is tidiness rather than protection.
            pass
        # basename(): the name is generated here, but if a caller ever passes
        # one through from the page this is what stops it walking out of the
        # directory.
        name = os.path.basename(filename or export_filename(facts))
        if not name or name in (".", ".."):
            raise TrustExportError("That is not a usable file name.")
        path = target / name
        path.write_text(facts.pem, encoding="ascii")
    except TrustExportError:
        raise
    except OSError as exc:
        raise TrustExportError(
            f"Could not write the certificate to {target}: {exc}") from exc
    return path


# --------------------------------------------------------------------------- #
# The whole picture, assembled once
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class TrustReport:
    """Everything the Certificate panel draws, gathered in one pass.

    Assembled here rather than in :mod:`aditor.app.api` for the reason that
    module's docstring gives: the bridge holds state and returns fragments, and
    no domain logic lives in it. Assembled *at all* — rather than the renderer
    calling four functions itself — because the four results have to be
    consistent with each other: a corroboration computed against a different
    chain than the one on screen would be worse than no corroboration.
    """

    chain: ChainInspection
    directory: DirectoryCertificates
    corroboration: Corroboration
    machine: MachineContext
    steps: Tuple[InstallStep, ...] = ()
    #: Where the last export landed, if the operator has exported. Empty means
    #: the commands carry :data:`PATH_PLACEHOLDER` instead of a real path.
    export_path: str = ""

    @property
    def exportable(self) -> Tuple[CertificateFacts, ...]:
        """The CA certificates worth offering as a file, anchor last.

        Only CA certificates: exporting the domain controller's own leaf and
        installing it as a root is a mistake the app should not make available,
        and it would not fix anything anyway.
        """
        return tuple(item for item in self.chain.certificates
                     if item.is_ca or item.self_issued)


def build_trust_report(settings: "object", password: str, *,
                       factory: Optional[object] = None,
                       fetch: Optional[object] = None,
                       system: Optional[str] = None,
                       environ: Optional[Dict[str, str]] = None,
                       export_path: str = "",
                       timeout: float = 10.0) -> TrustReport:
    """Inspect, read the directory, compare, and work out where we are.

    Both injection points exist for the tests, which run with no domain
    controller and no network: ``fetch`` stands in for the TLS handshake and
    ``factory`` for the LDAP manager.
    """
    host, port = parse_ldap_url(getattr(settings, "server", ""))
    chain = inspect_ldaps_chain(host, port, timeout=timeout, fetch=fetch)
    directory = ca_certificates_from_directory(settings, password, factory)
    corroboration = compare_chain_with_directory(chain, directory)
    machine = detect_machine(system, environ)
    path = Path(export_path) if export_path else None
    return TrustReport(chain=chain, directory=directory,
                       corroboration=corroboration, machine=machine,
                       steps=install_commands(machine, path),
                       export_path=str(export_path or ""))


__all__ = [
    "EXPORT_DIRNAME",
    "MACHINE_MACOS",
    "MACHINE_OTHER",
    "MACHINE_WINDOWS_JOINED",
    "MACHINE_WINDOWS_STANDALONE",
    "MACHINE_WINDOWS_UNKNOWN",
    "PATH_PLACEHOLDER",
    "InstallStep",
    "MachineContext",
    "TrustExportError",
    "TrustReport",
    "build_trust_report",
    "detect_machine",
    "export_ca_certificate",
    "export_filename",
    "install_commands",
]
