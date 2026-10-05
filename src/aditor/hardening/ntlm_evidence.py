"""Who still uses NTLMv1: evidence from exported event logs.

ADitor never reads event logs itself. :data:`EXPORT_SCRIPT` is a read-only
PowerShell script an admin runs (as a member of Event Log Readers on each host);
it writes one CSV, which :func:`read_evidence` parses and :func:`verdict` judges.

Two sources, because NTLMv1 is logged on the machine being signed in to:

* Security event 4624 with ``LmPackageName`` = ``NTLM V1``, on every Windows
  version. ANONYMOUS LOGON (S-1-5-7) is skipped: null sessions say nothing about
  what breaks.
* The NTLM/Operational events 4020-4023 (clients and servers) and 4030-4033
  (domain controllers, domain-wide) on Windows 11 24H2 and Server 2025, where
  the event text's "NTLM Version" reads NTLMv1. Microsoft documents these by
  their displayed labels, so the script reads the message text.

An empty list is never "safe" on its own: every host also reports how far back
its log goes and whether logon auditing was on, and the verdict says which
hosts the evidence covers.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

#: How many days of clean logs the verdict wants before saying "clear".
MIN_DAYS = 14

VERDICT_BLOCKED = "blocked"
VERDICT_NOT_YET = "not-yet"
VERDICT_CLEAR = "clear"

_COLUMNS = ("Host", "Log", "Kind", "EventId", "Time", "Account", "Domain",
            "Client", "ClientIp", "Server", "Process")

EXPORT_SCRIPT = r"""# ADitor: NTLMv1 evidence export. READ-ONLY: it reads event logs and writes
# one CSV file. It changes nothing on any machine.
#
# Run it as an account in "Event Log Readers" on each host (on domain
# controllers, the domain's BUILTIN\Event Log Readers group); Domain Admin is
# not needed. NTLMv1 is logged on the server being signed in to, so list your
# domain controllers AND your member servers. Then run:
#   aditor-cli ntlm-check ntlmv1-evidence.csv
$Hosts = @($env:COMPUTERNAME)   # e.g. @('DC01','DC02','FS01','APP01')
$Days  = 14
$Out   = 'ntlmv1-evidence.csv'

$since = (Get-Date).AddDays(-$Days)
$ntlmIds = 4020,4021,4022,4023,4030,4031,4032,4033
$op = 'Microsoft-Windows-NTLM/Operational'

function Row($h, $kind, $e, $f) {
  [pscustomobject]@{
    Host = $h; Log = $(if ($e) { $e.LogName } else { '' }); Kind = $kind
    EventId = $(if ($e) { $e.Id } else { '' })
    Time = $(if ($e) { $e.TimeCreated.ToUniversalTime().ToString('o') }
             else { (Get-Date).ToUniversalTime().ToString('o') })
    Account = $f.Account; Domain = $f.Domain; Client = $f.Client
    ClientIp = $f.Ip; Server = $f.Server; Process = $f.Process
  }
}
function Field($text, $label) {
  if ($text -match "(?m)^\s*$([regex]::Escape($label)):\s*(.+?)\s*$") { $Matches[1] }
}

$rows = foreach ($h in $Hosts) {
  Row $h 'exported' $null @{}
  try {
    Row $h 'log-oldest' (Get-WinEvent -ComputerName $h -LogName Security -MaxEvents 1 -Oldest -ErrorAction Stop) @{}
    $logon = Get-WinEvent -ComputerName $h -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($logon) { Row $h 'last-logon' $logon @{} }
    Get-WinEvent -ComputerName $h -LogName Security -ErrorAction SilentlyContinue `
      -FilterXPath "*[System[EventID=4624]] and *[EventData[Data[@Name='LmPackageName']='NTLM V1']]" |
      Where-Object { $_.TimeCreated -ge $since } | ForEach-Object {
        $d = @{}; foreach ($x in ([xml]$_.ToXml()).Event.EventData.Data) { $d[$x.Name] = $x.'#text' }
        if ($d['TargetUserSid'] -ne 'S-1-5-7') {
          Row $h 'ntlmv1' $_ @{Account=$d['TargetUserName']; Domain=$d['TargetDomainName'];
            Client=$d['WorkstationName']; Ip=$d['IpAddress']; Server=$h; Process=$d['ProcessName']}
        }
      }
  } catch {
    Row $h 'error' $null @{Account = "Security log: $($_.Exception.Message)"}
  }
  # Windows 11 24H2 / Server 2025 only; older hosts have no such log.
  $last = Get-WinEvent -ComputerName $h -FilterHashtable @{LogName=$op; Id=$ntlmIds} -MaxEvents 1 -ErrorAction SilentlyContinue
  if ($last) {
    Row $h 'ntlm-log-last' $last @{}
    Get-WinEvent -ComputerName $h -FilterHashtable @{LogName=$op; Id=$ntlmIds; StartTime=$since} -ErrorAction SilentlyContinue |
      Where-Object { $_.Message -match 'NTLM Version:\s*NTLMv1\b' } | ForEach-Object {
        $m = $_.Message
        $acct = (Field $m 'Client Username'), (Field $m 'Username'), (Field $m 'Client Name') | Where-Object { $_ } | Select-Object -First 1
        $dom  = (Field $m 'Client Domain'), (Field $m 'Domain') | Where-Object { $_ } | Select-Object -First 1
        $cli  = (Field $m 'Client Machine Name'), (Field $m 'Client Machine'), (Field $m 'Hostname') | Where-Object { $_ } | Select-Object -First 1
        $srv  = (Field $m 'Server Name'), (Field $m 'Target Machine') | Where-Object { $_ } | Select-Object -First 1
        Row $h 'ntlmv1' $_ @{Account=$acct; Domain=$dom; Client=$cli;
          Ip=(Field $m 'Client IP'); Server=$(if ($srv) { $srv } else { $h }); Process=(Field $m 'Process Name')}
      }
  }
}
$rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $Out
Write-Host "Wrote $Out ($(@($rows).Count) rows). It holds account and machine names: treat it as sensitive."
"""


class EvidenceError(ValueError):
    """An evidence file could not be read as an ADitor NTLMv1 export."""


def _time(text: str) -> Optional[datetime]:
    try:
        value = datetime.fromisoformat(str(text).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def read_evidence(paths: Iterable[Any]) -> List[Dict[str, str]]:
    """Every row from one or more exports of :data:`EXPORT_SCRIPT`."""
    rows: List[Dict[str, str]] = []
    for path in paths:
        try:
            with open(Path(path), encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                missing = [c for c in ("Host", "Kind", "Time")
                           if c not in (reader.fieldnames or [])]
                if missing:
                    raise EvidenceError(
                        f"{path} isn't an ADitor NTLMv1 export: it has no "
                        f"{', '.join(missing)} column. Make one with "
                        f"'aditor-cli ntlm-script'.")
                rows.extend({c: (row.get(c) or "").strip() for c in _COLUMNS}
                            for row in reader)
        except OSError as exc:
            raise EvidenceError(f"could not read {path}: {exc}") from exc
    return rows


def verdict(rows: List[Dict[str, str]], min_days: int = MIN_DAYS) -> Dict[str, Any]:
    """Who uses NTLMv1, what each host's logs cover, and whether it's clear."""
    hosts: Dict[str, Dict[str, Any]] = {}
    sources: Dict[tuple, Dict[str, Any]] = {}
    for row in rows:
        name = row["Host"] or "?"
        host = hosts.setdefault(name, {"host": name, "exported": None,
                                       "oldest": None, "logon_auditing": False,
                                       "ntlm_log": False, "error": None})
        kind, when = row["Kind"], _time(row["Time"])
        if kind == "exported":
            host["exported"] = when
        elif kind == "log-oldest":
            host["oldest"] = when
        elif kind == "last-logon":
            host["logon_auditing"] = True
        elif kind == "ntlm-log-last":
            host["ntlm_log"] = True
        elif kind == "error":
            host["error"] = row["Account"] or "the log couldn't be read"
        elif kind == "ntlmv1":
            key = (row["Account"].lower(), row["Domain"].lower(),
                   row["Client"].lower(), (row["Server"] or name).lower())
            source = sources.setdefault(key, {
                "account": row["Account"], "domain": row["Domain"],
                "client": row["Client"], "client_ip": row["ClientIp"],
                "server": row["Server"] or name, "process": row["Process"],
                "count": 0, "first": None, "last": None,
                "via": "Security 4624" if row["EventId"] == "4624"
                else "NTLM log"})
            source["count"] += 1
            if when:
                source["first"] = min(filter(None, [source["first"], when]))
                source["last"] = max(filter(None, [source["last"], when]))

    reasons: List[str] = []
    out_hosts = []
    for host in sorted(hosts.values(), key=lambda h: h["host"].lower()):
        days = None
        if host["exported"] and host["oldest"]:
            days = max(0.0, (host["exported"] - host["oldest"]).total_seconds()
                       / 86400)
        host["days_covered"] = round(min(days, min_days), 1) if days is not \
            None else None
        if host["error"]:
            reasons.append(f"{host['host']}: {host['error']}")
        elif not host["logon_auditing"]:
            reasons.append(f"{host['host']}: no logon events (4624) at all, so "
                           f"logon auditing looks off and NTLMv1 wouldn't show")
        elif days is None or days < min_days:
            shown = "unknown" if days is None else f"{days:.1f} days"
            reasons.append(f"{host['host']}: its Security log only goes back "
                           f"{shown}; {min_days} are needed. Raise the log size "
                           f"or export again later")
        out_hosts.append({k: (v.isoformat() if isinstance(v, datetime) else v)
                          for k, v in host.items()})

    found = sorted(sources.values(), key=lambda s: (-s["count"], s["account"]))
    for source in found:
        for key in ("first", "last"):
            if isinstance(source[key], datetime):
                source[key] = source[key].isoformat()

    if not hosts:
        state, summary = VERDICT_NOT_YET, "The export has no hosts in it."
    elif found:
        state = VERDICT_BLOCKED
        summary = (f"{len(found)} account and client pair(s) still use NTLMv1. "
                   f"Fix them before raising domain controllers to 5.")
    elif reasons:
        state = VERDICT_NOT_YET
        summary = ("No NTLMv1 seen, but the evidence isn't enough to rely on "
                   "yet: " + "; ".join(reasons) + ".")
    else:
        state = VERDICT_CLEAR
        summary = (f"No NTLMv1 seen on these {len(hosts)} host(s) in "
                   f"{min_days} days, with logon auditing on. This covers only "
                   f"the hosts exported: NTLMv1 is logged on the server being "
                   f"signed in to, so every server needs to be in the export.")
    return {"verdict": state, "summary": summary, "min_days": min_days,
            "hosts": out_hosts, "sources": found, "reasons": reasons}
