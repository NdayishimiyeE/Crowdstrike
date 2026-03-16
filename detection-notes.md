# CrowdStrike Falcon — Detection Notes
## APT41 Investigation | Host: 5236A4

This document captures the triage methodology and notes for each Falcon endpoint detection reviewed during the investigation.

---

## How to Triage Detections in Falcon

**Navigation Path:**  
`Falcon Console → Endpoint Security → Detections → Filter by Hostname: 5236A4`

**Key fields to review for each detection:**
- **Tactic** — MITRE ATT&CK tactic classification
- **Technique** — Specific MITRE technique
- **Process Tree** — Parent/child process relationships revealing execution chain
- **Command Line** — The exact command executed
- **File Path** — Where the activity occurred on disk
- **Timestamp** — Sequence events to build the attack timeline

---

## Detection 1 — IFEO Registry Modification (Persistence)

| Field | Value |
|-------|-------|
| **Tactic** | Persistence |
| **Technique** | Registry Run Keys / Startup Folder |
| **MITRE ID** | T1546.008 |
| **Registry Key** | `\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe` |
| **Value Written** | `C:\windows\system32\cmd.exe` |
| **Severity** | High |

**Analyst Notes:**  
This detection should be treated as critical. IFEO modification of an accessibility binary is a known, reliable indicator of adversary persistence. The attacker is establishing a backdoor that survives reboots and is triggerable pre-authentication via the Windows login screen (RDP). Combined with evidence of brute force, this suggests the attacker was attempting to secure persistent RDP access even after credentials rotate.

**Response Actions Recommended:**
- [ ] Isolate host immediately
- [ ] Audit all IFEO registry keys on affected host
- [ ] Review RDP access logs for unauthorized access attempts
- [ ] Restore the IFEO key by deleting the malicious `Debugger` value

---

## Detection 2 — certutil.exe Ingress Tool Transfer (First Instance)

| Field | Value |
|-------|-------|
| **Tactic** | Command and Control |
| **Technique** | Ingress Tool Transfer |
| **MITRE ID** | T1105 |
| **Tool Abused** | `certutil.exe` (LOLBin) |
| **File Downloaded** | `script.ps1` |
| **Severity** | High |

**Analyst Notes:**  
`certutil.exe` is a legitimate Microsoft binary used for certificate management. Its use to download remote files is a classic LOLBin technique — it bypasses application whitelisting policies that focus on binary reputation rather than behavior. The fact that the downloaded file is a `.ps1` (PowerShell script) suggests staged execution is imminent. Correlate immediately with SIEM.

**Response Actions Recommended:**
- [ ] Locate `script.ps1` on disk and collect for forensic analysis
- [ ] Block outbound certutil traffic at perimeter if not required
- [ ] Search SIEM for all certutil executions across the environment

---

## Detection 3 — PowerShell Credential Dumping (Credential Access)

| Field | Value |
|-------|-------|
| **Tactic** | Credential Access |
| **Technique** | OS Credential Dumping: LSASS Memory |
| **MITRE ID** | T1003.001 |
| **File** | `script.ps1` |
| **Parameter** | `-DumpCreds` |
| **Tool** | Mimikatz (via PowerShell) |
| **Severity** | Critical |

**Analyst Notes:**  
`-DumpCreds` is an unmistakable Mimikatz indicator. This parameter invokes credential harvesting from LSASS process memory, extracting NTLM hashes and potentially plaintext credentials for all users with active sessions on the host. If this completed successfully, assume all credentials on this system are compromised. Escalate to Tier 2/3 and notify identity team.

**Response Actions Recommended:**
- [ ] Assume all credentials on `5236A4` are compromised — initiate password reset for all affected accounts
- [ ] Review for subsequent lateral movement using harvested credentials
- [ ] Enable Credential Guard on endpoint if not already active

---

## Detection 4 — certutil.exe Drop of Masqueraded Executable (Second Instance)

| Field | Value |
|-------|-------|
| **Tactic** | Defense Evasion / Persistence |
| **Technique** | Masquerading + Create Windows Service |
| **MITRE ID** | T1036.005, T1543.003 |
| **File Dropped** | `Isass.exe` (capital I, not lowercase L) |
| **Deployment Path** | `C:\Windows\System32\Isass.exe` |
| **Registered As** | Windows Service |
| **Severity** | Critical |

**Analyst Notes:**  
The naming of `Isass.exe` with a capital "I" to impersonate `lsass.exe` is a sophisticated defense evasion move — many log viewers and analysts will overlook the character substitution at a glance. Placing it in `System32` and registering it as a service makes it appear legitimate at the process level. This provides the attacker with a persistent execution mechanism that survives reboots.

**Response Actions Recommended:**
- [ ] Remove the malicious Windows service immediately
- [ ] Delete `C:\Windows\System32\Isass.exe`
- [ ] Audit all services on host for suspicious entries
- [ ] Hash the file and submit to threat intel for further analysis

---

## Triage Priority Summary

| Detection | Priority | Immediate Action |
|-----------|----------|-----------------|
| IFEO Registry Hijack | 🔴 High | Isolate host, audit IFEO keys |
| certutil download (script.ps1) | 🔴 High | Collect file, search SIEM |
| Mimikatz -DumpCreds | 🔴 Critical | Reset all credentials, escalate |
| Isass.exe service creation | 🔴 Critical | Remove service, delete file |
