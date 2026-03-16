# APT41 Intrusion Detection & Response
### CrowdStrike Falcon | SIEM Investigation | Endpoint Triage

![CrowdStrike](https://img.shields.io/badge/CrowdStrike-Falcon-red?style=flat-square&logo=crowdstrike)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-blue?style=flat-square)
![Status](https://img.shields.io/badge/Status-Complete-green?style=flat-square)
![Threat Actor](https://img.shields.io/badge/Threat%20Actor-APT41%20%2F%20Wicked%20Panda-critical?style=flat-square)

---

## Overview

This repository documents a full threat detection and incident response investigation of a simulated **APT41 (Wicked Panda / BARIUM)** intrusion conducted in a CrowdStrike Falcon environment. As a SOC analyst, I triaged endpoint detections, hunted through Next-Gen SIEM logs, and identified the full attack chain — from initial persistence through credential access.

APT41 is a Chinese state-sponsored threat group known for dual espionage and financially motivated operations. Their TTPs are extensively documented by [MITRE ATT&CK (G0096)](https://attack.mitre.org/groups/G0096/).

---

## Attack Chain Summary

```
[Persistence]          [Payload Staging]       [Credential Access]       [Lateral Movement Prep]
Registry Hijack    →   certutil download    →   Mimikatz (-DumpCreds)  →   Fake lsass service
T1546.008              T1105                    T1003.001                   T1543.003
sethc.exe → cmd.exe    script.ps1               Credential Dumping          Masquerading
```

---

## Tools & Platform

| Tool | Purpose |
|------|---------|
| **CrowdStrike Falcon** | EDR platform — endpoint detections, host management |
| **Falcon Next-Gen SIEM** | Log management and event search |
| **Falcon Real-Time Response (RTR)** | Live host investigation capability |
| **MITRE ATT&CK** | TTP mapping and threat intelligence |

---

## Investigation Walkthrough

### Phase 1 — Persistence: Registry Accessibility Feature Hijack

**Host:** `5236A4`  
**Detection Tactic:** Persistence  
**MITRE Technique:** [T1546.008 — Event Triggered Execution: Accessibility Features](https://attack.mitre.org/techniques/T1546/008/)

**What was detected:**

CrowdStrike Falcon flagged a modification to the Windows Image File Execution Options (IFEO) registry key associated with `sethc.exe` (Sticky Keys). This is a well-documented APT41 technique for establishing persistent, pre-authentication access via RDP.

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Technique | Registry Run Keys / Startup Folder → Accessibility Features |
| Registry Key Modified | `\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe` |
| Malicious Value Set | `C:\windows\system32\cmd.exe` |

**What this means:**  
By setting `cmd.exe` as the "Debugger" for `sethc.exe` under IFEO, the attacker ensures that pressing Shift 5 times on the Windows login screen launches a SYSTEM-level command prompt — providing persistent, unauthenticated access even after reboots.

---

### Phase 2 — Payload Staging: certutil File Download

**Detection Tool:** Falcon Endpoint Detections  
**MITRE Technique:** [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

**What was detected:**

`certutil.exe`, a legitimate Windows binary, was abused to download a remote file — a classic LOLBin (Living off the Land Binary) technique used extensively by APT41.

| Field | Value |
|-------|-------|
| Tool Abused | `certutil.exe` |
| Downloaded File | `script.ps1` |
| Technique | LOLBin abuse for file ingress |

**SIEM Query Used:**

```
Match any: Any field → contains → script.ps1
AND: ComputerName → is equal to → 5236A4
```

---

### Phase 3 — Credential Access: Mimikatz Execution

**Detection Tactic:** Credential Access  
**MITRE Technique:** [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

**What was detected:**

The downloaded `script.ps1` was executed with the `-DumpCreds` parameter — confirming this as a Mimikatz-based credential harvesting operation targeting LSASS memory.

| Field | Value |
|-------|-------|
| File Executed | `script.ps1` |
| Parameter | `-DumpCreds` |
| Tactic | Credential Access |
| Tool | Mimikatz (via PowerShell wrapper) |

APT41 is confirmed to use Mimikatz for credential dumping as part of lateral movement preparation ([MITRE ATT&CK S0002](https://attack.mitre.org/software/S0002/)).

---

### Phase 4 — Defense Evasion / Persistence: Masquerading as lsass

**Detection Tool:** Falcon Endpoint Detections + Next-Gen SIEM  
**MITRE Technique:** [T1036.005 — Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/) + [T1543.003 — Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)

**What was detected:**

A second `certutil.exe` detection revealed a new file dropped to disk: `Isass.exe` — note the capital "I" (eye) used to impersonate the legitimate `lsass.exe` (el) Windows process. This file was then registered as a Windows service.

| Field | Value |
|-------|-------|
| Malicious File | `Isass.exe` (capital I, not lowercase L) |
| Technique | Process name masquerading |
| Action | Registered as a Windows service |
| Service Path | `C:\\Windows\\System32\\Isass.exe` |

**SIEM Query Used:**

```
Match any: CommandLine → contains → Isass.exe
AND: ComputerName → is equal to → 5236A4
```

---

### Phase 5 — Initial Access Vector: Brute Force

**MITRE Technique:** [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)

**What was detected:**

A SIEM query for `UserLogonFailed` events on host `5236A4` returned multiple failed authentication attempts, consistent with APT41's documented use of brute force attacks against RDP and local administrator accounts.

| Field | Value |
|-------|-------|
| SIEM Event | `#event_simpleName → contains → UserLogonFailed` |
| Host | `5236A4` |
| Technique | Brute Force (T1110) |

**SIEM Query Used:**

```
Match any: #event_simpleName → contains → UserLogonFailed
AND: ComputerName → is equal to → 5236A4
```

---

## MITRE ATT&CK Mapping

| Phase | Tactic | Technique ID | Technique Name |
|-------|--------|-------------|----------------|
| Persistence | Persistence | T1546.008 | Event Triggered Execution: Accessibility Features |
| Payload Delivery | Command & Control | T1105 | Ingress Tool Transfer |
| Credential Theft | Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory |
| Defense Evasion | Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name |
| Service Persistence | Persistence | T1543.003 | Create or Modify System Process: Windows Service |
| Initial Access | Initial Access | T1110 | Brute Force |

---

## Repository Structure

```
apt41-crowdstrike-investigation/
├── README.md                        ← This file (investigation overview)
├── docs/
│   └── apt41-threat-profile.md      ← APT41 threat actor background
├── iocs/
│   └── ioc-list.md                  ← Indicators of Compromise
├── detections/
│   └── detection-notes.md           ← Falcon detection breakdown
├── queries/
│   └── siem-queries.md              ← CrowdStrike Next-Gen SIEM queries used
└── incident-report/
    └── incident-report.md           ← Full formal incident report
```

---

## Key Skills Demonstrated

- **Endpoint Detection Triage** — filtering and interpreting CrowdStrike Falcon alerts
- **SIEM Investigation** — constructing multi-condition event search queries in Falcon Next-Gen SIEM
- **Threat Actor Profiling** — mapping activity to known APT41 TTPs via MITRE ATT&CK
- **IOC Identification** — extracting registry keys, file names, command parameters as indicators
- **Incident Documentation** — formal incident report writing following SOC standards
- **Defense Evasion Recognition** — identifying LOLBin abuse, masquerading, and IFEO injection

---

## References

- [MITRE ATT&CK: APT41 (G0096)](https://attack.mitre.org/groups/G0096/)
- [MITRE ATT&CK: T1546.008 — Accessibility Features](https://attack.mitre.org/techniques/T1546/008/)
- [MITRE ATT&CK: T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK: T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1543.003 — Windows Service](https://attack.mitre.org/techniques/T1543/003/)
- [Mandiant: Double Dragon — APT41 Report (2019)](https://www.mandiant.com/resources/apt41-double-dragon-a-dual-espionage-and-cyber-crime-operation)
- [CrowdStrike Falcon Documentation](https://www.crowdstrike.com/products/falcon-platform/)

---

> **Disclaimer:** This investigation was performed in a controlled lab simulation environment. All host names, usernames, and findings are from a simulated scenario. No real systems or data were involved.
