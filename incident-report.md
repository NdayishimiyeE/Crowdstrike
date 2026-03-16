# Incident Report
## IR-2024-001 | APT41 Intrusion — Host 5236A4

---

| Field | Detail |
|-------|--------|
| **Incident ID** | IR-2024-001 |
| **Classification** | Critical — Nation-State Threat Actor |
| **Threat Actor** | APT41 (Wicked Panda / BARIUM) |
| **Affected Host** | 5236A4 |
| **Detection Platform** | CrowdStrike Falcon |
| **Analyst** | SOC — Tier 1 Initial Triage |
| **Status** | Contained |

---

## Executive Summary

A simulated APT41 intrusion was detected on endpoint `5236A4` via CrowdStrike Falcon endpoint detections and Next-Gen SIEM analysis. The attacker employed a multi-stage attack chain consistent with publicly documented APT41 tactics: initial access via brute force, persistence via Windows registry accessibility feature hijacking, payload staging using a legitimate Windows binary (certutil.exe), credential harvesting via Mimikatz, and persistent service installation using a masqueraded process name.

All detections were triaged and correlated. The full attack chain was reconstructed and IOCs were identified for defensive response.

---

## Timeline of Events

| Stage | Activity | MITRE ID | Detection Source |
|-------|----------|----------|-----------------|
| 1 | Brute force logon failures against host `5236A4` | T1110 | Next-Gen SIEM — UserLogonFailed |
| 2 | IFEO registry key modified: `sethc.exe` → `cmd.exe` | T1546.008 | Falcon Endpoint Detection |
| 3 | `certutil.exe` used to download `script.ps1` | T1105 | Falcon Endpoint Detection |
| 4 | `script.ps1` executed with `-DumpCreds` parameter | T1003.001 | Next-Gen SIEM Event Search |
| 5 | `certutil.exe` used to drop `Isass.exe` to `System32` | T1105 | Falcon Endpoint Detection |
| 6 | `Isass.exe` registered as a Windows service | T1543.003 | Next-Gen SIEM Event Search |

---

## Detailed Findings

### Finding 1: Persistence via IFEO Accessibility Feature Hijack (T1546.008)

The attacker modified the Windows Image File Execution Options registry key to intercept execution of `sethc.exe` (Sticky Keys). By setting `C:\windows\system32\cmd.exe` as the "Debugger" value, any invocation of Sticky Keys — including from the Windows login screen before authentication — will launch a SYSTEM-level command shell.

- **Registry Key:** `\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe`
- **Value:** `Debugger` = `C:\windows\system32\cmd.exe`
- **Impact:** Pre-authentication persistent SYSTEM shell access via RDP

### Finding 2: Payload Staging via certutil LOLBin Abuse (T1105)

`certutil.exe`, a legitimate Windows Certificate Services utility, was abused to download `script.ps1` from a remote source. This is a well-documented technique for bypassing application control policies by leveraging a trusted, signed binary.

- **Binary Abused:** `certutil.exe`
- **File Staged:** `script.ps1`

### Finding 3: Credential Harvesting via Mimikatz (T1003.001)

The staged PowerShell script was executed with the `-DumpCreds` parameter, indicative of a Mimikatz credential dumping operation targeting LSASS process memory. This is designed to extract plaintext passwords and NTLM hashes for all users with active sessions.

- **Command:** `script.ps1 -DumpCreds`
- **Tactic:** Credential Access
- **Assumption:** All credentials on `5236A4` should be treated as compromised

### Finding 4: Masqueraded Process Persistence via Windows Service (T1036.005 + T1543.003)

A second `certutil.exe` execution dropped `Isass.exe` — a filename designed to visually impersonate `lsass.exe` by substituting a capital "I" for a lowercase "L". The file was placed in `C:\Windows\System32\` and registered as a Windows service, providing persistent execution on every system boot.

- **Malicious File:** `Isass.exe` (capital I)
- **Service Path:** `C:\\Windows\\System32\\Isass.exe`
- **Impact:** Persistent backdoor execution with service-level privileges

### Finding 5: Initial Access via Brute Force (T1110)

SIEM analysis of `UserLogonFailed` events on host `5236A4` revealed multiple failed authentication attempts, consistent with an automated brute force attack against local accounts. This is the probable initial access vector that preceded all subsequent attacker activity.

- **Event:** `UserLogonFailed` — multiple occurrences
- **Target:** Built-in / local accounts on `5236A4`

---

## Attack Chain Diagram

```
[Brute Force]
     │ T1110 — Password spraying against local accounts
     ↓
[Persistence Established]
     │ T1546.008 — sethc.exe IFEO → cmd.exe
     │ (Pre-auth RDP shell backdoor)
     ↓
[Payload Staging]
     │ T1105 — certutil.exe downloads script.ps1
     ↓
[Credential Harvesting]
     │ T1003.001 — script.ps1 -DumpCreds (Mimikatz)
     │ (LSASS memory dump — all credentials compromised)
     ↓
[Persistent Backdoor]
     │ T1105 — certutil.exe drops Isass.exe
     │ T1036.005 — Masquerading as lsass.exe
     └ T1543.003 — Registered as Windows service
```

---

## IOC Summary

| Type | Indicator |
|------|-----------|
| Registry Key | `...Image File Execution Options\sethc.exe` → Debugger = `cmd.exe` |
| Filename | `script.ps1` |
| Filename | `Isass.exe` (capital I) |
| File Path | `C:\Windows\System32\Isass.exe` |
| Command | `script.ps1 -DumpCreds` |
| Event | `UserLogonFailed` (multiple) |
| Process | `certutil.exe` (network activity) |

---

## Recommended Remediation Actions

1. **Isolate host `5236A4`** from the network immediately
2. **Delete the malicious IFEO registry key** under `Image File Execution Options\sethc.exe`
3. **Stop and remove the `Isass.exe` Windows service**
4. **Delete `C:\Windows\System32\Isass.exe`** from disk
5. **Reset all credentials** for users with sessions on `5236A4` — assume Mimikatz succeeded
6. **Review lateral movement** — hunt for use of harvested credentials across the environment
7. **Audit all IFEO keys** on the affected host and across the environment
8. **Block certutil.exe network access** at the host firewall level if not required
9. **Enable Credential Guard** to prevent future LSASS memory attacks
10. **Conduct threat hunt** for `UserLogonFailed` spikes on other hosts — determine scope of brute force campaign

---

## Lessons Learned

| Observation | Recommendation |
|-------------|----------------|
| certutil LOLBin abuse was the primary delivery mechanism | Alert on certutil.exe with `-urlcache` or `-f` flags alongside outbound network connections |
| Capital-I/lowercase-L masquerading bypassed initial visual triage | Implement hash-based process verification rather than name-based detection |
| IFEO persistence was established before credential theft | Treat IFEO modifications as automatic escalation events |
| Multiple certutil detections preceded final payload — alerts existed | Faster triage of initial LOLBin alert would have interrupted the chain |

---

> **Disclaimer:** This incident report documents findings from a controlled simulation environment. All host names, usernames, and events are simulated. No real systems, data, or users were affected.
