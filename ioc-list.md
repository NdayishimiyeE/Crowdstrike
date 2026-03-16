# Indicators of Compromise (IOCs)
## APT41 Simulated Intrusion — Host: 5236A4

> All IOCs are from a simulated lab environment and are for educational/portfolio purposes only.

---

## Registry IOCs

| Type | Indicator | Description |
|------|-----------|-------------|
| Registry Key | `\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe` | IFEO hijack key used to intercept Sticky Keys |
| Registry Value | `Debugger` = `C:\windows\system32\cmd.exe` | Redirects sethc.exe to cmd.exe for pre-auth shell access |

**MITRE Technique:** T1546.008 — Accessibility Features

---

## File IOCs

| Type | Indicator | Description |
|------|-----------|-------------|
| Filename | `script.ps1` | PowerShell script downloaded via certutil; executed with `-DumpCreds` (Mimikatz) |
| Filename | `Isass.exe` | Malicious executable masquerading as `lsass.exe` (capital I vs lowercase L) |
| File Path | `C:\\Windows\\System32\\Isass.exe` | Deployment path chosen to blend in with legitimate Windows processes |

**MITRE Techniques:** T1105, T1036.005, T1003.001

---

## Process / Command IOCs

| Type | Indicator | Description |
|------|-----------|-------------|
| Process | `certutil.exe` | LOLBin abused twice: once to download script.ps1, once to stage Isass.exe |
| Command Parameter | `-DumpCreds` | Mimikatz credential dumping parameter passed to script.ps1 |
| Service | `Isass.exe` registered as Windows service | Persistence via service creation (T1543.003) |

---

## Event / Log IOCs

| Type | Indicator | Description |
|------|-----------|-------------|
| Event Name | `UserLogonFailed` | Multiple failed logon attempts indicative of brute force (T1110) |
| Host | `5236A4` | Compromised endpoint |

---

## Detection Recommendations

Based on the IOCs above, the following detections should be in place in any CrowdStrike Falcon deployment:

1. **Alert on IFEO registry key creation/modification** — especially under `Image File Execution Options` for accessibility binaries (`sethc.exe`, `utilman.exe`, `osk.exe`)
2. **Alert on certutil.exe with `-urlcache` or `-decode` flags** — classic LOLBin download indicator
3. **Alert on PowerShell execution with `-DumpCreds`** — Mimikatz signature
4. **Hunt for process names containing `lsass` with unexpected casing** — capital-I masquerading
5. **Alert on new Windows services created from `System32` paths** by non-system processes
6. **Monitor `UserLogonFailed` spikes** — threshold alerting for brute force detection
