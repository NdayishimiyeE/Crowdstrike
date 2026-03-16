# Threat Actor Profile: APT41 (Wicked Panda / BARIUM)

## Overview

| Attribute | Detail |
|-----------|--------|
| **Also Known As** | Wicked Panda, BARIUM, Double Dragon, Brass Typhoon |
| **Origin** | China (assessed as state-sponsored) |
| **Active Since** | At least 2012 |
| **MITRE ATT&CK ID** | [G0096](https://attack.mitre.org/groups/G0096/) |
| **Motivation** | Dual: State-sponsored espionage + financially motivated cybercrime |
| **Targeted Sectors** | Healthcare, Telecom, Technology, Finance, Gaming, Government |
| **Targeted Regions** | Global — confirmed operations in 14+ countries |

---

## What Makes APT41 Unique

APT41 is one of the rare threat actors that operates in two distinct modes:

1. **Espionage Mode** — Targets strategic industries on behalf of the Chinese government to steal intellectual property, PII, and sensitive data.
2. **Financial Crime Mode** — Targets video game companies and financial institutions for direct monetary gain (virtual currency theft, ransomware).

This dual nature has led to the "Double Dragon" nickname from Mandiant's original 2019 report.

---

## Key TTPs (Tactics, Techniques & Procedures)

### Initial Access
| Technique | ID | Description |
|-----------|-----|-------------|
| Spear Phishing | T1566 | Targeted phishing emails with malicious attachments or links |
| Exploit Public-Facing Applications | T1190 | Exploitation of web vulnerabilities (Log4j, Confluence, Apache Struts) |
| Supply Chain Compromise | T1195 | Trojanizing legitimate software updates |
| Brute Force | T1110 | Credential stuffing and password spraying against RDP, VPN |

### Execution
| Technique | ID | Description |
|-----------|-----|-------------|
| PowerShell | T1059.001 | Heavy use of PowerShell for execution and staging |
| Windows Command Shell | T1059.003 | cmd.exe usage, especially after accessibility feature hijack |
| Certutil LOLBin Abuse | T1105 | Using certutil.exe to download payloads from remote sources |

### Persistence
| Technique | ID | Description |
|-----------|-----|-------------|
| Registry Run Keys | T1547.001 | Ensuring malware survives reboots via startup registry keys |
| Accessibility Feature Hijack | T1546.008 | IFEO injection on sethc.exe / utilman.exe for pre-auth shell access |
| Create Windows Service | T1543.003 | Registering malicious executables as Windows services |
| Scheduled Tasks | T1053.005 | Configuring malware to execute on schedule |

### Credential Access
| Technique | ID | Description |
|-----------|-----|-------------|
| LSASS Memory Dumping | T1003.001 | Using Mimikatz to extract credentials from LSASS process memory |
| SAM Database Extraction | T1003.002 | reg save to extract SAM and SYSTEM hives for offline cracking |

### Defense Evasion
| Technique | ID | Description |
|-----------|-----|-------------|
| Masquerading | T1036 | Naming malicious files to mimic system processes (e.g., `Isass.exe` vs `lsass.exe`) |
| File Deletion | T1070.004 | Covering tracks by deleting malware after use |
| Disable Security Tools | T1562 | Attempting to disable or bypass AV/EDR products |

---

## How This Investigation Maps to APT41 TTPs

Every detection and finding in this investigation maps directly to publicly documented APT41 behavior:

```
sethc.exe IFEO hijack          →  T1546.008  (confirmed APT41 TTP)
certutil.exe download          →  T1105      (confirmed APT41 TTP)  
Mimikatz -DumpCreds            →  T1003.001  (confirmed APT41 TTP)
Isass.exe masquerading         →  T1036.005  (confirmed APT41 TTP)
Fake Windows service           →  T1543.003  (confirmed APT41 TTP)
Brute force (UserLogonFailed)  →  T1110      (confirmed APT41 TTP)
```

---

## References & Further Reading

- [MITRE ATT&CK: APT41 Group Page](https://attack.mitre.org/groups/G0096/)
- [Mandiant: Double Dragon — APT41 (2019)](https://www.mandiant.com/resources/apt41-double-dragon-a-dual-espionage-and-cyber-crime-operation)
- [Mandiant: APT41 Targeting US State Governments (2022)](https://www.mandiant.com/resources/apt41-us-state-governments)
- [CISA Advisory on APT41](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [DOJ Indictment of APT41 Members (2020)](https://www.justice.gov/opa/pr/seven-international-cyber-defendants-including-apt41-actors-charged-connection-computer)
