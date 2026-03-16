# CrowdStrike Next-Gen SIEM — Event Search Queries
## APT41 Investigation | Host: 5236A4

These queries were constructed and executed in **CrowdStrike Falcon Next-Gen SIEM → Log Management → Event Search** during the APT41 intrusion investigation.

---

## Query 1 — Hunt for PowerShell Script Execution

**Objective:** Find log entries related to the execution of the downloaded `script.ps1` file.

**Query Logic:**

```
ROW 1 (Match any):
  Any field → contains → script.ps1

ROW 2 (AND group):
  ComputerName → is equal to → 5236A4
```

**What to look for in results:**
- The specific command line that invoked `script.ps1`
- The parameter used: `-DumpCreds`
- Tactic classified as: **Credential Access**

**Key Finding:** `script.ps1 -DumpCreds` — Mimikatz-based credential harvesting targeting LSASS memory.

---

## Query 2 — Hunt for Masqueraded lsass Activity

**Objective:** Find command line activity involving the malicious `Isass.exe` (capital I).

**Query Logic:**

```
ROW 1 (Match any):
  CommandLine → contains → Isass.exe

ROW 2 (AND group):
  ComputerName → is equal to → 5236A4
```

> **Note:** Do NOT use the full path in the filter. Search for `Isass.exe` only to ensure all invocations are captured regardless of working directory.

**What to look for in results:**
- Service creation command registering `Isass.exe`
- Service path: `C:\\Windows\\System32\\Isass.exe`
- Tactic: **Defense Evasion / Persistence**
- Technique: **T1543.003 — Create or Modify System Process: Windows Service** + **T1036.005 — Masquerading**

---

## Query 3 — Brute Force Detection

**Objective:** Identify failed logon attempts indicative of a brute force attack against host `5236A4`.

**Query Logic:**

```
ROW 1 (Match any):
  #event_simpleName → contains → UserLogonFailed

ROW 2 (AND group):
  ComputerName → is equal to → 5236A4
```

**What to look for in results:**
- High volume of `UserLogonFailed` events within a short time window
- Username targeted (typically `Administrator` or built-in accounts in APT41 campaigns)
- Consistent source — suggests automated brute force tool, not user error
- Tactic: **Initial Access** — T1110 Brute Force

---

## Query Construction Notes

### CrowdStrike Next-Gen SIEM — Key Tips

| Tip | Detail |
|-----|--------|
| Match any vs Match all | "Match any" = OR logic within a row; rows connected by AND groups = AND logic between them |
| `#event_simpleName` | CrowdStrike-specific field for simplified event classification — useful for hunting by event category |
| `ComputerName` filter | Always scope to a specific host when investigating a known endpoint to reduce noise |
| Case sensitivity | Field values may be case-sensitive depending on the field type — test both cases when uncertain |
| CommandLine field | More reliable than `Any field` for process execution hunting; reduces false positives |

---

## Recommended Follow-Up Queries

These additional queries would be logical next steps in a real investigation:

```
# Hunt for all certutil network activity
CommandLine → contains → certutil
AND ComputerName → is equal to → 5236A4

# Hunt for all PowerShell execution with encoded or suspicious parameters  
CommandLine → contains → powershell
AND CommandLine → contains → -enc OR -nop OR -exec bypass
AND ComputerName → is equal to → 5236A4

# Hunt for new service creation events
#event_simpleName → contains → ServiceInstall
AND ComputerName → is equal to → 5236A4

# Hunt for IFEO registry writes
RegObjectName → contains → Image File Execution Options
AND ComputerName → is equal to → 5236A4
```
