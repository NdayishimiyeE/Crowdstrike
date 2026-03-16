# MITRE ATT&CK Navigator Layer

## File
`apt41-crowdstrike-investigation.json`

## How to Load This Layer

1. Go to [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/)
2. Click **Open Existing Layer**
3. Select **Upload from local**
4. Choose `apt41-crowdstrike-investigation.json`

The layer will render with all confirmed techniques highlighted and color-coded by tactic phase.

---

## Techniques Mapped

| Technique ID | Name | Tactic | Color |
|-------------|------|--------|-------|
| T1110 / T1110.001 | Brute Force / Password Guessing | Initial Access | 🟠 Orange |
| T1546 / T1546.008 | Accessibility Features (sethc.exe IFEO) | Persistence | 🔴 Red |
| T1543 / T1543.003 | Windows Service Creation (Isass.exe) | Persistence | 🔴 Red |
| T1105 | Ingress Tool Transfer (certutil LOLBin) | Command & Control | 🟣 Purple |
| T1059 / T1059.001 | PowerShell Execution (script.ps1) | Execution | 🔵 Blue |
| T1003 / T1003.001 | LSASS Memory Dump (Mimikatz -DumpCreds) | Credential Access | 🟡 Yellow |
| T1036 / T1036.005 | Masquerading (Isass.exe → lsass.exe) | Defense Evasion | 🟢 Green |

---

## Color Legend

Each color represents a tactic phase in the attack chain, making it easy to visually trace the progression of the intrusion across the ATT&CK matrix at a glance.

> Each technique entry includes a detailed comment describing exactly what was observed in CrowdStrike Falcon, visible when you hover over or click a technique in the Navigator.
>
> <img width="1440" height="814" alt="ATT CK Navigator SC" src="https://github.com/user-attachments/assets/0ec996dd-5c45-4653-95b3-4cf4792e9a9f" />


