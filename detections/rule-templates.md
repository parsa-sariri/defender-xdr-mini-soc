# 🎯 Detection Engineering & MITRE ATT&CK Mapping

This section contains production-ready Custom Detection templates designed to convert Advanced Hunting telemetry into actionable high-fidelity alerts.

---

## 1. Suspicious Script Host Spawning (LOLBAS)

* **Rule Name:** `Suspicious Script Host Spawned by Non-Standard Parent`
* **Severity:** `Medium`
* **MITRE ATT&CK Mapping:**
  * **Tactic:** Execution (`TA0002`)
  * **Technique:** Command and Scripting Interpreter: PowerShell (`T1059.001`) / Visual Basic (`T1059.005`)

### KQL Detection Logic:
```kusto
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "cscript.exe", "wscript.exe")
| where InitiatingProcessFileName in~ ("wmiprvse.exe", "sqlservr.exe", "w3wp.exe", "certutil.exe")
| project 
    Timestamp,
    DeviceId,
    DeviceName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AccountName
```

### False Positive Tuning:
* Verify if legitimate management scripts or administrative orchestrators (e.g. SCCM, Intune agents) execute administrative tasks under WMI.
* Whitelist specific trusted command-line arguments using `| where ProcessCommandLine !has ...`.
