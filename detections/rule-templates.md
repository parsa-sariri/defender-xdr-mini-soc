# 🎯 Custom Detection Rule Templates & MITRE ATT&CK Mapping

This reference defines production-grade detection templates engineered and tested within the Enterprise Defender XDR Mini-SOC environment.

---

## 📋 Rule Template 01: Suspicious Native Reconnaissance Burst (LOLBAS Discovery)

* **Rule Title:** `Suspicious Host Discovery via Native Windows Utilities`
* **Target Table:** `DeviceProcessEvents`
* **Severity:** Medium
* **MITRE ATT&CK:**
  - `TA0007` (Discovery)
  - `T1033` (System Owner/User Discovery)
  - `T1082` (System Information Discovery)
  - `T1016` (System Network Configuration Discovery)
  - `T1057` (Process Discovery)

### Detection Logic (KQL):
```kusto
DeviceProcessEvents
| where FileName in~ ("whoami.exe", "hostname.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe", "quser.exe")
| summarize 
    ReconCommandCount = dcount(FileName), 
    CommandsUsed = make_set(ProcessCommandLine),
    ToolsUsed = make_set(FileName),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    ReportId = any(ReportId)
    by DeviceId, DeviceName, AccountName, bin(Timestamp, 1h)
| where ReconCommandCount >= 3
| project Timestamp, DeviceId, ReportId, DeviceName, AccountName, ReconCommandCount, CommandsUsed, ToolsUsed, FirstSeen, LastSeen
```

---

## 📋 Rule Template 02: Correlated Office Sub-Process with Network Egress

* **Rule Title:** `Office Binary Child Process with Corroborating External Socket`
* **Target Tables:** `DeviceProcessEvents` JOIN `DeviceNetworkEvents`
* **Severity:** High
* **MITRE ATT&CK:**
  - `TA0001` (Initial Access) -> `T1566` (Phishing)
  - `TA0002` (Execution) -> `T1204.002` (Malicious File), `T1059.001` (PowerShell)
  - `TA0011` (Command and Control) -> `T1071.001` (Web Protocols)

### Detection Logic (KQL):
```kusto
let Lookback = 1h;
let Shells = dynamic(["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"]);
let Parents = dynamic(["winword.exe", "excel.exe", "powerpnt.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where InitiatingProcessFileName in~ (Parents)
| where FileName in~ (Shells)
| project ProcessTime = Timestamp, DeviceId, DeviceName, AccountName, Parent = InitiatingProcessFileName, Child = FileName, ProcessCommandLine, ProcessId
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp >= ago(Lookback)
    | where ActionType == "ConnectionSuccess" and not(ipv4_is_private(RemoteIP))
    | project NetworkTime = Timestamp, DeviceId, InitiatingProcessId = ProcessId, RemoteIP, RemotePort
) on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| where abs(datetime_diff('second', NetworkTime, ProcessTime)) <= 60
| project ProcessTime, DeviceName, AccountName, Parent, Child, ProcessCommandLine, RemoteIP, RemotePort
```

---

## 📋 Rule Template 03: Brute-Force & Credential Spraying Pipeline

* **Rule Title:** `Anomalous Authentication Failure Burst Followed by Successful Logon`
* **Target Table:** `DeviceLogonEvents`
* **Severity:** High
* **MITRE ATT&CK:**
  - `TA0006` (Credential Access) -> `T1110.001` (Password Guessing), `T1110.003` (Password Spraying)
  - `TA0008` (Lateral Movement) -> `T1078` (Valid Accounts)

### Detection Logic (KQL):
```kusto
DeviceLogonEvents
| where Timestamp >= ago(12h)
| where ActionType in ("LogonFailed", "LogonSuccess")
| summarize 
    FailedAttempts = countif(ActionType == "LogonFailed"),
    SuccessfulLogons = countif(ActionType == "LogonSuccess"),
    TargetedAccounts = dcountif(AccountName, ActionType == "LogonFailed"),
    ReportId = any(ReportId)
    by RemoteIP, DeviceName, bin(Timestamp, 30m)
| where FailedAttempts >= 10 and SuccessfulLogons >= 1
| project Timestamp, RemoteIP, DeviceName, FailedAttempts, SuccessfulLogons, TargetedAccounts, ReportId
| sort by FailedAttempts desc
```
