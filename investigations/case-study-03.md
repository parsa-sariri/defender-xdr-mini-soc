# 🔬 Case Study 03: Behavioral Lineage Scoring & Corroborating Telemetry

## 1. Executive Summary & Problem Formulation
* **Challenge:** In enterprise environments, commodity productivity tools (e.g., `winword.exe`, `excel.exe`) and administrative script hosts frequently spawn child processes. Traditional binary detections (e.g., alerting purely on `winword.exe -> powershell.exe`) trigger intolerable false-positive rates when automated reporting pipelines or legitimate macros exist in the enterprise baseline.
* **The Pitfall of Premature Allowlists:** Suppressing alerts via broad directory or path-based allowlists creates fatal security blind spots, enabling adversaries to evade detection using Living-off-the-Land Binaries (LOLBins) or hijacked script paths.
* **Core Hypothesis:** Rather than relying on fragile static exclusions, high-fidelity detection engineering requires **lineage scoring** coupled with **corroborating telemetry** (network outbound connections, command-line entropy, and file write indicators) before elevating an event to a high-severity alert.

---

## 2. Architectural Methodology: The Multi-Stage Verification Funnel

Instead of a single-table match, this scenario implements a 3-tier correlation model:

```
[ Tier 1: Process Lineage ]
   Office/Admin binary spawns command shell or script host
            │
            ▼
[ Tier 2: Behavioral Risk Scoring ]
   Evaluate CLI flags: encoded scripts (-enc), hidden windows (-w hidden), execution bypass (-ep bypass)
            │
            ▼
[ Tier 3: Corroborating Telemetry Correlation ]
   Cross-table join with DeviceNetworkEvents (External C2 attempt) OR DeviceFileEvents (Payload staging)
            │
            ▼
[ Outcome: High-Confidence Actionable Incident ]
```

---

## 3. KQL Detection Logic: Correlated Lineage & Network Telemetry

```kusto
// ==============================================================================
// Analytic: Suspicious Office Child Process with Corroborating Network Connection
// Framework: Microsoft Defender XDR Advanced Hunting
// Schema: DeviceProcessEvents INNER JOIN DeviceNetworkEvents
// ==============================================================================

let Lookback = 2h;
let SuspiciousParents = dynamic(["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]);
let ShellChildren = dynamic(["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"]);

// Step 1: Capture suspicious parent-child process executions
let ProcessSpawns = DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where InitiatingProcessFileName in~ (SuspiciousParents)
| where FileName in~ (ShellChildren)
| extend RiskScore = 0
| extend RiskScore = RiskScore + case(
    ProcessCommandLine has_any ("-enc", "-encodedcommand", "base64"), 40,
    ProcessCommandLine has_any ("bypass", "unrestricted", "hidden"), 25,
    ProcessCommandLine has_any ("downloadstring", "webrequest", "curl", "certutil"), 35,
    10
)
| project ProcessTime = Timestamp, DeviceId, DeviceName, AccountName, 
          ParentProcess = InitiatingProcessFileName, 
          ChildProcess = FileName, 
          ProcessCommandLine, 
          InitiatingProcessId, 
          ProcessId, 
          RiskScore;

// Step 2: Correlate with concurrent external network communication
let NetworkConnections = DeviceNetworkEvents
| where Timestamp >= ago(Lookback)
| where ActionType == "ConnectionSuccess"
| where not(ipv4_is_private(RemoteIP))
| project NetworkTime = Timestamp, DeviceId, InitiatingProcessId = ProcessId, RemoteIP, RemotePort, RemoteUrl;

// Step 3: Multi-telemetry behavioral join
ProcessSpawns
| join kind=inner (NetworkConnections) on DeviceId, InitiatingProcessId
| where abs(datetime_diff('second', NetworkTime, ProcessTime)) <= 120
| extend TotalConfidenceScore = RiskScore + 30 // Network confirmation bonus
| where TotalConfidenceScore >= 50
| project ProcessTime, DeviceName, AccountName, ParentProcess, ChildProcess, 
          ProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, TotalConfidenceScore
| sort by TotalConfidenceScore desc
```

---

## 4. Engineering Trade-Offs & Tuning Principles

1. **Scoring vs. Binary Decisions:**  
   Assigning cumulative weights across execution arguments, parent lineage, and network egress prevents immediate alert fatigue while ensuring sophisticated stealth attacks trigger threshold boundaries.
2. **Temporal Windowing (`datetime_diff`):**  
   Correlating process creation with external socket establishment within a tight bounded window (120 seconds) neutralizes unassociated background network chatter.
3. **Surgical Suppression (When Allowlists Are Justified):**  
   Environment-specific allowlists should be implemented strictly on immutable cryptographic hashes or verified code-signing certificates—never on raw file paths or filenames alone.

---

## 5. Alignment with Microsoft Applied Skills & MITRE ATT&CK
* **MITRE ATT&CK Techniques:**
  - `T1204.002` (User Execution: Malicious File)
  - `T1059.001` (Command and Scripting Interpreter: PowerShell)
  - `T1071.001` (Application Layer Protocol: Web Protocols)
* **Operational Readiness:**  
  Directly applies advanced KQL joins (`kind=inner`), datetime functions, and cross-table correlation proven during the *Microsoft Defender XDR (APL-5004)* assessment.
