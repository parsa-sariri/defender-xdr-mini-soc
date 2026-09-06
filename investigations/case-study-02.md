# 🔬 Case Study 02: Behavioral Discovery Hunting & Custom Detection Engineering

## 1. Executive Summary & Objective
* **Purpose:** Move beyond static antivirus signatures to engineer a behavior-based custom detection rule capable of catching post-exploitation host enumeration executed via native Windows utilities.
* **Hypothesis:** An anomalous burst of native administrative reconnaissance binaries executed within a tight time window by the same user context indicates early-stage adversary host discovery (living-off-the-land).
* **Scope:** Controlled execution of 6 native discovery utilities within an isolated KVM guest (`LAB-WIN2025`), correlated telemetry analysis in `DeviceProcessEvents`, sub-second KQL aggregation, and deployment of a scheduled Detection-as-Code analytic.

---

## 2. Epistemic Discipline: What This Case Demonstrates vs. Does NOT Demonstrate
* **What This Demonstrates:**
  - Capability to correlate disparate benign process creation events into a composite behavioral pattern.
  - Development of noise-resilient Kusto Query Language (KQL) heuristics using multi-dimensional aggregation (`summarize`, `dcount`, `make_set`, `bin`).
  - Production deployment of automated detection engineering rules within Microsoft Defender XDR.
* **What This Does NOT Demonstrate:**
  - Automated remediation/containment (deliberately scoped to alerting to avoid impacting legitimate administrative operations).
  - Cross-domain lateral movement detection (scoped strictly to local host discovery).
  - Adversary emulation beyond living-off-the-land command execution.

---

## 3. Simulated Adversary Activity
Executed via elevated interactive command shell (`cmd.exe`) on `LAB-WIN2025` under user context `Administrator`:

```cmd
whoami /all
hostname
ipconfig /all
systeminfo
tasklist
quser
```

* **Observed Host Response:** All commands executed cleanly without antivirus obstruction (return code `0`), as all binaries are native, cryptographically signed Microsoft operating system utilities.
* **Execution Duration:** All 6 tools executed within a 64-second window (`05:56:53 AM` to `05:57:57 AM`).

---

## 4. Telemetry Extraction & KQL Development

### Phase 1: Telemetry Discovery (Find)
Initial audit of `DeviceProcessEvents` confirmed 100% ingestion with sub-second query latency (0.628s):

```kusto
DeviceProcessEvents
| where DeviceName =~ "LAB-WIN2025"
| where FileName in~ ("whoami.exe", "hostname.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe", "quser.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by Timestamp desc
```

### Phase 2: Process Lineage Correlation
Verifying parent-child relationships revealed `InitiatingProcessFileName` as `cmd.exe` across all 6 executions, confirming interactive shell enumeration.

### Phase 3: Behavioral Detection Analytic (Detection Logic)
To prevent noisy, low-fidelity alerts on single administrative queries, the analytic groups events into 1-hour dynamic buckets and triggers only when distinct discovery tool usage reaches or exceeds the threshold of 3:

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

* **Query Execution Performance:** `00:01.57` latency, `Low` resource consumption.
* **Output:** Matched host `LAB-WIN2025`, identified `ReconCommandCount = 6`, and aggregated the full execution payload.

---

## 5. Custom Detection Rule Deployment

* **Rule Name:** `Suspicious Host Discovery via Native Windows Utilities`
* **Execution Frequency:** Hourly (`Lookback: 4 Hours`)
* **Severity:** `Medium`
* **MITRE ATT&CK Mapping:**
  * **Tactic:** Discovery (`TA0007`)
  * **Techniques:** 
    - `T1033` (System Owner/User Discovery)
    - `T1082` (System Information Discovery)
    - `T1016` (System Network Configuration Discovery)
    - `T1057` (Process Discovery)
* **Impacted Asset Mapping:** `Device` mapped dynamically to `DeviceId`.
* **Alert Enrichment:** Dynamic tokenization generating alert title and contextual description (`{{DeviceName}}` and `{{AccountName}}`).
* **Deployment Status:** `Active` / `Rule saved successfully` (confirmed via Microsoft Defender XDR management plane).

---

## 6. Engineering Takeaways & SOC Operations
1. **Signature Evasion Resilience:** Native Windows binaries bypass traditional file-based AV checks; behavioral aggregation in EDR is essential for early-stage intrusion detection.
2. **False-Positive Tuning Strategy:** In enterprise production, threshold tuning (`ReconCommandCount >= 4`) combined with parent process whitelisting (e.g., excluding approved deployment scripts or monitoring orchestrators) minimizes operational SOC fatigue while catching interactive human intrusions.
