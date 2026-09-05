# 🔬 Case Study 01: Baseline Sensor Validation & LOLBAS Interception

## 1. Executive Summary & Objective
* **Purpose:** Establish baseline telemetry health and validate client-side heuristic detection on an onboarded Windows Server 2025 node.
* **Scope:** Controlled execution of a Living-off-the-Land Binary (LOLBAS) ingress tool transfer pattern (`certutil.exe`).
* **Result:** Real-time interception by Microsoft Defender Antivirus (`Sense.exe` EDR channel), generation of heuristic security alert `daedfcb22-5f66-4150-8ab5-0eb50f305fea_1`, and automated containment of the execution thread.

---

## 2. Test Execution Details
* **Target Node:** `dc1` (Windows Server 2025 Datacenter, Build `26100.33296`)
* **Execution Context:** `Administrator` (Elevated CLI session)
* **MITRE ATT&CK Mapping:**
  * **Tactic:** Ingress Tool Transfer (`TA0011` - Command and Control)
  * **Technique:** Ingress Tool Transfer via LOLBAS (`T1105`)

### Executed Command:
```cmd
certutil.exe -urlcache -split -f "https://www.google.com" C:\Users\Administrator\Desktop\test_artifact.txt
```

---

## 3. Host & Portal Evidence Observations

### A. Host-Level Interception:
* **Process Termination:** Immediate process failure with return code `Access is denied`.
* **Sensor Notification:** Windows Security Antivirus notification triggered locally:
  > *"Threats found: Microsoft Defender Antivirus found threats."*

### B. Microsoft Defender XDR Portal Telemetry:
* **Alert Title:** `An active 'Ceprolad' malware in a command line was prevented from executing`
* **Alert ID:** `daedfcb22-5f66-4150-8ab5-0eb50f305fea_1`
* **Severity:** `Low`
* **Category:** `Malware`
* **Detection Technology:** `Client, Heuristic`
* **Status:** `New` / `Action: Blocked`
* **Impacted Assets:** Device `dc1`, User `Administrator`

---

## 4. Engineering Takeaway & Next Steps
* **Ingestion Baseline:** Validates that client-side behavioral heuristics actively protect the host and ingest security incident telemetry directly into Microsoft Defender XDR.
* **Next Milestone:** Transition from signature/heuristic prevention to **silent process hunting** using KQL against non-blocked administrative LOLBAS patterns to build custom proactive detection rules.
