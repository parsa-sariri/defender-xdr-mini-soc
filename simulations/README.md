# 🧪 Telemetry Simulation Protocol

## Purpose
This directory outlines safe, benign, and repeatable telemetry generation scripts. The goal is to generate observable system artifacts in Microsoft Defender for Endpoint without destabilizing lab machines or triggering destructive activity.

---

## 1. Benign Discovery Simulation (Local System Discovery - T1082)
To audit host discovery events and verify ingestion into `DeviceProcessEvents`:

```cmd
whoami /all
ipconfig /all
net user
```

## 2. Non-Destructive LOLBAS Execution (Certificate Utility Audit - T1105)
Executing native utilities with benign parameter flags to test parent-child process detection:

```cmd
certutil.exe -v
```

All simulations are recorded in the lab activity logs to establish true positive baselines for KQL hunting queries.
