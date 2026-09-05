# 🛡️ Enterprise Defender XDR Mini-SOC & Threat Detection Lab

> **Author:** Parsa Sariri Ajili  
> **Environment:** Hybrid Enterprise Lab (Isolated KVM Virtualization + Microsoft Defender XDR Cloud)  
> **Target Platform:** Windows Server 2025 Datacenter (Build 26100, Version 24H2)  
> **Core Focus:** Cloud-Native EDR Onboarding, Telemetry Pipeline Ingestion, Advanced Hunting via KQL, MITRE ATT&CK Detection Engineering.

---

## 📌 1. Project Overview & Architectural Mission

This project documents the engineering, deployment, and operational validation of an **Enterprise Mini-SOC Lab**. 

Rather than relying on pre-packaged academic simulators, this environment mirrors production SecOps by bridging an on-premises enterprise server guest (`LAB-DC01` running **Windows Server 2025**) hosted inside a hardened Linux hypervisor (KVM/QEMU) directly into **Microsoft Defender XDR (formerly Microsoft 365 Defender)** via authenticated cloud EDR endpoints (`WestEurope3`).

The goal is to maintain a repeatable, version-controlled repository of:
1. **Cloud EDR Architecture & Outbound Ingestion Pathways:** Seamless telemetry streaming through virtualized bridges without exposing underlying hypervisor controls.
2. **KQL Threat Hunting Library:** Production-grade Kusto Query Language (KQL) detections mapped to MITRE ATT&CK techniques.
3. **Behavioral Telemetry Validation:** Verifying sub-second raw log ingestion (`DeviceInfo`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceLogonEvents`).
4. **Custom Detection Rules as Code:** Prototyping automated detection rules directly consumable by SIEM/XDR platforms.

---

## 🏛️ 2. High-Level Lab Topology

```
+-------------------------------------------------------------------------+
| Linux Host Hypervisor (Ubuntu 24.04 LTS / Kernel 7.0)                   |
| - Virtual Machine Manager (libvirt / QEMU-KVM)                          |
| - Virtual Network Gateway (Isolated Host NAT / Secure Forwarding)       |
+------------------------------------+------------------------------------+
                                     |
                          [Virtual Bridge / vnet0]
                                     |
+------------------------------------+------------------------------------+
| Guest Virtual Machine: LAB-DC01 (Windows Server 2025 Datacenter 24H2)   |
| - Host Role: Dedicated Server Workload (Sanitized ID: dc1)             |
| - Security Agent: Microsoft Defender for Endpoint (Sense.exe v10.8830)  |
| - Health State: Active | Onboarding State: Successfully Onboarded       |
+------------------------------------+------------------------------------+
                                     |
                         [Outbound HTTPS / TLS 1.3]
                         [*.endpoint.security.microsoft.com]
                                     |
+------------------------------------+------------------------------------+
| Microsoft Defender XDR Cloud Platform (Region: EU - WestEurope3)        |
| - Defender for Endpoint P2 Telemetry Pipeline                           |
| - Advanced Hunting Engine (Kusto Cluster)                               |
| - Incident Management & Custom Detections Framework                    |
+-------------------------------------------------------------------------+
```

---

## 🚀 3. Repository Structure

```
defender-xdr-mini-soc/
├── README.md                          # Master architectural overview and lab brief
├── architecture/
│   ├── network-topology.md            # In-depth hypervisor & network gateway specifications
│   └── onboarding-pipeline.md         # Deployment tool & EDR authentication protocol
├── hunting/
│   ├── README.md                      # Hunting strategy and hypothesis generation
│   ├── baseline-device-telemetry.kql  # Host posture, OS build & sensor health verification
│   ├── process-execution-hunting.kql  # Parent-child lineage & command-line auditing
│   └── logon-authentication-audit.kql # Interactive vs Network logon triage
├── detections/
│   ├── README.md                      # Detection engineering lifecycle & rule tuning
│   └── rule-templates.md              # MITRE-mapped custom detection templates
├── simulations/
│   └── README.md                      # Controlled, non-destructive telemetry generators
├── investigations/
│   └── case-study-01.md               # Baseline sensor validation & LOLBAS interception
└── docs/
    └── methodology.md                 # Sanitization standards & verification protocol
```

---

## 🔍 4. Verified Ingestion & Sub-Second Query Latency

The onboarding pipeline was confirmed operational with live telemetry ingestion across core tables:

```kusto
// Verification Query: Host Identification & Build Audit
DeviceInfo
| where DeviceName =~ "dc1"
| project Timestamp, DeviceName, OSPlatform, OSBuild, ClientVersion, PublicIP
| take 1
```

* **Observed Execution Time:** `00:00.676` (~676 ms)
* **Ingested OS Build:** `26100.33296` (Windows Server 2025 Datacenter)
* **Sensor Status:** Active and streaming continuous process telemetry to Microsoft's West Europe EDR cluster.

---

## 🔒 5. Privacy & Data Sanitization Disclosure

In adherence to enterprise security hygiene:
- Public IP addresses, tenant subscription GUIDs, and internal Active Directory credentials have been completely sanitized and replaced with standard RFC/placeholder nomenclature (`LAB-DC01`, `10.0.0.0/24`, `example.local`).
- No private attack payloads or destructive capabilities are distributed in this repository. All simulations are designed for benign behavioral auditing.

---

## 📜 6. References & Standards
- [Microsoft Defender XDR Documentation](https://learn.microsoft.com/en-us/defender-xdr/)
- [Microsoft Applied Skills: APL-5004](https://learn.microsoft.com/en-us/credentials/applied-skills/defend-against-cyberthreats-with-microsoft-defender-xdr/)
- [MITRE ATT&CK Enterprise Matrix (v16)](https://attack.mitre.org/)
