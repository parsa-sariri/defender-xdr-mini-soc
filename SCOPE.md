# 🎯 Scope & Rules of Engagement

## 1. Laboratory Authorization & Boundary
* **Environment:** Fully self-hosted, private virtualization boundary running on local hardware (Kernel-based Virtual Machine on Ubuntu 24.04 LTS).
* **Target Nodes:** Dedicated, isolated virtual machine instances (`LAB-WIN2025` / evaluation builds) created solely for defensive security engineering, telemetry validation, and threat detection research.
* **External Networks:** Telemetry outbound communication is strictly restricted to authorized Microsoft Defender XDR cloud endpoints (`*.endpoint.security.microsoft.com`). No scanning, probing, or adversary emulation is ever conducted against external, third-party, or unauthorized networks.

---

## 2. Research Objective & Ethics
This repository serves defensive detection engineering, academic research in systems and network security, and preparation for Microsoft Applied Skills (APL-5004) credentials. All activities follow the highest standards of academic integrity and security operations ethics.
