# 🔒 Security Policy & OpSec Hygiene

## 1. Zero Secret & Credential Disclosure
* **No Production Credentials:** This repository does not store or track any live passwords, active Personal Access Tokens (PAT), Azure AD client secrets, or cryptographic certificates.
* **Redaction Policy:** All machine identifiers (`DeviceId`), tenant GUIDs, public IP addresses, and organizational alert identifiers have been systematically sanitized and replaced with RFC-compliant documentation ranges or lab placeholders (`LAB-WIN2025`, `10.0.0.0/24`, `REDACTED-LAB-001`).

---

## 2. Responsible Disclosure & Lab Safety
* All detection engineering logic, hunting queries, and telemetry analyses are developed within a strictly isolated, self-hosted virtualization boundary (KVM/QEMU hypervisor on Linux).
* Simulation scripts contained herein are strictly benign, non-destructive, and reversible. They utilize native Windows administration utilities to generate observable behavioral telemetry. No offensive exploit payloads or weaponized exploits are hosted or published.
