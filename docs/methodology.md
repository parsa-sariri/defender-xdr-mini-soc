# 🔒 Data Sanitization & Verification Standards

To uphold professional OpSec and data privacy, all published artifacts in this repository strictly adhere to these controls:

1. **Host & Tenant Sanitization:** Real organizational GUIDs, subscription IDs, and Microsoft Entra tenant identifiers are purged or anonymized.
2. **Network Scoping:** Actual external public IPs are replaced with generic documentation prefixes (e.g., RFC 5737 `203.0.113.0/24`) or standard internal documentation subnets (`10.0.0.0/24`).
3. **No Credential Distribution:** No live credentials, Access Keys, or Personal Access Tokens (PAT) are stored in git history.
4. **Reproducibility:** All KQL queries are written against standard, documented schema tables available in production Microsoft Defender XDR tenants.
