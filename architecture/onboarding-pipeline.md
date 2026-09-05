# 🔑 Cloud EDR Onboarding Pipeline

## 1. Onboarding Strategy
Windows Server 2025 Datacenter requires modern EDR sensor registration. In this lab, we utilized the official **Microsoft Defender Deployment Tool** combined with a time-bounded cryptographic **Access Key** generated within `security.microsoft.com/securitysettings/endpoints/onboarding`.

---

## 2. Verification Protocol

### Step 1: Tool Execution on Target Host
Run the deployment package as Administrator:
```powershell
.\DefenderDeploymentTool_Onboard_[Scope].exe
```
When prompted, supply the 20-character tenant Access Key. The installer:
1. Validates prerequisites and verifies root certificate authorities.
2. Registers the Microsoft Defender Advanced Threat Protection service (`Sense.exe`).
3. Establishes the regional cloud telemetry channel (`https://edr-weu3.eu.endpoint.security.microsoft.com/edr/`).
4. Confirms completion with `Sequence completed successfully`.

### Step 2: Local Service Verification
Confirm that the sensor service is active and running:
```powershell
Get-Service -Name "Sense" | Select-Object Name, Status, StartType
```

### Step 3: Portal Registration Check
Inside the Defender XDR portal (`Assets > Devices`):
* **Sensor health state:** `● Active`
* **Onboarding status:** `✔ Onboarded`
* **OS Platform:** `WindowsServer2025`
