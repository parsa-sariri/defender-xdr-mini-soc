# 🌐 Network & Virtualization Architecture

## 1. Physical Host Environment
* **Platform:** Dell Latitude 7430
* **Host Operating System:** Ubuntu 24.04 LTS (Noble Numbat) / Linux Kernel 7.0
* **Hypervisor:** Kernel-based Virtual Machine (KVM) with QEMU (`libvirt` orchestration via Virtual Machine Manager)

---

## 2. Virtual Gateway & Subnet Design
The guest environment runs on an isolated virtual network bridge (`virbr0` / `vnet0`):
* **Gateway Interface:** `192.168.122.1/24` (NAT Gateway with DHCP & DNS resolution provided by `dnsmasq`)
* **Target Guest IP:** Assigned dynamically or configured statically within the `192.168.122.0/24` lab scope.
* **Firewall Rules:** Layer 3 forwarding policy enforced via `iptables`/`nftables` on the host to permit outbound TCP 443 traffic to Microsoft cloud telemetry infrastructure while dropping unsolicited inbound access from external untrusted interfaces.

---

## 3. Outbound Telemetry Routing
Microsoft Defender for Endpoint requires direct or proxy-forwarded connectivity to specific cloud endpoints:
* `*.endpoint.security.microsoft.com` (TLS 1.2/1.3, Port 443)
* `*.events.data.microsoft.com`
* `*.blob.core.windows.net`

All guest traffic routes through host NAT, allowing continuous real-time telemetry streaming to Microsoft’s European datacenters (`WestEurope3`) without exposing hypervisor host services to the guest network.
