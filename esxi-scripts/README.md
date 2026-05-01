# esxi-scripts

PowerShell scripts for ESXi/vSphere management and auditing.

---

## secureboot-audit.ps1

Audit Secure Boot certificate status in VMware virtual machines across vSphere environments, identifying VMs affected by Microsoft Secure Boot certificate EOL (June 2026).

### Background

VMware vSphere VMs initialize their vUEFI Secure Boot certificates at first power-on and retain them for the **lifetime of the VM**. This is the core issue:

| ESXi Version (at VM creation) | VM Hardware Ver | Certificates | KEK Expiry |
|---|---|---|---|
| ESXi 9.x | v14+ | 2023 chain | Mar 2038 ✅ |
| ESXi 8.0.2+ | v21+ | 2023 chain | Mar 2038 ✅ |
| ESXi 8.0.0–8.0.1 | any | 2011 chain | Jun 2026 ❌ |
| ESXi 7.x | any | 2011 chain | Jun 2026 ❌ |

VMs created on ESXi 8.0.1 and below (or 7.x) have the **2011 certificate chain** baked into their vNVRAM. The affected certificates expire **30 June 2026**:

- Microsoft Windows Production PCA 2011 (DB)
- Microsoft Corporation UEFI CA 2011 (DB)
- Microsoft Corporation KEK CA 2011 (KEK)

**Key points:**

- **It's not about ESXi host firmware.** Upgrading ESXi does **not** retroactively update existing VM certificates.
- **VMs will continue to boot** after the cert expiry — boot is only impacted when Microsoft revokes the 2011 DB certificates.
- **An expired KEK** impacts the ability to update Secure Boot databases (DB, DBX) — future revocation updates will fail.
- **Affected workflows:** BitLocker VBS, Windows Update signed boot components, any authenticated Secure Boot update.

### What it does

1. Enumerates VMs from vCenter (all VMs, Secure Boot only, or filtered by cluster/datacenter/host)
2. Checks each VM's Secure Boot configuration and certificate status
3. Uses **version-based inference** to determine cert chain from ESXi version + VM hardware version (works for powered-off VMs)
4. For powered-on VMs with guest access, performs **direct certificate verification** via `Invoke-VMScript` querying the vUEFI database
5. Generates a CSV report and console summary

### Requirements

- **PowerShell 5.1+** on Windows
- **VMware PowerCLI** module
  - Install: `Install-Module -Name VMware.PowerCLI -Force`
- **vCenter Server** access (or ESXi direct connection)
- **Guest credentials** (optional) — for direct vUEFI certificate verification on powered-on VMs

### Usage

**Connect and audit all VMs:**

```powershell
.\secureboot-audit.ps1 -vCenter "vc.domain.local" -vCredUser "administrator@vsphere.local" -vCredPass "password" -AuditAll
```

**Audit only Secure Boot VMs (recommended):**

```powershell
.\secureboot-audit.ps1 -vCenter "vc.domain.local" -vCredUser "administrator@vsphere.local" -vCredPass "password" -SecureBootOnly
```

**Filter by cluster:**

```powershell
.\secureboot-audit.ps1 -vCenter "vc.domain.local" -vCredUser "admin" -vCredPass "pass" -SecureBootOnly -Cluster "Production"
```

**Filter by datacenter:**

```powershell
.\secureboot-audit.ps1 -vCenter "vc.domain.local" -vCredUser "admin" -vCredPass "pass" -AuditAll -Datacenter "London", "Frankfurt"
```

**Filter by specific ESXi hosts:**

```powershell
.\secureboot-audit.ps1 -vCenter "vc.domain.local" -vCredUser "admin" -vCredPass "pass" -SecureBootOnly -ESXiHost "esxi01", "esxi02"
```

**Use existing PowerCLI session:**

```powershell
Connect-VIServer "vc.domain.local"
.\secureboot-audit.ps1 -AuditAll
```

### Output

- **CSV report** — `SecureBootAudit_YYYYMMDD_HHMMSS.csv` in the script directory
- **Log file** — `SecureBootAudit_YYYYMMDD_HHMMSS.log` with scan details
- **Console summary** — certificate chain status breakdown and affected VMs table

### Certificate Status Classifications

| Status | Meaning |
|---|---|
| **GOOD (2023)** | VM has the 2023 certificate chain — no action needed |
| **AFFECTED (2011)** | VM has the 2011 certificate chain — will break after Jun 2026 revocation |
| **UNKNOWN** | Cannot determine cert chain — needs guest-level verification |
| **N/A** | Secure Boot is disabled on this VM |

### Remediation for Affected VMs

The fix is at the **VM level**, not the host level. VMware provides two paths:

**1. VMware Manual PK Update** (Article [423919](https://knowledge.broadcom.com/external/article/423919))

Update the Platform Key (PK) to a valid certificate, then follow Microsoft's Secure Boot update guidance. This is the supported VMware path.

**2. Manual Update via Guest OS (Windows)**

For powered-on Windows VMs with administrative access:

1. Update PK to Windows OEM Devices PK (valid certificate)
2. Add `Microsoft Corporation KEK 2K CA 2023` to the KEK database
3. Run Windows Update to apply new DB/DBX certificates
4. Verify: `Get-SecureBootUEFI`

For Linux VMs, use `mokutil --update-key` to add new KEK certificates via VMware's Secure Boot update mechanisms.

**3. New VMs**

VMs created on ESXi 8.0.2+ with HW v21+ (or any ESXi 9.x) already have the 2023 certificate chain. No action needed.

### Timeline

- **30 June 2026** — Microsoft 2011 certificates expire
- **After revocation** — VMs can no longer apply DB/DBX Secure Boot updates
- **Target:** Audit all VMs and remediate affected ones well before June 2026
