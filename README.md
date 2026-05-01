# esxi-scripts

PowerShell scripts for ESXi/vSphere management and auditing.

---

## Secure Boot Certificate Remediation (Microsoft 2026 EOL)

Microsoft Secure Boot UEFI certificates expire **30 June 2026**. VMware VMs created on ESXi 8.0.1 and below (or 7.x) have the 2011 certificate chain baked into their vUEFI NVRAM.

### Affected Certificates

- Microsoft Windows Production PCA 2011 (DB)
- Microsoft Corporation UEFI CA 2011 (DB)
- Microsoft Corporation KEK CA 2011 (KEK)

### Impact

- VMs will **continue to boot** after expiry
- After Microsoft revokes the 2011 DB certificates, VMs **cannot apply Secure Boot database updates** (DB, DBX, KEK)
- Affected workflows: BitLocker VBS, Windows Update signed boot components, authenticated Secure Boot updates

### Remediation Process

The fix is at the **VM level**, not the host level. Follow this sequence:

1. **Audit** — Run `secureboot-audit.ps1` to identify affected VMs
2. **Update PK** — Run `Update-SecureBootPK-VM.ps1` to replace the invalid Platform Key
3. **Update KEK** — Run `Update-SecureBootKEK-VM.ps1` to enroll the 2023 KEK
4. **Update DB/DBX** — Run Windows Update on guest OS to apply new DB/DBX certificates

### Prerequisites

- VMware PowerCLI: `Install-Module -Name VMware.PowerCLI -Force`
- Guest OS credentials (for verification)
- vCenter access or ESXi direct connection
- **⚠️ BitLocker/vTPM:** If VM has vTPM with disk encryption, back up recovery keys before proceeding

---

## Scripts

### secureboot-audit.ps1

Audit Secure Boot certificate status in VMware VMs.

See audit script documentation below.

### Update-SecureBootPK-VM.ps1

Update the Secure Boot Platform Key (PK) from the invalid 2011 cert to the valid Windows OEM Devices PK.

**Usage:**

```powershell
# Interactive (prompts for confirmation)
.\Update-SecureBootPK-VM.ps1 -VMName "my-vm" -vCenter "vc.domain.local" -vCredUser "admin" -vCredPass "password"

# With guest credentials for verification
.\Update-SecureBootPK-VM.ps1 -VMName "my-vm" -vCenter "vc.domain.local" -vCredUser "admin" -vCredPass "password" -GuestUser "Administrator" -GuestPass "password"

# Using existing PowerCLI session
Connect-VIServer "vc.domain.local"
.\Update-SecureBootPK-VM.ps1 -VMName "my-vm"
```

**What it does:**

1. Shuts down VM
2. Creates snapshot
3. Downloads PK cert from Microsoft
4. Attaches 128MB disk
5. Enables `uefi.allowAuthBypass = "TRUE"` and Force EFI Setup
6. Boots VM into EFI firmware setup

After this script completes, you must manually complete EFI setup (see below), then verify and proceed to KEK update.

### Update-SecureBootKEK-VM.ps1

Update the Secure Boot Key Exchange Key (KEK) from the expired 2011 cert to the 2023 KEK.

**Usage:**

```powershell
.\Update-SecureBootKEK-VM.ps1 -VMName "my-vm" -vCenter "vc.domain.local" -vCredUser "admin" -vCredPass "password"
```

**What it does:**

1. Verifies PK is valid (prerequisite)
2. Shuts down VM, creates snapshot
3. Downloads and converts KEK-2023 certificate
4. Attaches 128MB disk with KEK cert
5. Enables EFI auth bypass and Force EFI Setup
6. Boots VM for manual KEK enrollment

---

## Manual EFI Setup Steps

Both update scripts prepare the VM and boot into EFI setup. You must complete these steps manually in the firmware interface:

### PK Update (after running `Update-SecureBootPK-VM.ps1`)

1. Press **F2** during boot to enter EFI Setup
2. Navigate to: **Secure Boot Configuration → PK Options → Enroll PK**
3. Select the PK cert from the attached FAT32 disk
4. Review and **Commit** changes
5. Exit EFI Setup and let VM boot

### KEK Update (after running `Update-SecureBootKEK-VM.ps1`)

1. Press **F2** during boot to enter EFI Setup
2. Navigate to: **Secure Boot Configuration → KEK Options → Enroll KEK**
3. Select the `KEK-2023.der` file from the attached disk
4. Review and **Commit** changes
5. Exit EFI Setup and reboot

---

## Post-Update Verification

### Check PK (Windows guest)

```powershell
$pk = Get-SecureBootUEFI -Name PK
$bytes = $pk.Bytes
$cert = $bytes[44..($bytes.Length-1)]
[IO.File]::WriteAllBytes("PK.der", $cert)
certutil -dump PK.der
# Should show "Microsoft" in output (not "00 ." which indicates invalid/null PK)
```

### Check KEK (Windows guest)

```powershell
[System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI KEK).Bytes) -match "Microsoft Corporation KEK 2K CA 2023"
# Should return True
```

### Linux guest

```bash
mokutil --pk     # Should show valid cert, not empty
mokutil --kek    # Should list "Microsoft Corporation KEK 2K CA 2023"
```

### Final Step: Update DB/DBX

Run **Windows Update** on the guest OS to apply the new DB/DBX certificate revocations. This is handled automatically by Windows Update once the PK and KEK are valid.

---

## References

- VMware KB 423919: [Manual Update of the Secure Boot Platform Key in Virtual Machines](https://knowledge.broadcom.com/external/article/423919)
- VMware KB 423893: [Secure Boot Certificate Expirations and Update Failures in VMware Virtual Machines](https://knowledge.broadcom.com/external/article/423893)
- Microsoft: [Secure Boot Certificate updates: Guidance for IT professionals](https://support.microsoft.com/en-us/topic/secure-boot-certificate-updates-guidance-for-it-professionals-and-organizations-e2b43f9f-b424-42df-bc6a-8476db65ab2f)
- Microsoft Secure Boot Objects: [GitHub repository](https://github.com/microsoft/secureboot_objects)
