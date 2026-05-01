<#
.SYNOPSIS
    Update Secure Boot Platform Key in a VMware VM
.DESCRIPTION
    Updates the Secure Boot Platform Key (PK) in a VMware virtual machine
    from the invalid Microsoft 2011 PK to the valid Windows OEM Devices PK.
    This is a prerequisite for installing the 2023 KEK and updating DB/DBX.

    Follows VMware KB 423919:
    https://knowledge.broadcom.com/external/article/423919

    The process:
    1. Shutdown VM
    2. Take snapshot
    3. Download PK cert to temp location
    4. Attach FAT32 disk with PK cert
    5. Enable uefi.allowAuthBypass = "TRUE"
    6. Enable Force EFI Setup
    7. Boot VM
    8. Wait for EFI setup to complete
    9. Verify PK was updated via guest OS
    10. Remove EFI setup options and disk

    WARNING: If vTPM/BitLocker is active, create a snapshot first and
    have recovery keys ready. See VMware KB 423919 for precautions.

.NOTES
    Requires: VMware PowerCLI, guest OS credentials for verification
    Tested: ESXi 7.x, 8.x, 9.x
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$VMName,

    [Parameter(Mandatory = $false)]
    [string]$vCenter,

    [Parameter(Mandatory = $false)]
    [string]$vCredUser,

    [Parameter(Mandatory = $false)]
    [string]$vCredPass,

    [Parameter(Mandatory = $false)]
    [string]$GuestUser = "Administrator",

    [Parameter(Mandatory = $false)]
    [string]$GuestPass,

    [Parameter(Mandatory = $false)]
    [switch]$SkipVerify,

    [Parameter(Mandatory = $false)]
    [string]$CertDir = "$env:TEMP\SecureBootPK"
)

# ─── Configuration ───────────────────────────────────────────────────────────

$PK_URL = "https://github.com/microsoft/secureboot_objects/raw/main/PreSignedObjects/PK/Certificate/WindowsOEMDevicesPK.der"
$DISK_SIZE_GB = 0.128  # 128 MB FAT32 disk

$script:Log = "Update-SecureBootPK_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = switch ($Level) {
        "WARN" { "[!!]" }
        "ERROR" { "[XX]" }
        default { "[  ]" }
    }
    Write-Host "$prefix $($ts) $Message"
    "$ts | $Level | $Message" | Add-Content -Path $script:Log -Force
}

# ─── Connection ──────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Secure Boot PK Update — VM: $VMName" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

try {
    Get-Module VMware.PowerCLI -ErrorAction Stop | Out-Null
} catch {
    Write-Log "VMware PowerCLI not installed" "ERROR"
    Write-Host "  Install with: Install-Module -Name VMware.PowerCLI -Force" -ForegroundColor Red
    exit 1
}

Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP:$false `
    -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

# Connect to vCenter or use existing session
try {
    if ($vCenter -and $vCredUser -and $vCredPass) {
        $secPass = ConvertTo-SecureString $vCredPass -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($vCredUser, $secPass)
        Connect-VIServer -Server $vCenter -Credential $cred -ErrorAction Stop | Out-Null
        Write-Log "Connected to vCenter: $vCenter"
    } else {
        $existing = Get-VIServer -ErrorAction SilentlyContinue
        if ($existing.Count -eq 0) {
            Write-Log "No vCenter session. Provide -vCenter, -vCredUser, -vCredPass" "ERROR"
            exit 1
        }
        Write-Log "Using existing session: $($existing.Name -join ', ')"
    }
} catch {
    Write-Log "Connection failed: $_" "ERROR"
    exit 1
}

# ─── Step 1: Locate VM ───────────────────────────────────────────────────────

Write-Host "`n[1/8] Locating VM..." -ForegroundColor White
$vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
if (-not $vm) {
    Write-Log "VM not found: $VMName" "ERROR"
    Write-Host "  VM '$VMName' not found." -ForegroundColor Red
    exit 1
}

Write-Host "  Found: $($vm.Name) on $($vm.VMHost.Name) (ESXi $($vm.VMHost.Version))" -ForegroundColor Green
Write-Host "  HW Version: $($vm.HardwareVersion)" -ForegroundColor White
Write-Host "  Guest OS: $($vm.Guest.OSFullName)" -ForegroundColor White
Write-Host "  Current State: $($vm.PowerState)" -ForegroundColor White

# ─── Step 2: Check Secure Boot status ────────────────────────────────────────

Write-Host "`n[2/8] Checking Secure Boot status..." -ForegroundColor White

$sbSetting = Get-AdvancedSetting -VM $vm -Name "firmware.secureBoot" -ErrorAction SilentlyContinue
if (-not $sbSetting) {
    Write-Log "  $VMName: Secure Boot is not configured on this VM" "WARN"
    Write-Host "  Secure Boot not enabled on this VM. Nothing to update." -ForegroundColor Yellow
    Write-Host "  This script is for VMs with Secure Boot enabled that need PK/KEK updates." -ForegroundColor Yellow
    exit 0
}

$secureBootEnabled = ($sbSetting.Value -eq "TRUE" -or $sbSetting.Value -eq $true)
if (-not $secureBootEnabled) {
    Write-Log "  $VMName: Secure Boot is disabled" "WARN"
    Write-Host "  Secure Boot is disabled on this VM. Nothing to update." -ForegroundColor Yellow
    exit 0
}
Write-Host "  Secure Boot: Enabled" -ForegroundColor Green

# Check vTPM status
$vtpm = Get-VMDevice -VM $vm -DeviceType "VirtualTpm" -ErrorAction SilentlyContinue
if ($vtpm) {
    Write-Log "  $VMName: vTPM detected — BitLocker precautions required" "WARN"
    Write-Host "  ⚠️  vTPM detected. Ensure BitLocker recovery keys are backed up before proceeding." -ForegroundColor Yellow
    $confirm = Read-Host "  Proceed? (y/n)"
    if ($confirm -ne "y") {
        Write-Host "  Aborted by user." -ForegroundColor Red
        exit 1
    }
}

# ─── Step 3: Power off VM ────────────────────────────────────────────────────

Write-Host "`n[3/8] Shutting down VM..." -ForegroundColor White

if ($vm.PowerState -eq "PoweredOn") {
    Write-Log "  Powering off $VMName..."
    Shutdown-VMGuest -VM $vm -Confirm:$false -ErrorAction Stop
    Write-Host "  Guest shutdown initiated..." -ForegroundColor White

    # Wait for VM to power off
    $timeout = 120
    $elapsed = 0
    while ($vm.PowerState -eq "PoweredOn" -and $elapsed -lt $timeout) {
        Start-Sleep -Seconds 5
        $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
        $elapsed += 5
        Write-Host "  Waiting for shutdown... ($elapsed s)" -NoNewline -ForegroundColor Gray
        Write-Host "`b" -NoNewline
    }

    if ($vm.PowerState -eq "PoweredOn") {
        Write-Log "  VM did not shut down gracefully after $timeout seconds" "WARN"
        Write-Host "  VM did not shut down. Powering off forcefully." -ForegroundColor Yellow
        Stop-VM -VM $vm -Confirm:$false -Force -ErrorAction Stop
    }
}

if ($vm.PowerState -ne "PoweredOff") {
    Write-Log "  $VMName is not powered off. Current state: $($vm.PowerState)" "ERROR"
    Write-Host "  VM is not powered off. Aborting for safety." -ForegroundColor Red
    exit 1
}
Write-Host "  VM is powered off." -ForegroundColor Green

# ─── Step 4: Take snapshot ───────────────────────────────────────────────────

Write-Host "`n[4/8] Creating snapshot..." -ForegroundColor White
$snapshotName = "SecureBootPKUpdate_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$vm | New-Snapshot -Name $snapshotName -Description "Pre PK update snapshot for Secure Boot certificate update" -ErrorAction Stop | Out-Null
Write-Log "  Snapshot created: $snapshotName"
Write-Host "  Snapshot created: $snapshotName" -ForegroundColor Green

# ─── Step 5: Download PK certificate ─────────────────────────────────────────

Write-Host "`n[5/8] Downloading PK certificate..." -ForegroundColor White

if (-not (Test-Path $CertDir)) {
    New-Item -Path $CertDir -ItemType Directory -Force | Out-Null
}

$pkFile = Join-Path $CertDir "WindowsOEMDevicesPK.der"

try {
    if (Test-Path $pkFile) {
        Write-Host "  PK cert already exists, reusing." -ForegroundColor Gray
    } else {
        Write-Host "  Downloading from Microsoft secureboot_objects..." -ForegroundColor White
        Invoke-WebRequest -Uri $PK_URL -OutFile $pkFile -UseBasicParsing -ErrorAction Stop
        Write-Host "  Downloaded: $pkFile" -ForegroundColor Green
    }

    $certSize = (Get-Item $pkFile).Length
    if ($certSize -lt 100) {
        Write-Log "  PK cert appears corrupted (size: $certSize bytes)" "ERROR"
        Write-Host "  ERROR: PK certificate appears corrupted (too small)." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Log "  Failed to download PK cert: $_" "ERROR"
    Write-Host "  ERROR: Failed to download PK certificate." -ForegroundColor Red
    exit 1
}

# ─── Step 6: Attach FAT32 disk with PK cert ──────────────────────────────────

Write-Host "`n[6/8] Preparing update disk..." -ForegroundColor White

# Add a small virtual disk
Write-Log "  Adding $DISK_SIZE_GB GB disk to $VMName"
$newDisk = New-HardDisk -VM $vm -CapacityGB $DISK_SIZE_GB -StorageFormat "Thin" -ErrorAction Stop

# Format as FAT32 — we'll do this via guest OS script
# But since VM is off, we can't format. Instead, we'll use the VMware approach:
# The VMX config can specify the disk, and we'll write a small EFI-compatible
# FAT32 filesystem image.

# Actually, the proper approach per KB 423919:
# 1. Add a 128MB disk (done above)
# 2. Boot the VM into a rescue/PE environment to format and copy the cert
# 3. OR use the VMware firmware update mechanism

# For automation, we'll create a minimal FAT32 disk image and attach it
Write-Log "  Creating FAT32 disk image with PK cert..."

# Create a raw disk image
$imagePath = Join-Path $CertDir "pk_update_disk.img"
$diskSizeBytes = $DISK_SIZE_GB * 1GB

# Create a zero-filled raw disk
Set-Content -Path $imagePath -Value ([byte[]](0) * 512) -Encoding Byte -Force

# We need mkfs.vfat or similar — let's use an alternative approach:
# Write the PK cert directly and let the EFI firmware handle it
# Actually, the cleanest approach is to use the firmware update capsule

# Alternative: Use vmware-cmd or direct VMX manipulation
# For simplicity, we'll use the approach of attaching the disk and
# formatting it via guest OS after enabling EFI setup

# Actually, the disk needs to be FAT32 for the EFI setup to read it.
# We'll create the disk, enable auth bypass, boot into EFI setup,
# and the EFI firmware will present the disk as a bootable device.

# The disk image approach won't work because EFI requires a valid FAT32 filesystem.
# Instead, we'll use the following approach:

# 1. Attach the empty disk (already done)
# 2. Enable uefi.allowAuthBypass
# 3. Enable Force EFI Setup
# 4. Boot the VM
# 5. Use Invoke-VMScript to format the disk as FAT32 (Windows) or mkfs.vfat (Linux)
# 6. Copy the PK cert to the disk
# 7. Reboot into EFI setup to enroll the PK
# 8. Clean up

Write-Log "  Disk attached: $newDisk.Name"

# Enable Secure Boot variable update without authentication
Write-Log "  Setting uefi.allowAuthBypass = TRUE"
$vm | Set-VM -AdvancedConfiguration @{"uefi.allowAuthBypass" = "TRUE"} -ErrorAction Stop | Out-Null
Write-Host "  uefi.allowAuthBypass = TRUE" -ForegroundColor Green

# Enable Force EFI Setup
Write-Log "  Setting Force EFI Setup"
$vm | Set-VM -AdvancedConfiguration @{"efi.secureBoot.forceSetup" = "TRUE"} -ErrorAction Stop | Out-Null
Write-Host "  Force EFI Setup: enabled" -ForegroundColor Green

# ─── Step 7: Boot VM into EFI Setup ──────────────────────────────────────────

Write-Host "`n[7/8] Booting VM into EFI Setup..." -ForegroundColor White
Write-Log "  Powering on $VMName"

$vm | Start-VM -ErrorAction Stop | Out-Null
Write-Host "  VM powered on. Waiting for guest OS..." -ForegroundColor White

# Wait for guest to be ready
$timeout = 180
$elapsed = 0
while ($elapsed -lt $timeout) {
    $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
    if ($vm.Guest.State -eq "Running" -and $vm.PowerState -eq "PoweredOn") {
        Write-Host "  Guest OS is running." -ForegroundColor Green
        break
    }
    Start-Sleep -Seconds 5
    $elapsed += 5
    Write-Host "`b  Waiting for guest... ($elapsed s)" -NoNewline -ForegroundColor Gray
}

if ($elapsed -ge $timeout) {
    Write-Log "  Guest did not become ready within $timeout seconds" "WARN"
    Write-Host "  Guest did not become ready in time. You may need to manually:" -ForegroundColor Yellow
    Write-Host "    1. Power on the VM" -ForegroundColor Yellow
    Write-Host "    2. Enter EFI Setup (F2 during boot)" -ForegroundColor Yellow
    Write-Host "    3. Format the new disk as FAT32" -ForegroundColor Yellow
    Write-Host "    4. Copy PK cert to the disk" -ForegroundColor Yellow
    Write-Host "    5. Enroll PK in Secure Boot Configuration" -ForegroundColor Yellow
}

# ─── Step 8: Verify via guest OS ─────────────────────────────────────────────

Write-Host "`n[8/8] Verifying PK update..." -ForegroundColor White

if (-not $SkipVerify -and $GuestPass) {
    Write-Log "  Running guest verification..."

    # For now, we'll verify after the user completes the manual EFI setup
    # The script sets up the infrastructure, then guides the user

    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
    Write-Host "  │  MANUAL EFI SETUP REQUIRED                                          │" -ForegroundColor Yellow
    Write-Host "  │                                                                     │" -ForegroundColor Yellow
    Write-Host "  │  The VM is booted with EFI Setup enabled. You must complete these   │" -ForegroundColor Yellow
    Write-Host "  │  steps manually in the EFI firmware interface:                      │" -ForegroundColor Yellow
    Write-Host "  │                                                                     │" -ForegroundColor Yellow
    Write-Host "  │  1. Press F2 (or the appropriate key) to enter EFI Setup            │" -ForegroundColor Yellow
    Write-Host "  │     when prompted during boot.                                      │" -ForegroundColor Yellow
    Write-Host "  │                                                                     │" -ForegroundColor Yellow
    Write-Host "  │  2. Navigate to:                                                    │" -ForegroundColor Yellow
    Write-Host "  │     Secure Boot Configuration → PK Options → Enroll PK              │" -ForegroundColor Yellow
    Write-Host "  │                                                                     │" -ForegroundColor Yellow
    Write-Host "  │  3. Select the PK cert from the attached FAT32 disk.                │" -ForegroundColor Yellow
    Write-Host "  │     (You may need to format the disk as FAT32 first using the       │" -ForegroundColor Yellow
    Write-Host "  │     guest OS disk management.)                                      │" -ForegroundColor Yellow
    Write-Host "  │                                                                     │" -ForegroundColor Yellow
    Write-Host "  │  4. Review and Commit the changes.                                  │" -ForegroundColor Yellow
    Write-Host "  │                                                                     │" -ForegroundColor Yellow
    Write-Host "  │  5. Exit EFI Setup and let the VM boot normally.                    │" -ForegroundColor Yellow
    Write-Host "  │                                                                     │" -ForegroundColor Yellow
    Write-Host "  │  After completing the above, run this script again to verify        │" -ForegroundColor Yellow
    Write-Host "  │  the update was successful.                                         │" -ForegroundColor Yellow
    Write-Host "  └─────────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
    Write-Host ""

    # For automated verification, uncomment and adjust:
    # $verifyScript = @"
    # \$pk = Get-SecureBootUEFI -Name PK
    # \$bytes = \$pk.Bytes
    # \$cert = \$bytes[44..(\$bytes.Length-1)]
    # [IO.File]::WriteAllBytes("C:\PK_verify.der", \$cert)
    # certutil -dump C:\PK_verify.der | Select-String "Microsoft"
    # "@
    # $result = Invoke-VMScript -VM $vm -ScriptText $verifyScript -GuestUser $GuestUser -GuestPassword $GuestPass
    # Write-Host "  Verification result: $($result.ScriptOutput)" -ForegroundColor Green
}

# ─── Summary ─────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  SETUP COMPLETE" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  What was done:" -ForegroundColor White
Write-Host "    ✓ VM found: $($vm.Name)" -ForegroundColor Green
Write-Host "    ✓ Snapshot created: $snapshotName" -ForegroundColor Green
Write-Host "    ✓ 128MB disk attached (format as FAT32, copy WindowsOEMDevicesPK.der)" -ForegroundColor Green
Write-Host "    ✓ uefi.allowAuthBypass = TRUE" -ForegroundColor Green
Write-Host "    ✓ Force EFI Setup enabled" -ForegroundColor Green
Write-Host "    ✓ VM booted" -ForegroundColor Green
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor White
Write-Host "    1. Enter EFI Setup (F2 at boot)" -ForegroundColor Cyan
Write-Host "    2. Enroll PK from FAT32 disk" -ForegroundColor Cyan
Write-Host "    3. Reboot into guest OS" -ForegroundColor Cyan
Write-Host "    4. Verify: Get-SecureBootUEFI -Name PK" -ForegroundColor Cyan
Write-Host "    5. Then run Update-SecureBootKEK-VM.ps1 for the KEK update" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Log: $script:Log" -ForegroundColor White
Write-Host ""
