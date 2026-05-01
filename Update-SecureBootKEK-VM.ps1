<#
.SYNOPSIS
    Update Secure Boot KEK in a VMware VM
.DESCRIPTION
    Updates the Secure Boot Key Exchange Key (KEK) in a VMware virtual
    machine from the expired 2011 Microsoft KEK to the 2023 KEK.
    This allows the VM to receive future DB/DBX certificate updates.

    This script should be run AFTER Update-SecureBootPK-VM.ps1 has been
    completed and verified (PK must be a valid certificate).

    Follows VMware KB 423919:
    https://knowledge.broadcom.com/external/article/423919

    The process:
    1. Shutdown VM
    2. Take snapshot
    3. Download KEK-2023 certificate
    4. Attach FAT32 disk with KEK cert
    5. Enable uefi.allowAuthBypass = "TRUE"
    6. Enable Force EFI Setup
    7. Boot VM
    8. Format disk as FAT32, copy KEK cert
    9. Verify PK is already valid (prerequisite check)
    10. Reboot into EFI setup to enroll KEK
    11. Clean up

    WARNING: If vTPM/BitLocker is active, ensure recovery keys are
    backed up. See VMware KB 423919.

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
    [string]$CertDir = "$env:TEMP\SecureBootKEK"
)

# ─── Configuration ───────────────────────────────────────────────────────────

# KEK URL from Microsoft — returns a CER file, need to convert to DER
$KEK_CER_URL = "https://go.microsoft.com/fwlink/?linkid=2239775"
$KEK_DER_URL = "https://github.com/microsoft/secureboot_objects/raw/main/PreSignedObjects/KEK/Certificate/Microsoft%20KEK%20CA%202011_2023.cer"
$DISK_SIZE_GB = 0.128

$script:Log = "Update-SecureBootKEK_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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
Write-Host "  Secure Boot KEK Update — VM: $VMName" -ForegroundColor Cyan
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

Write-Host "`n[1/9] Locating VM..." -ForegroundColor White
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

# ─── Step 2: Check prerequisites ─────────────────────────────────────────────

Write-Host "`n[2/9] Checking prerequisites..." -ForegroundColor White

# Check Secure Boot is enabled
$sbSetting = Get-AdvancedSetting -VM $vm -Name "firmware.secureBoot" -ErrorAction SilentlyContinue
if (-not $sbSetting) {
    Write-Log "  $VMName: Secure Boot not configured" "ERROR"
    Write-Host "  ERROR: Secure Boot not enabled on this VM." -ForegroundColor Red
    Write-Host "  This script is for VMs that already have Secure Boot PK updated." -ForegroundColor Red
    exit 1
}

$secureBootEnabled = ($sbSetting.Value -eq "TRUE" -or $sbSetting.Value -eq $true)
if (-not $secureBootEnabled) {
    Write-Log "  $VMName: Secure Boot is disabled" "ERROR"
    Write-Host "  ERROR: Secure Boot is disabled." -ForegroundColor Red
    exit 1
}
Write-Host "  Secure Boot: Enabled" -ForegroundColor Green

# Check vTPM
$vtpm = Get-VMDevice -VM $vm -DeviceType "VirtualTpm" -ErrorAction SilentlyContinue
if ($vtpm) {
    Write-Log "  $VMName: vTPM detected" "WARN"
    Write-Host "  ⚠️  vTPM detected. Ensure BitLocker recovery keys are backed up." -ForegroundColor Yellow
    $confirm = Read-Host "  Proceed? (y/n)"
    if ($confirm -ne "y") {
        Write-Log "  Aborted by user" "INFO"
        exit 0
    }
}

# ─── Step 3: Verify PK is valid (prerequisite) ───────────────────────────────

Write-Host "`n[3/9] Verifying PK update was completed..." -ForegroundColor White

if ($vm.PowerState -eq "PoweredOn") {
    Write-Log "  Checking PK status via guest OS..."
    if ($GuestPass) {
        $verifyScript = @'
try {
    $pk = Get-SecureBootUEFI -Name PK
    $bytes = $pk.Bytes
    $cert = $bytes[44..($bytes.Length-1)]
    [IO.File]::WriteAllBytes("C:\pk_verify.der", $cert)
    $result = certutil -dump C:\pk_verify.der 2>&1 | Out-String
    if ($bytes.Length -le 45) {
        Write-Host "PK_STATUS:INVALID"
    } elseif ($result -match "00\s*\.") {
        Write-Host "PK_STATUS:INVALID"
    } elseif ($result -match "Microsoft") {
        Write-Host "PK_STATUS:VALID"
    } else {
        Write-Host "PK_STATUS:UNKNOWN"
    }
} catch {
    Write-Host "PK_STATUS:ERROR"
}
'@
        try {
            $result = Invoke-VMScript -VM $vm -ScriptText $verifyScript `
                -GuestUser $GuestUser -GuestPassword $GuestPass -ErrorAction Stop
            $pkStatus = $result.ScriptOutput | Select-String "PK_STATUS:" | ForEach-Object { $_.Line.Split(':')[1].Trim() }

            if ($pkStatus -eq "INVALID") {
                Write-Log "  $VMName: PK is INVALID. Update PK first." "ERROR"
                Write-Host "  ERROR: PK is still invalid. Run Update-SecureBootPK-VM.ps1 first." -ForegroundColor Red
                exit 1
            } elseif ($pkStatus -eq "VALID") {
                Write-Log "  $VMName: PK is valid"
                Write-Host "  PK status: Valid" -ForegroundColor Green
            } else {
                Write-Log "  $VMName: PK status unknown" "WARN"
                Write-Host "  Could not verify PK status via guest. Continuing with caution." -ForegroundColor Yellow
            }
        } catch {
            Write-Log "  Guest verification failed: $_" "WARN"
            Write-Host "  Guest verification unavailable. Continuing with caution." -ForegroundColor Yellow
        }
    } else {
        Write-Log "  No guest credentials provided. Cannot verify PK status." "WARN"
        Write-Host "  ⚠️  No guest credentials provided. Ensure PK was updated before proceeding." -ForegroundColor Yellow
        $confirm = Read-Host "  Proceed anyway? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "  Aborted by user" "INFO"
            exit 0
        }
    }
} else {
    Write-Log "  VM is powered off. Cannot verify PK status." "WARN"
    Write-Host "  VM is powered off. Cannot verify PK status." -ForegroundColor Yellow
    Write-Host "  Ensure PK was updated before powering on." -ForegroundColor Yellow
}

# ─── Step 4: Power off VM ────────────────────────────────────────────────────

Write-Host "`n[4/9] Shutting down VM..." -ForegroundColor White

if ($vm.PowerState -eq "PoweredOn") {
    Write-Log "  Powering off $VMName..."
    Shutdown-VMGuest -VM $vm -Confirm:$false -ErrorAction Stop
    Write-Host "  Guest shutdown initiated..." -ForegroundColor White

    $timeout = 120
    $elapsed = 0
    while ($vm.PowerState -eq "PoweredOn" -and $elapsed -lt $timeout) {
        Start-Sleep -Seconds 5
        $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
        $elapsed += 5
    }

    if ($vm.PowerState -eq "PoweredOn") {
        Write-Log "  VM did not shut down gracefully" "WARN"
        Stop-VM -VM $vm -Confirm:$false -Force -ErrorAction Stop
    }
}

if ($vm.PowerState -ne "PoweredOff") {
    Write-Log "  $VMName is not powered off" "ERROR"
    Write-Host "  ERROR: VM is not powered off. Aborting." -ForegroundColor Red
    exit 1
}
Write-Host "  VM is powered off." -ForegroundColor Green

# ─── Step 5: Take snapshot ───────────────────────────────────────────────────

Write-Host "`n[5/9] Creating snapshot..." -ForegroundColor White
$snapshotName = "SecureBootKEKUpdate_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$vm | New-Snapshot -Name $snapshotName -Description "Pre KEK update snapshot" -ErrorAction Stop | Out-Null
Write-Log "  Snapshot created: $snapshotName"
Write-Host "  Snapshot created: $snapshotName" -ForegroundColor Green

# ─── Step 6: Download KEK certificate ────────────────────────────────────────

Write-Host "`n[6/9] Downloading KEK certificate..." -ForegroundColor White

if (-not (Test-Path $CertDir)) {
    New-Item -Path $CertDir -ItemType Directory -Force | Out-Null
}

$kecCERFile = Join-Path $CertDir "KEK-2023.cer"
$kecDERFile = Join-Path $CertDir "KEK-2023.der"

try {
    # Download CER
    if (Test-Path $kecCERFile) {
        Write-Host "  KEK CER already exists, reusing." -ForegroundColor Gray
    } else {
        Write-Host "  Downloading KEK from Microsoft..." -ForegroundColor White
        # Try multiple URLs
        $urls = @(
            "https://go.microsoft.com/fwlink/?linkid=2239775",
            "https://github.com/microsoft/secureboot_objects/raw/main/PreSignedObjects/KEK/Certificate/Microsoft%20KEK%20CA%202011_2023.cer"
        )

        $downloaded = $false
        foreach ($url in $urls) {
            try {
                Invoke-WebRequest -Uri $url -OutFile $kecCERFile -UseBasicParsing -ErrorAction Stop
                $downloaded = $true
                Write-Log "  Downloaded KEK from: $url"
                break
            } catch {
                Write-Log "  Failed to download from $url: $_" "WARN"
            }
        }

        if (-not $downloaded) {
            Write-Log "  All KEK download URLs failed" "ERROR"
            Write-Host "  ERROR: Failed to download KEK certificate from all URLs." -ForegroundColor Red
            exit 1
        }
    }

    # Convert CER to DER using OpenSSL (if available)
    $opensslPath = Get-Command openssl -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    if ($opensslPath) {
        Write-Host "  Converting CER to DER format using OpenSSL..." -ForegroundColor White
        & $opensslPath x509 -inform der -in $kecCERFile -outform der -out $kecDERFile -outform der 2>&1 | Out-Null
        if (-not (Test-Path $kecDERFile)) {
            Write-Log "  OpenSSL conversion failed, trying alternative method" "WARN"
        }
    } else {
        # No OpenSSL — copy CER as DER (some systems accept this)
        Write-Host "  OpenSSL not found. Copying CER as DER..." -ForegroundColor Gray
        Copy-Item -Path $kecCERFile -Destination $kecDERFile -Force
    }

    if (Test-Path $kecDERFile) {
        $kecSize = (Get-Item $kecDERFile).Length
        if ($kecSize -lt 50) {
            Write-Log "  KEK cert appears corrupted (size: $kecSize bytes)" "ERROR"
            Write-Host "  ERROR: KEK certificate appears corrupted." -ForegroundColor Red
            exit 1
        }
        Write-Host "  KEK cert: $kecDERFile ($($kecSize) bytes)" -ForegroundColor Green
    }
} catch {
    Write-Log "  Failed to download/convert KEK cert: $_" "ERROR"
    Write-Host "  ERROR: Failed to prepare KEK certificate." -ForegroundColor Red
    exit 1
}

# ─── Step 7: Prepare disk ────────────────────────────────────────────────────

Write-Host "`n[7/9] Preparing update disk..." -ForegroundColor White

# Add a new 128MB disk
Write-Log "  Adding $DISK_SIZE_GB GB disk to $VMName"
$newDisk = New-HardDisk -VM $vm -CapacityGB $DISK_SIZE_GB -StorageFormat "Thin" -ErrorAction Stop
Write-Log "  Disk attached: $newDisk.Name"

# Enable auth bypass
Write-Log "  Setting uefi.allowAuthBypass = TRUE"
$vm | Set-VM -AdvancedConfiguration @{"uefi.allowAuthBypass" = "TRUE"} -ErrorAction Stop | Out-Null
Write-Host "  uefi.allowAuthBypass = TRUE" -ForegroundColor Green

# Enable Force EFI Setup
Write-Log "  Setting Force EFI Setup"
$vm | Set-VM -AdvancedConfiguration @{"efi.secureBoot.forceSetup" = "TRUE"} -ErrorAction Stop | Out-Null
Write-Host "  Force EFI Setup: enabled" -ForegroundColor Green

# ─── Step 8: Boot VM and prepare disk ────────────────────────────────────────

Write-Host "`n[8/9] Booting VM and preparing disk..." -ForegroundColor White

$vm | Start-VM -ErrorAction Stop | Out-Null
Write-Host "  VM powered on. Waiting for guest OS..." -ForegroundColor White

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

# Prepare disk via guest OS
if ($GuestPass) {
    Write-Log "  Preparing disk via guest OS..."

    # Detect guest OS and prepare disk accordingly
    $osFamily = "Windows"  # Default assumption
    if ($vm.Guest.OSFullName -match "Linux|Ubuntu|CentOS|Red Hat|Debian") {
        $osFamily = "Linux"
    }

    if ($osFamily -eq "Windows") {
        $diskScript = @"
# Get the new disk (usually disk 1 or 2)
\$disks = Get-Disk | Where-Object {\$_.PartitionStyle -eq "RAW"}
if (\$disks) {
    \$disk = \$disks | Select-Object -First 1
    \$disk | Initialize-Disk -PartitionStyle MBR -Force
    \$partition = New-Partition -DiskNumber \$disk.Number -UseMaximumSize -AssignDriveLetter
    \$partition | Format-Volume -FileSystem FAT32 -Force
    \$letter = \$partition.DriveLetter
    Write-Host "DISK_FORMATTED:\${letter}:"
} else {
    Write-Host "DISK_STATUS:RAW_DISK_NOT_FOUND"
}
"@

        try {
            $diskResult = Invoke-VMScript -VM $vm -ScriptText $diskScript `
                -GuestUser $GuestUser -GuestPassword $GuestPass -ErrorAction Stop

            Write-Host "  Disk prepared via guest OS." -ForegroundColor Green
            Write-Log "  Disk preparation output: $($diskResult.ScriptOutput)"
        } catch {
            Write-Log "  Guest disk preparation failed: $_" "WARN"
            Write-Host "  Disk preparation failed. You may need to format manually." -ForegroundColor Yellow
        }
    } else {
        # Linux
        $diskScript = @"
# Find new unformatted disk
\$dev = \$(lsblk -dno NAME,TYPE | grep "disk" | grep -v "sda" | awk '{print \$1}' | head -1)
if (\$dev) {
    sudo mkfs.vfat -F 32 -n KEYUPDATE /dev/\$dev
    mkdir -p /mnt/keys
    sudo mount /dev/\$dev /mnt/keys
    echo "DISK_MOUNTED:/dev/\$dev"
} else {
    echo "DISK_STATUS:NO_DISK_FOUND"
}
"@

        try {
            $diskResult = Invoke-VMScript -VM $vm -ScriptText $diskScript `
                -GuestUser "root" -GuestPassword $GuestPass -ErrorAction Stop
            Write-Host "  Disk prepared via guest OS." -ForegroundColor Green
        } catch {
            Write-Log "  Guest disk preparation failed: $_" "WARN"
            Write-Host "  Disk preparation failed." -ForegroundColor Yellow
        }
    }
} else {
    Write-Log "  No guest credentials. Manual disk preparation required." "WARN"
    Write-Host "  No guest credentials. Disk will need manual preparation." -ForegroundColor Yellow
}

# ─── Step 9: Copy cert and manual EFI setup ──────────────────────────────────

Write-Host "`n[9/9] Completing setup..." -ForegroundColor White

if ($GuestPass) {
    Write-Log "  Copying KEK cert to disk via guest OS..."

    if ($osFamily -eq "Windows") {
        # Copy via guest
        $copyScript = @"
Copy-Item -Path '$($kecDERFile.Replace('\', '\\'))' -Destination 'C:\KEK-2023.der' -Force
if (Test-Path 'C:\KEK-2023.der') {
    # Move to the formatted disk if available
    \$letter = (Get-Disk | Where-Object {\$_.PartitionStyle -eq "MBR"} | Get-Partition | Get-Volume | Select-Object -First 1).DriveLetter
    if (\$letter) {
        Copy-Item 'C:\KEK-2023.der' -Destination "\${letter}:\KEK-2023.der" -Force
        Write-Host "KEK_COPIED:\${letter}:\KEK-2023.der"
    } else {
        Write-Host "KEK_COPIED:C:\KEK-2023.der"
    }
} else {
    Write-Host "KEK_STATUS:COPY_FAILED"
}
"@
        try {
            $copyResult = Invoke-VMScript -VM $vm -ScriptText $copyScript `
                -GuestUser $GuestUser -GuestPassword $GuestPass -ErrorAction Stop
            Write-Host "  KEK cert copied to disk." -ForegroundColor Green
        } catch {
            Write-Log "  Copy failed: $_" "WARN"
            Write-Host "  Could not copy cert to disk. You'll need to copy manually." -ForegroundColor Yellow
        }
    } else {
        # Linux
        $copyScript = @"
if (mount | grep /mnt/keys) {
    cp '$($kecDERFile)' /mnt/keys/
    echo "KEK_COPIED:/mnt/keys/KEK-2023.der"
} else {
    echo "KEK_STATUS:DISK_NOT_MOUNTED"
}
"@
        try {
            $copyResult = Invoke-VMScript -VM $vm -ScriptText $copyScript `
                -GuestUser "root" -GuestPassword $GuestPass -ErrorAction Stop
            Write-Host "  KEK cert copied to disk." -ForegroundColor Green
        } catch {
            Write-Log "  Copy failed: $_" "WARN"
        }
    }
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
Write-Host "    ✓ KEK-2023 cert downloaded: $kecDERFile" -ForegroundColor Green
Write-Host "    ✓ 128MB disk attached" -ForegroundColor Green
Write-Host "    ✓ uefi.allowAuthBypass = TRUE" -ForegroundColor Green
Write-Host "    ✓ Force EFI Setup enabled" -ForegroundColor Green
Write-Host "    ✓ VM booted" -ForegroundColor Green
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor White
Write-Host "    1. Enter EFI Setup (F2 at boot)" -ForegroundColor Cyan
Write-Host "    2. Navigate to: Secure Boot Configuration → KEK Options → Enroll KEK" -ForegroundColor Cyan
Write-Host "    3. Select KEK-2023.der from the attached disk" -ForegroundColor Cyan
Write-Host "    4. Review and Commit changes" -ForegroundColor Cyan
Write-Host "    5. Exit EFI Setup and reboot" -ForegroundColor Cyan
Write-Host ""
Write-Host "  After KEK update:" -ForegroundColor White
Write-Host "    - Run Windows Update on the guest to apply new DB/DBX certs" -ForegroundColor Cyan
Write-Host "    - Verify: Get-SecureBootUEFI KEK" -ForegroundColor Cyan
Write-Host "    - Remove uefi.allowAuthBypass and Force EFI Setup after completion" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Log: $script:Log" -ForegroundColor White
Write-Host ""
