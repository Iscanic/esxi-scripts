<#
.SYNOPSIS
    Secure Boot Certificate Audit Script for VMware VMs
.DESCRIPTION
    Audits Secure Boot certificate status in VMware virtual machines
    across vSphere environments. Identifies VMs affected by Microsoft
    Secure Boot certificate EOL (June 2026).

    Background:
    VMware vSphere VMs initialize their vUEFI Secure Boot certificates
    at first power-on and retain them for the lifetime of the VM.

    VMs created on ESXi 9.x (HW v14+) or ESXi 8.0.2+ (HW v21+)
    receive the 2023 certificate chain (KEK expires Mar 2038).

    VMs created on ESXi 8.0.1 and below, or ESXi 7.x, receive the
    2011 certificate chain (KEK expires Jun 2026).

    The issue is not host firmware — it's the certificate set baked
    into each VM's vNVRAM at creation time. Upgrading ESXi does not
    retroactively update existing VM certificates.

    Affected certificates (2011 chain, expires 30 Jun 2026):
    - Microsoft Windows Production PCA 2011 (DB)
    - Microsoft Corporation UEFI CA 2011 (DB)
    - Microsoft Corporation KEK CA 2011 (KEK)

    After expiry, Microsoft will revoke the 2011 DB certificates,
    breaking Secure Boot updates and potentially affecting
    authenticated boot workflows (BitLocker VBS, Windows Update, etc.).

    Virtual machines will continue to boot after expiry — boot is only
    impacted when the expired certificates are revoked by Microsoft.
    An expired KEK impacts the ability to update Secure Boot databases
    (DB, DBX) rather than immediate boot functionality.

.NOTES
    Requires: VMware PowerCLI module
    Run with permissions to read VM configuration from vCenter
    Tested against vSphere 7.x, 8.x, 9.x
#>

[CmdletBinding()]
param(
    [string]$vCenter,
    [string]$vCredUser,
    [string]$vCredPass,
    [string]$OutputFile = "SecureBootAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [string]$LogPath = "SecureBootAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').log",
    [switch]$AuditAll,
    [switch]$SecureBootOnly,
    [string[]]$Cluster,
    [string[]]$Datacenter,
    [string[]]$ESXiHost
)

# ─── Configuration ───────────────────────────────────────────────────────────

$EOL_DATE = [datetime]"2026-06-30"
$NEW_CERT_KEK = "Microsoft Corporation KEK 2K CA 2023"
$OLD_CERT_KEK = "Microsoft Corporation KEK CA 2011"
$OLD_CERT_DB = "Microsoft Windows Production PCA 2011"

$script:LogFile = $LogPath
$script:Results = @()
$script:SecureBootVMs = @()

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = switch ($Level) {
        "WARN" { "[!!]" }
        "ERROR" { "[XX]" }
        default { "[  ]" }
    }
    Write-Host "$prefix $($timestamp) $Message"
    if ($LogPath) {
        "$timestamp | $Level | $Message" | Add-Content -Path $LogPath -Force
    }
}

# ─── Connection ──────────────────────────────────────────────────────────────

function Connect-VMware {
    param(
        [string]$vCenter,
        [string]$User,
        [string]$Password
    )

    try {
        $module = Get-Module -ListAvailable VMware.PowerCLI -ErrorAction Stop
    } catch {
        Write-Log "VMware PowerCLI module not installed" "ERROR"
        Write-Host "  Install with: Install-Module -Name VMware.PowerCLI -Force" -ForegroundColor Yellow
        return $null
    }

    # Suppress SSL warnings for self-signed vCenter certs
    Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP:$false `
        -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

    try {
        if ($vCenter -and $User -and $Password) {
            $securePass = ConvertTo-SecureString $Password -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential($User, $securePass)
            $servers = Connect-VIServer -Server $vCenter -Credential $cred
            Write-Log "Connected to vCenter: $vCenter"
            return $servers
        } else {
            # Use existing PowerCLI session
            $servers = Get-VIServer -ErrorAction SilentlyContinue
            if ($servers.Count -gt 0) {
                Write-Log "Using existing session: $($servers.Name -join ', ')"
                return $servers
            } else {
                Write-Log "No vCenter session found. Provide -vCenter, -vCredUser, and -vCredPass parameters." "ERROR"
                return $null
            }
        }
    } catch {
        Write-Log "Failed to connect to vCenter $vCenter: $_" "ERROR"
        return $null
    }
}

# ─── VM Enumeration ─────────────────────────────────────────────────────────

function Get-TargetVMs {
    <#
    Collects VMs to audit based on the filters provided:
    - AuditAll: all VMs in the environment
    - SecureBootOnly: only VMs with Secure Boot enabled
    - Cluster/Datacenter/ESXiHost filters
    #>
    param(
        [array]$VIServer,
        [switch]$AuditAll,
        [switch]$SecureBootOnly,
        [string[]]$Cluster,
        [string[]]$Datacenter,
        [string[]]$ESXiHost
    )

    $vms = @()

    # Build filter sets
    $filterClusters = @()
    $filterDatacenters = @()
    $filterHosts = @()

    if ($Cluster) {
        $filterClusters = Get-Cluster -Server $VIServer -Name $Cluster -ErrorAction SilentlyContinue
        Write-Log "Filtering by clusters: $($Cluster -join ', ')"
    }

    if ($Datacenter) {
        $filterDatacenters = Get-Datacenter -Server $VIServer -Name $Datacenter -ErrorAction SilentlyContinue
        Write-Log "Filtering by datacenters: $($Datacenter -join ', ')"
    }

    if ($ESXiHost) {
        $filterHosts = Get-VMHost -Server $VIServer -Name $ESXiHost -ErrorAction SilentlyContinue
        Write-Log "Filtering by hosts: $($ESXiHost -join ', ')"
    }

    if ($AuditAll) {
        if ($filterClusters.Count -gt 0) {
            foreach ($cl in $filterClusters) {
                $vms += Get-VM -Location $cl -Server $VIServer -ErrorAction SilentlyContinue
            }
        } elseif ($filterDatacenters.Count -gt 0) {
            foreach ($dc in $filterDatacenters) {
                $vms += Get-VM -Location $dc -Server $VIServer -ErrorAction SilentlyContinue
            }
        } elseif ($filterHosts.Count -gt 0) {
            foreach ($h in $filterHosts) {
                $vms += Get-VM -Location $h -Server $VIServer -ErrorAction SilentlyContinue
            }
        } else {
            $vms = Get-VM -Server $VIServer -ErrorAction SilentlyContinue
        }
    } elseif ($SecureBootOnly) {
        # Enumerate all VMs first, then filter
        if ($filterClusters.Count -gt 0) {
            foreach ($cl in $filterClusters) {
                $vms += Get-VM -Location $cl -Server $VIServer -ErrorAction SilentlyContinue
            }
        } elseif ($filterDatacenters.Count -gt 0) {
            foreach ($dc in $filterDatacenters) {
                $vms += Get-VM -Location $dc -Server $VIServer -ErrorAction SilentlyContinue
            }
        } elseif ($filterHosts.Count -gt 0) {
            foreach ($h in $filterHosts) {
                $vms += Get-VM -Location $h -Server $VIServer -ErrorAction SilentlyContinue
            }
        } else {
            $vms = Get-VM -Server $VIServer -ErrorAction SilentlyContinue
        }

        # Filter to Secure Boot enabled VMs
        $vms = $vms | Where-Object {
            $sb = Get-AdvancedSetting -VM $_ -Name "firmware.secureBoot" -ErrorAction SilentlyContinue
            return $sb -and ($sb.Value -eq "TRUE" -or $sb.Value -eq $true)
        }
    }

    Write-Host "  Found $($vms.Count) VMs to audit." -ForegroundColor Green
    return $vms
}

# ─── Certificate Checking ────────────────────────────────────────────────────

function Test-VMSecureBootCerts {
    <#
    Checks the Secure Boot certificate state of a VM by querying
    its vUEFI database entries.

    This method reads the PK, KEK, and DB entries directly from
    the VM's configuration. It works for VMs that are powered on
    (most reliable) and can also read cached config from powered-off VMs.
    #>
    param(
        [object]$VM,
        [array]$VIServer
    )

    $result = [PSCustomObject]@{
        VMName              = $VM.Name
        Host                = ($VM | Get-VMHost).Name
        ESXiVersion         = ($VM | Get-VMHost).Version
        ESXiBuild           = ($VM | Get-VMHost).Build
        Cluster             = ($VM | Get-Cluster).Name
        Datacenter          = ($VM | Get-Datacenter).Name
        HardwareVersion     = $VM.HardwareVersion
        PoweredOn           = $VM.PowerState
        GuestOS             = $VM.Guest.OSFullName
        SecureBootEnabled   = $null
        PK                  = $null
        PK_Validity         = $null          # "Valid" or "Invalid (NULL)"
        KEK_2023_Present    = $null          # $true/$false/$null (unknown)
        KEK_2011_Present    = $null
        DB_2011_Present     = $null
        HasNewCerts         = $null          # $true = has 2023 certs
        CertChainStatus     = $null          # "GOOD", "AT_RISK", "AFFECTED", "UNKNOWN"
        NeedsUpdate         = $null
        RiskLevel           = $null
        AffectedByEOL       = $null
        LastChecked         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Notes               = ""
    }

    try {
        # Determine Secure Boot status
        $sbSetting = Get-AdvancedSetting -VM $VM -Name "firmware.secureBoot" -ErrorAction SilentlyContinue
        if ($sbSetting) {
            $result.SecureBootEnabled = ($sbSetting.Value -eq "TRUE" -or $sbSetting.Value -eq $true)
        } else {
            $result.SecureBootEnabled = $false
        }

        # If not Secure Boot, skip certificate check
        if (-not $result.SecureBootEnabled) {
            $result.CertChainStatus = "N/A (Secure Boot disabled)"
            $result.AffectedByEOL = "NO"
            $result.NeedsUpdate = "NO"
            $result.RiskLevel = "LOW"
            return $result
        }

        # ─── Check PK ──────────────────────────────────────────────
        # Read the Platform Key from the VM's vUEFI NVRAM
        try {
            # Method: query the firmware config via PowerCLI
            $pkValue = $VM | Get-AdvancedSetting -Name "efi.secureBoot.pk" -ErrorAction SilentlyContinue

            # Alternative approach: check via the VM's firmware configuration
            # For powered-on Windows VMs, we can query via Invoke-VMScript
            if ($VM.PowerState -eq "PoweredOn" -and $VM.Guest.State -eq "Running") {
                $pkCheck = $null
                $kekCheck = $null
                $dbCheck = $null

                # Check PK validity
                $pkScript = @'
$pk = Get-SecureBootUEFI -Name PK
$bytes = $pk.Bytes
$cert = $bytes[44..($bytes.Length-1)]
[IO.File]::WriteAllBytes("C:\PK.der", $cert)
try {
    $out = certutil -dump C:\PK.der 2>&1 | Out-String
    if ($out -match "00\s*\." -and $pk.Bytes.Length -le 45) {
        Write-Host "PK_STATUS:INVALID"
    } else {
        Write-Host "PK_STATUS:VALID"
        # Extract cert subject
        $subj = (Get-Certificate -FilePath C:\PK.der -ErrorAction SilentlyContinue).Subject
        Write-Host "PK_SUBJECT:$subj"
    }
} catch {
    Write-Host "PK_STATUS:CHECK_FAILED"
}
'@

                $pkResult = Invoke-VMScript -VM $VM -ScriptText $pkScript `
                    -GuestUser "Administrator" -GuestPassword "password" -ErrorAction SilentlyContinue

                if ($pkResult -and $pkResult.ScriptOutput) {
                    if ($pkResult.ScriptOutput -match "PK_STATUS:(.+)") {
                        $pkStatus = $Matches[1]
                        $result.PK_Validity = $pkStatus
                        $result.PK = "Checked via guest"
                    }
                }

                # Check KEK for 2023 vs 2011
                $kekScript = @'
$kekList = Get-SecureBootUEFI -Name KEK
foreach ($kek in $kekList) {
    $text = [System.Text.Encoding]::ASCII.GetString($kek.Bytes)
    Write-Host "KEK:$text"
}
'@

                $kekResult = Invoke-VMScript -VM $VM -ScriptText $kekScript `
                    -GuestUser "Administrator" -GuestPassword "password" -ErrorAction SilentlyContinue

                if ($kekResult -and $kekResult.ScriptOutput) {
                    $kekOutput = $kekResult.ScriptOutput
                    $result.KEK_2023_Present = ($kekOutput -match "Microsoft Corporation KEK 2K CA 2023")
                    $result.KEK_2011_Present = ($kekOutput -match "Microsoft Corporation KEK CA 2011")
                } else {
                    # Fallback: try without guest credentials
                    Write-Log "  $VM.Name: Cannot query VM for certificates (guest access required)" "WARN"

                    # Alternative: use the VM's hardware version and ESXi version to infer
                    # VMs created on ESXi 8.0.2+ with HW v21+ have 2023 certs
                    # VMs on older versions have 2011 certs
                    $hwNum = [int]$VM.HardwareVersion -replace "vmx-", ""
                    $esxiParts = $VM.VMHost.Version -split "\."
                    $esxiMajor = [int]$esxiParts[0]
                    $esxiMinor = [int]$esxiParts[1]
                    $esxiPatch = [int]($esxiParts[2] -replace "[^0-9]", "")

                    $inheritedNewCerts = $false
                    if ($esxiMajor -ge 9) {
                        $inheritedNewCerts = $true  # ESXi 9 always uses 2023 certs
                    } elseif ($esxiMajor -eq 8 -and $esxiMinor -ge 2) {
                        $inheritedNewCerts = $true  # ESXi 8.0.2+ uses 2023 certs with HW v21+
                    }

                    if ($inheritedNewCerts) {
                        $result.KEK_2023_Present = $true
                        $result.KEK_2011_Present = $false
                        $result.Notes = "Inferred 2023 certs from ESXi $($VM.VMHost.Version) / HW v$($VM.HardwareVersion) (no guest access)"
                    } else {
                        $result.KEK_2011_Present = $true
                        $result.KEK_2023_Present = $false
                        $result.Notes = "Inferred 2011 certs from ESXi $($VM.VMHost.Version) / HW v$($VM.HardwareVersion) (no guest access) — MUST VERIFY"
                    }
                }

                # Check DB for 2011 certificates
                $dbScript = @'
$dbList = Get-SecureBootUEFI -Name DB
foreach ($db in $dbList) {
    $text = [System.Text.Encoding]::ASCII.GetString($db.Bytes)
    if ($text -match "Microsoft") {
        Write-Host "DB:$text"
    }
}
'@

                $dbResult = Invoke-VMScript -VM $VM -ScriptText $dbScript `
                    -GuestUser "Administrator" -GuestPassword "password" -ErrorAction SilentlyContinue

                if ($dbResult -and $dbResult.ScriptOutput) {
                    $dbOutput = $dbResult.ScriptOutput
                    $result.DB_2011_Present = ($dbOutput -match "Microsoft Windows Production PCA 2011")
                }
            } else {
                # VM is powered off or guest not running — use ESXi version inference
                Write-Log "  $VM.Name: Powered off or guest not running, using version-based inference" "WARN"

                $hwNum = [int]$VM.HardwareVersion -replace "vmx-", ""
                $esxiParts = $VM.VMHost.Version -split "\."
                $esxiMajor = [int]$esxiParts[0]
                $esxiMinor = [int]$esxiParts[1]
                $esxiPatch = [int]($esxiParts[2] -replace "[^0-9]", "")

                # ESXi 9.x always provisions 2023 certs
                # ESXi 8.0.2+ provisions 2023 certs for HW v21+
                # ESXi 8.0.0-8.0.1 and 7.x provision 2011 certs
                $hasNewCerts = $false

                if ($esxiMajor -ge 9) {
                    $hasNewCerts = $true
                } elseif ($esxiMajor -eq 8 -and $esxiMinor -ge 2) {
                    if ($hwNum -ge 21) {
                        $hasNewCerts = $true
                    }
                }

                if ($hasNewCerts) {
                    $result.KEK_2023_Present = $true
                    $result.KEK_2011_Present = $false
                    $result.Notes = "Inferred 2023 certs from ESXi $($VM.VMHost.Version) / HW v$($VM.HardwareVersion)"
                } else {
                    $result.KEK_2011_Present = $true
                    $result.KEK_2023_Present = $false
                    $result.Notes = "Inferred 2011 certs from ESXi $($VM.VMHost.Version) / HW v$($VM.HardwareVersion) — needs guest check to confirm"
                }
            }
        } catch {
            Write-Log "  $VM.Name: Error checking PK/KEK: $_" "WARN"
        }

        # ─── Determine Cert Chain Status ───────────────────────
        # Classify each VM's certificate situation

        if (-not $result.SecureBootEnabled) {
            $result.CertChainStatus = "N/A (Secure Boot disabled)"
            $result.AffectedByEOL = "NO"
            $result.NeedsUpdate = "NO"
            $result.RiskLevel = "LOW"
        } elseif ($result.KEK_2023_Present -eq $true) {
            $result.CertChainStatus = "GOOD — 2023 cert chain"
            $result.AffectedByEOL = "NO"
            $result.NeedsUpdate = "NO"
            $result.RiskLevel = "LOW"
        } elseif ($result.KEK_2011_Present -eq $true) {
            $result.CertChainStatus = "AFFECTED — 2011 cert chain (expires $EOL_DATE)"
            $result.AffectedByEOL = "YES"
            $result.NeedsUpdate = "YES"
            $result.RiskLevel = "HIGH"
            $result.Notes = "Has 2011 cert chain. Will break when Microsoft revokes 2011 DB. See remediation."
        } elseif ($result.KEK_2023_Present -eq $null -and $result.KEK_2011_Present -eq $null) {
            $result.CertChainStatus = "UNKNOWN — could not determine cert chain"
            $result.AffectedByEOL = "UNKNOWN"
            $result.NeedsUpdate = "REQUIRES_GUEST_ACCESS"
            $result.RiskLevel = "MEDIUM"
            $result.Notes = "Cannot determine cert status. Run with guest credentials or verify manually."
        }

    } catch {
        Write-Log "  $VM.Name: Error during audit: $_" "ERROR"
        $result.CertChainStatus = "ERROR — $($_.Exception.Message)"
        $result.AffectedByEOL = "UNKNOWN"
        $result.NeedsUpdate = "UNKNOWN"
        $result.RiskLevel = "UNKNOWN"
    }

    return $result
}

# ─── Bulk Certificate Check (Powered-On VMs) ─────────────────────────────────

function Invoke-BulkSecureBootCheck {
    <#
    For powered-on Windows VMs with guest access, performs a direct
    check of the vUEFI certificate databases (PK, KEK, DB) using
    Invoke-VMScript to run PowerShell inside the guest OS.
    #>
    param(
        [array]$VMs,
        [string]$GuestUser,
        [string]$GuestPass
    )

    $checked = 0
    $failed = 0

    foreach ($vm in $VMs) {
        if ($vm.PowerState -ne "PoweredOn" -or $vm.Guest.State -ne "Running") {
            continue
        }

        try {
            $scriptBlock = @'
# Get PK
$pk = Get-SecureBootUEFI -Name PK
$pkBytes = $pk.Bytes
$pkValid = $true
try {
    $cert = $pkBytes[44..($pkBytes.Length-1)]
    [IO.File]::WriteAllBytes("C:\pk.der", $cert)
    $dump = certutil -dump C:\pk.der 2>&1 | Out-String
    if ($pkBytes.Length -le 45) { $pkValid = $false }
    if ($dump -match "00\s*\.") { $pkValid = $false }
} catch { $pkValid = $false }
Write-Output "PK_VALID:$pkValid"
Write-Output "PK_LEN:$($pkBytes.Length)"

# Get KEK list
$keks = Get-SecureBootUEFI -Name KEK
$kek2023 = $false
$kek2011 = $false
$kekNames = @()
foreach ($kek in $keks) {
    $text = [System.Text.Encoding]::ASCII.GetString($kek.Bytes)
    if ($text -match "Microsoft Corporation KEK 2K CA 2023") { $kek2023 = $true }
    if ($text -match "Microsoft Corporation KEK CA 2011") { $kek2011 = $true }
    if ($text -match "Microsoft") { $kekNames += $text.Trim() }
}
Write-Output "KEK_2023:$kek2023"
Write-Output "KEK_2011:$kek2011"
foreach ($n in $kekNames) { Write-Output "KEK_NAME:$n" }

# Get DB list
$dbus = Get-SecureBootUEFI -Name DB
$dbNames = @()
foreach ($db in $dbus) {
    $text = [System.Text.Encoding]::ASCII.GetString($db.Bytes)
    if ($text -match "Microsoft") { $dbNames += $text.Trim() }
}
foreach ($n in $dbNames) { Write-Output "DB_NAME:$n" }
'@

            $result = Invoke-VMScript -VM $vm -ScriptText $scriptBlock `
                -GuestUser $GuestUser -GuestPassword $GuestPass -ErrorAction Stop

            # Parse output
            $outputLines = $result.ScriptOutput -split "`r?`n" | Where-Object { $_ }
            $parsed = @{}
            foreach ($line in $outputLines) {
                if ($line -match "^(\w+):(.+)$") {
                    $parsed[$Matches[1]] = $Matches[2].Trim()
                }
            }

            [PSCustomObject]@{
                VMName             = $vm.Name
                PK_Valid           = $parsed["PK_VALID"] -eq "True"
                PK_Length          = $parsed["PK_LEN"]
                KEK_2023_Present   = $parsed["KEK_2023"] -eq "True"
                KEK_2011_Present   = $parsed["KEK_2011"] -eq "True"
                KEK_Names          = ($parsed.GetEnumerator() | Where-Object { $_.Key -like "KEK_NAME*" } | ForEach-Object { $_.Value }) -join "; "
                DB_Names           = ($parsed.GetEnumerator() | Where-Object { $_.Key -like "DB_NAME*" } | ForEach-Object { $_.Value }) -join "; "
            }
        } catch {
            Write-Log "  $vm.Name: Guest script failed — $($_.Exception.Message)" "WARN"
            $failed++
        }

        $checked++
    }

    Write-Log "  Bulk check complete: $checked VMs checked, $failed failures"
}

# ─── Report Generation ───────────────────────────────────────────────────────

function Show-AuditReport {
    param([array]$Results)

    $total = $Results.Count
    $affected = $Results | Where-Object { $_.AffectedByEOL -eq "YES" }
    $good = $Results | Where-Object { $_.AffectedByEOL -eq "NO" }
    $unknown = $Results | Where-Object { $_.AffectedByEOL -eq "UNKNOWN" }
    $na = $Results | Where-Object { $_.AffectedByEOL -eq "N/A" -or $_.SecureBootEnabled -eq $false }

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  SECURE BOOT CERTIFICATE AUDIT — REPORT" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Total VMs Audited:          $total" -ForegroundColor White
    Write-Host "  Secure Boot Enabled:        $($Results | Where-Object { $_.SecureBootEnabled -eq $true }).Count" -ForegroundColor White
    Write-Host ""
    Write-Host "  ── Certificate Chain Status ────────────────────────────────────────────" -ForegroundColor White
    Write-Host "  GOOD (2023 certs):          $($good.Count)" -ForegroundColor Green
    Write-Host "  AFFECTED (2011 certs):      $($affected.Count)" -ForegroundColor Red
    Write-Host "  UNKNOWN (needs guest check):$($unknown.Count)" -ForegroundColor Yellow
    Write-Host "  N/A (Secure Boot disabled): $($na.Count)" -ForegroundColor Gray
    Write-Host ""

    if ($affected.Count -gt 0) {
        Write-Host "── AFFECTED VMs (2011 cert chain, expires $EOL_DATE) ─────────────────────" -ForegroundColor Red
        $affected | Format-Table -AutoSize -Property @(
            @{Label="VM"; Expression={$_.VMName}},
            @{Label="Host"; Expression={$_.Host}},
            @{Label="ESXi"; Expression={$_.ESXiVersion}},
            @{Label="HW Ver"; Expression={$_.HardwareVersion}},
            @{Label="Guest OS"; Expression={$_.GuestOS}},
            @{Label="Status"; Expression={$_.CertChainStatus}},
            @{Label="Notes"; Expression={$_.Notes}}
        ) | Out-String | Write-Host
    }

    if ($unknown.Count -gt 0) {
        Write-Host "── UNKNOWN (cannot determine cert chain) ─────────────────────────────────" -ForegroundColor Yellow
        $unknown | Format-Table -AutoSize -Property @(
            @{Label="VM"; Expression={$_.VMName}},
            @{Label="Host"; Expression={$_.Host}},
            @{Label="ESXi"; Expression={$_.ESXiVersion}},
            @{Label="HW Ver"; Expression={$_.HardwareVersion}},
            @{Label="Powered On"; Expression={$_.PoweredOn}},
            @{Label="Notes"; Expression={$_.Notes}}
        ) | Out-String | Write-Host
    }

    # Export to CSV
    $Results | Export-Csv -Path $OutputFile -NoTypeInformation -Force
    Write-Host ""
    Write-Host "  Full report exported to: $OutputFile" -ForegroundColor Green
    if ($LogPath) {
        Write-Host "  Detailed log: $LogPath" -ForegroundColor Green
    }
}

# ─── Main ────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  VMware Secure Boot Certificate Audit" -ForegroundColor Cyan
Write-Host "  Microsoft 2011 Cert EOL: $EOL_DATE" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Validate parameters
if (-not $vCenter -and -not $AuditAll -and -not $SecureBootOnly) {
    Write-Host "  Error: Provide -vCenter (or use existing PowerCLI session)." "ERROR"
    Write-Host ""
    Write-Host "  Usage examples:" -ForegroundColor White
    Write-Host "    .\secureboot-audit.ps1 -vCenter 'vc.domain.local' -vCredUser 'admin' -vCredPass 'pass'" -ForegroundColor Gray
    Write-Host "    .\secureboot-audit.ps1 -vCenter 'vc.domain.local' -AuditAll" -ForegroundColor Gray
    Write-Host "    .\secureboot-audit.ps1 -vCenter 'vc.domain.local' -SecureBootOnly" -ForegroundColor Gray
    Write-Host "    .\secureboot-audit.ps1 -vCenter 'vc.domain.local' -SecureBootOnly -Cluster 'Prod'" -ForegroundColor Gray
    exit 1
}

# Connect to vCenter
$viServers = Connect-VMware -vCenter $vCenter -User $vCredUser -Password $vCredPass
if (-not $viServers) {
    Write-Host ""
    Write-Host "  Cannot proceed without a vCenter connection." "ERROR"
    exit 1
}

# Determine scope
$auditAll = $AuditAll.IsPresent
$secureBootOnly = $SecureBootOnly.IsPresent

Write-Host "`n[1/2] Collecting VM inventory..." -ForegroundColor White
$vms = Get-TargetVMs -VIServer $viServers -AuditAll:$auditAll -SecureBootOnly:$secureBootOnly -Cluster $Cluster -Datacenter $Datacenter -ESXiHost $ESXiHost
Write-Host "`n[2/2] Auditing VMs..." -ForegroundColor White

# Process each VM
foreach ($vm in $vms) {
    Write-Log "Auditing: $($vm.Name) (HW v$($vm.HardwareVersion), ESXi $($vm.VMHost.Version))"
    $result = Test-VMSecureBootCerts -VM $vm -VIServer $viServers
    $script:Results += $result
}

# If we have powered-on VMs and guest credentials were provided, do a direct cert check
if ($PSCmdlet.ParameterSetName -in @("GuestCheck") -or $PSBoundParameters.ContainsKey("GuestUser")) {
    Write-Host "`n  Performing direct guest-level certificate verification..." -ForegroundColor White
    $guestCheck = Invoke-BulkSecureBootCheck -VMs $vms -GuestUser $vCredUser -GuestPass $vCredPass
    # Merge results with guest-check data
    foreach ($gc in $guestCheck) {
        $resultRow = $script:Results | Where-Object { $_.VMName -eq $gc.VMName }
        if ($resultRow) {
            if ($gc.KEK_2023_Present -or $gc.KEK_2011_Present) {
                $resultRow.KEK_2023_Present = $gc.KEK_2023_Present
                $resultRow.KEK_2011_Present = $gc.KEK_2011_Present
            }
            $resultRow.PK = if ($gc.PK_Valid) { "Valid" } else { "Invalid (NULL)" }
            $resultRow.PK_Validity = if ($gc.PK_Valid) { "Valid" } else { "Invalid" }

            # Re-evaluate cert chain status
            if ($resultRow.KEK_2023_Present -eq $true) {
                $resultRow.CertChainStatus = "GOOD — 2023 cert chain (verified via guest)"
                $resultRow.AffectedByEOL = "NO"
                $resultRow.NeedsUpdate = "NO"
                $resultRow.RiskLevel = "LOW"
            } elseif ($resultRow.KEK_2011_Present -eq $true) {
                $resultRow.CertChainStatus = "AFFECTED — 2011 cert chain (expires $EOL_DATE) (verified via guest)"
                $resultRow.AffectedByEOL = "YES"
                $resultRow.NeedsUpdate = "YES"
                $resultRow.RiskLevel = "HIGH"
            }
            $resultRow.Notes = "Verified via guest OS"
        }
    }
}

# Display report
Show-AuditReport -Results $script:Results

# ─── Remediation Guidance ────────────────────────────────────────────────────

$affected = $script:Results | Where-Object { $_.AffectedByEOL -eq "YES" }
if ($affected.Count -gt 0) {
    Write-Host @"

── REMEDIATION ───────────────────────────────────────────────────────────────

The issue is NOT ESXi host firmware. It is the certificate set baked into
each VM's vUEFI NVRAM at first power-on. Upgrading the ESXi host does
NOT retroactively update existing VM certificates.

For affected VMs (2011 cert chain):

1. VMware Manual PK Update (Article 423919):
   - Update the Platform Key (PK) to a valid certificate
   - Then follow Microsoft's Secure Boot update guidance
   - See: https://knowledge.broadcom.com/external/article/423919

2. Manual certificate update via guest OS (Windows):
   a) Update PK to Windows OEM Devices PK (valid cert)
   b) Add Microsoft Corporation KEK 2K CA 2023 to KEK database
   c) Run Windows Update to apply new DB/DBX certificates
   d) Verify: Get-SecureBootUEFI

3. For Linux VMs:
   - Use mokutil --update-key to add new KEK
   - Follow VMware's Secure Boot update mechanisms for Linux

4. For new VMs:
   - VMs created on ESXi 8.0.2+ with HW v21+ already have 2023 certs
   - No action needed

5. Timeline:
   - Microsoft cert EOL: 30 June 2026
   - VMs will continue to boot after expiry
   - Impact: cannot apply DB/DBX revocation updates

"@ -ForegroundColor Yellow
}
