<#
.SYNOPSIS
    System hardening and security configuration checks
.DESCRIPTION
    Checks:
    - User Account Control (UAC)
    - Secure Boot status
    - TPM (Trusted Platform Module)
    - BitLocker encryption
    - Windows Update settings
    - Remote Desktop configuration
#>

using module .\Core.psm1

function Invoke-SystemHardeningAudit {
    <#
    .SYNOPSIS
        Performs system hardening security checks
    .PARAMETER Config
        Configuration object from Config.psd1
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )
    
    Write-AuditHeader "System Hardening & Configuration"
    
    # === UAC (User Account Control) ===
    Test-UAC
    
    # === Secure Boot ===
    Test-SecureBoot
    
    # === TPM ===
    Test-TPM
    
    # === BitLocker ===
    Test-BitLocker
    
    # === Windows Update ===
    Test-WindowsUpdate -Config $Config
    
    # === Remote Desktop ===
    Test-RemoteDesktop
    
    # === Administrator Account ===
    Test-AdminAccount
}

function Test-UAC {
    Write-Host "Checking User Account Control (UAC)..." -ForegroundColor Cyan
    
    try {
        $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name EnableLUA -ErrorAction Stop
        
        if ($uac.EnableLUA -eq 1) {
            Write-AuditResult "UAC" "Enabled" -Status Pass
            
            Add-AuditFinding `
                -Id "SysHard_UAC" `
                -Title "User Account Control" `
                -Value "Enabled" `
                -Severity 1 `
                -Category "SystemHardening"
        }
        else {
            Write-AuditResult "UAC" "DISABLED" -Status Fail
            
            Add-AuditFinding `
                -Id "SysHard_UAC" `
                -Title "User Account Control" `
                -Value "Disabled" `
                -Severity 0 `
                -Weight 25 `
                -Notes "UAC is disabled. This is a critical security risk. Attackers can gain full system access without prompts." `
                -Category "SystemHardening"
        }
    }
    catch {
        Write-AuditResult "UAC" "Unable to determine" -Status Warn
        
        Add-AuditFinding `
            -Id "SysHard_UAC" `
            -Title "User Account Control" `
            -Value "Unknown" `
            -Severity 2 `
            -Category "SystemHardening"
    }
}

function Test-SecureBoot {
    Write-Host "Checking Secure Boot..." -ForegroundColor Cyan
    
    $secureBoot = Invoke-SafeCommand { Confirm-SecureBootUEFI }
    
    if ($secureBoot -eq $true) {
        Write-AuditResult "Secure Boot" "Enabled" -Status Pass
        
        Add-AuditFinding `
            -Id "SysHard_SecureBoot" `
            -Title "Secure Boot" `
            -Value "Enabled" `
            -Severity 1 `
            -Category "SystemHardening"
    }
    elseif ($secureBoot -eq $false) {
        Write-AuditResult "Secure Boot" "Disabled or Legacy BIOS" -Status Warn
        
        Add-AuditFinding `
            -Id "SysHard_SecureBoot" `
            -Title "Secure Boot" `
            -Value "Disabled/Legacy" `
            -Severity 2 `
            -Notes "Secure Boot helps prevent rootkits and boot-level malware. Enable if supported by hardware." `
            -Category "SystemHardening"
    }
    else {
        Write-AuditResult "Secure Boot" "Unknown/Not Supported" -Status Info
        
        Add-AuditFinding `
            -Id "SysHard_SecureBoot" `
            -Title "Secure Boot" `
            -Value "Unknown" `
            -Severity 3 `
            -Category "SystemHardening"
    }
}

function Test-TPM {
    Write-Host "Checking TPM (Trusted Platform Module)..." -ForegroundColor Cyan
    
    $tpm = Invoke-SafeCommand { Get-Tpm }
    
    if ($tpm) {
        if ($tpm.TpmPresent -and $tpm.TpmReady) {
            Write-AuditResult "TPM" "Present & Ready" -Status Pass
            
            Add-AuditFinding `
                -Id "SysHard_TPM" `
                -Title "TPM Module" `
                -Value "Present & Ready (Version: $($tpm.ManufacturerVersion))" `
                -Severity 1 `
                -Category "SystemHardening"
        }
        elseif ($tpm.TpmPresent -and -not $tpm.TpmReady) {
            Write-AuditResult "TPM" "Present but NOT Ready" -Status Warn
            
            Add-AuditFinding `
                -Id "SysHard_TPM" `
                -Title "TPM Module" `
                -Value "Present but not ready" `
                -Severity 2 `
                -Notes "TPM is present but not initialized. Initialize TPM in BIOS/UEFI." `
                -Category "SystemHardening"
        }
        else {
            Write-AuditResult "TPM" "Not Present" -Status Warn
            
            Add-AuditFinding `
                -Id "SysHard_TPM" `
                -Title "TPM Module" `
                -Value "Not Present" `
                -Severity 2 `
                -Notes "TPM provides hardware-based security. Modern systems should have TPM 2.0." `
                -Category "SystemHardening"
        }
    }
    else {
        Write-AuditResult "TPM" "Query Failed" -Status Info
        
        Add-AuditFinding `
            -Id "SysHard_TPM" `
            -Title "TPM Module" `
            -Value "Unknown" `
            -Severity 3 `
            -Category "SystemHardening"
    }
}

function Test-BitLocker {
    Write-Host "Checking BitLocker encryption..." -ForegroundColor Cyan
    
    $volumes = Invoke-SafeCommand { Get-BitLockerVolume }
    
    if (-not $volumes) {
        Write-AuditResult "BitLocker" "Not available or not configured" -Status Info
        
        Add-AuditFinding `
            -Id "SysHard_BitLocker" `
            -Title "BitLocker Encryption" `
            -Value "Not configured" `
            -Severity 3 `
            -Notes "BitLocker provides full-disk encryption. Recommended for laptops and sensitive data." `
            -Category "SystemHardening"
        return
    }
    
    $encryptedVolumes = 0
    $unencryptedVolumes = 0
    
    foreach ($vol in $volumes) {
        if ($vol.ProtectionStatus -eq 'On') {
            $encryptedVolumes++
            Write-AuditResult "BitLocker $($vol.MountPoint)" "Encrypted (Protected)" -Status Pass
        }
        else {
            $unencryptedVolumes++
            Write-AuditResult "BitLocker $($vol.MountPoint)" "Not Encrypted" -Status Warn
        }
    }
    
    if ($unencryptedVolumes -gt 0) {
        Add-AuditFinding `
            -Id "SysHard_BitLocker" `
            -Title "BitLocker Encryption" `
            -Value "$unencryptedVolumes volume(s) unencrypted" `
            -Severity 2 `
            -Notes "Enable BitLocker to protect data if device is lost or stolen." `
            -Category "SystemHardening"
    }
    else {
        Add-AuditFinding `
            -Id "SysHard_BitLocker" `
            -Title "BitLocker Encryption" `
            -Value "All volumes encrypted" `
            -Severity 1 `
            -Category "SystemHardening"
    }
}

function Test-WindowsUpdate {
    param([hashtable]$Config)
    
    Write-Host "Checking Windows Update status..." -ForegroundColor Cyan
    
    $lastUpdate = Invoke-SafeCommand {
        Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    }
    
    if ($lastUpdate -and $lastUpdate.InstalledOn) {
        $daysSince = (New-TimeSpan -Start $lastUpdate.InstalledOn -End (Get-Date)).Days
        $threshold = $Config.Thresholds.MaxUpdateAge
        
        if ($daysSince -lt $threshold) {
            Write-AuditResult "Windows Update" "Last patch $daysSince days ago" -Status Pass
            
            Add-AuditFinding `
                -Id "SysHard_Update" `
                -Title "Windows Update" `
                -Value "Last update: $daysSince days ago" `
                -Severity 1 `
                -Category "SystemHardening"
        }
        else {
            Write-AuditResult "Windows Update" "Last patch $daysSince days ago (OUTDATED)" -Status Warn
            
            Add-AuditFinding `
                -Id "SysHard_Update" `
                -Title "Windows Update" `
                -Value "Last update: $daysSince days ago" `
                -Severity 2 `
                -Notes "System is outdated. Run Windows Update to install latest security patches." `
                -Category "SystemHardening"
        }
        
        Write-Host "  Latest update: $($lastUpdate.HotFixID) installed on $($lastUpdate.InstalledOn)" -ForegroundColor Gray
    }
    else {
        Write-AuditResult "Windows Update" "Unable to determine" -Status Warn
        
        Add-AuditFinding `
            -Id "SysHard_Update" `
            -Title "Windows Update" `
            -Value "Unknown" `
            -Severity 2 `
            -Category "SystemHardening"
    }
}

function Test-RemoteDesktop {
    Write-Host "Checking Remote Desktop (RDP) status..." -ForegroundColor Cyan
    
    try {
        $rdp = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
            -Name "fDenyTSConnections" -ErrorAction Stop
        
        if ($rdp.fDenyTSConnections -eq 0) {
            Write-AuditResult "Remote Desktop" "ENABLED" -Status Warn
            
            Add-AuditFinding `
                -Id "SysHard_RDP" `
                -Title "Remote Desktop" `
                -Value "Enabled" `
                -Severity 2 `
                -Notes "RDP is enabled. Ensure strong passwords and Network Level Authentication (NLA) are configured. Consider disabling if not needed." `
                -Category "SystemHardening"
        }
        else {
            Write-AuditResult "Remote Desktop" "Disabled" -Status Pass
            
            Add-AuditFinding `
                -Id "SysHard_RDP" `
                -Title "Remote Desktop" `
                -Value "Disabled" `
                -Severity 1 `
                -Category "SystemHardening"
        }
    }
    catch {
        Write-AuditResult "Remote Desktop" "Unknown" -Status Info
        
        Add-AuditFinding `
            -Id "SysHard_RDP" `
            -Title "Remote Desktop" `
            -Value "Unknown" `
            -Severity 3 `
            -Category "SystemHardening"
    }
}

function Test-AdminAccount {
    Write-Host "Checking local Administrator accounts..." -ForegroundColor Cyan
    
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        $adminCount = $admins.Count
        
        Write-AuditResult "Administrator Accounts" "$adminCount account(s)" -Status Info
        
        $nonStandardAdmins = @()
        
        foreach ($admin in $admins) {
            # Check if it's a standard admin account
            if ($admin.Name -notmatch 'Administrator|Domain Admins|BUILTIN') {
                $nonStandardAdmins += $admin.Name
                Write-Host "  - $($admin.Name)" -ForegroundColor Yellow
            }
            else {
                Write-Host "  - $($admin.Name)" -ForegroundColor Gray
            }
        }
        
        if ($nonStandardAdmins.Count -gt 0) {
            Add-AuditFinding `
                -Id "SysHard_AdminAccounts" `
                -Title "Local Administrator Accounts" `
                -Value "$($nonStandardAdmins.Count) non-standard admin(s)" `
                -Severity 2 `
                -Notes "Review: $($nonStandardAdmins -join ', '). Only trusted users should have admin rights." `
                -Category "SystemHardening"
        }
        else {
            Add-AuditFinding `
                -Id "SysHard_AdminAccounts" `
                -Title "Local Administrator Accounts" `
                -Value "Standard configuration" `
                -Severity 1 `
                -Category "SystemHardening"
        }
    }
    catch {
        Write-AuditResult "Administrator Accounts" "Query failed" -Status Warn
        
        Add-AuditFinding `
            -Id "SysHard_AdminAccounts" `
            -Title "Local Administrator Accounts" `
            -Value "Unknown" `
            -Severity 2 `
            -Category "SystemHardening"
    }
}

Export-ModuleMember -Function Invoke-SystemHardeningAudit