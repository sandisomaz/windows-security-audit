#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Defender and antivirus analysis module (ENHANCED)
.DESCRIPTION
    Checks with improved recommendations and fix commands
.NOTES
    Version : 5.5.0
#>

using module .\Core.psm1

function Invoke-DefenderAudit {
    <#
    .SYNOPSIS
        Performs comprehensive Windows Defender analysis
    .PARAMETER Config
        Configuration object from Config.psd1
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )
    
    Write-AuditHeader "Windows Defender & Antivirus Analysis"
    
    # === Get Defender Status ===
    $defender = Invoke-SafeCommand { Get-MpComputerStatus }
    
    if ($defender) {
        Test-DefenderProtection -Defender $defender
        Test-DefenderSignatures -Defender $defender
        Test-DefenderScans -Defender $defender
        Test-TamperProtection
        Test-DefenderThreats
    }
    else {
        Write-AuditResult "Windows Defender" "Not available or Third-party AV installed" -Status Warn
        
        $notes = Format-FixRecommendation `
            -Problem "Windows Defender is not available. This may be because a third-party antivirus is installed." `
            -ManualSteps @(
                "Check if third-party antivirus is installed (McAfee, Norton, Avast, etc.)",
                "Verify the third-party AV is active and up-to-date",
                "If no AV is installed, reinstall Windows Defender",
                "Go to Windows Security -> Virus & threat protection"
            ) `
            -MoreInfo "https://support.microsoft.com/windows-security"
        
        Add-AuditFinding `
            -Id "Def_NotAvailable" `
            -Title "Windows Defender" `
            -Value "Not available" `
            -Severity 2 `
            -Notes $notes `
            -Category "Defender"
    }
    
    # === Check Security Center for registered AV ===
    Test-SecurityCenter
}

function Test-DefenderProtection {
    param($Defender)
    
    Write-Host "Checking Defender protection status..." -ForegroundColor Cyan
    
    # Real-time Protection
    if ($Defender.RealTimeProtectionEnabled) {
        Write-AuditResult "Real-Time Protection" "ACTIVE" -Status Pass
        
        Add-AuditFinding `
            -Id "Def_RealTime" `
            -Title "Real-Time Protection" `
            -Value "Active" `
            -Severity 1 `
            -Category "Defender"
    }
    else {
        Write-AuditResult "Real-Time Protection" "DISABLED" -Status Fail
        
        $notes = Format-FixRecommendation `
            -Problem "CRITICAL: Real-time protection is disabled. Your system is vulnerable to malware attacks." `
            -QuickFix "Set-MpPreference -DisableRealtimeMonitoring `$false" `
            -ManualSteps @(
                "Open Windows Security (search in Start menu)",
                "Click 'Virus & threat protection'",
                "Under 'Virus & threat protection settings', click 'Manage settings'",
                "Toggle 'Real-time protection' to ON"
            ) `
            -MoreInfo "https://support.microsoft.com/windows/turn-on-real-time-and-cloud-delivered-protection" `
            -IsSafe $true
        
        Add-AuditFinding `
            -Id "Def_RealTime" `
            -Title "Real-Time Protection" `
            -Value "Disabled" `
            -Severity 0 `
            -Weight 25 `
            -Notes $notes `
            -Category "Defender"
    }
    
    # Anti-Spyware
    if ($Defender.AntispywareEnabled) {
        Write-AuditResult "Anti-Spyware" "ACTIVE" -Status Pass
        
        Add-AuditFinding `
            -Id "Def_AntiSpyware" `
            -Title "Anti-Spyware Protection" `
            -Value "Active" `
            -Severity 1 `
            -Category "Defender"
    }
    else {
        Write-AuditResult "Anti-Spyware" "DISABLED" -Status Fail
        
        $notes = Format-FixRecommendation `
            -Problem "CRITICAL: Anti-spyware protection is disabled." `
            -QuickFix "Set-MpPreference -DisableAntiSpyware `$false" `
            -ManualSteps @(
                "Open Windows Security",
                "Go to Virus & threat protection",
                "Enable all protection features"
            ) `
            -IsSafe $true
        
        Add-AuditFinding `
            -Id "Def_AntiSpyware" `
            -Title "Anti-Spyware Protection" `
            -Value "Disabled" `
            -Severity 0 `
            -Weight 25 `
            -Notes $notes `
            -Category "Defender"
    }
    
    # Behavior Monitoring
    if ($Defender.BehaviorMonitorEnabled) {
        Write-AuditResult "Behavior Monitoring" "ACTIVE" -Status Pass
        
        Add-AuditFinding `
            -Id "Def_Behavior" `
            -Title "Behavior Monitoring" `
            -Value "Active" `
            -Severity 1 `
            -Category "Defender"
    }
    else {
        Write-AuditResult "Behavior Monitoring" "DISABLED" -Status Warn
        
        $notes = Format-FixRecommendation `
            -Problem "Behavior monitoring detects suspicious activity and fileless malware." `
            -QuickFix "Set-MpPreference -DisableBehaviorMonitoring `$false" `
            -ManualSteps @(
                "Open Windows Security",
                "Go to App & browser control",
                "Enable 'Reputation-based protection'"
            ) `
            -IsSafe $true
        
        Add-AuditFinding `
            -Id "Def_Behavior" `
            -Title "Behavior Monitoring" `
            -Value "Disabled" `
            -Severity 2 `
            -Notes $notes `
            -Category "Defender"
    }
    
    # IOAV (IE Downloads and Outlook Express Attachments)
    if ($Defender.IoavProtectionEnabled) {
        Write-AuditResult "Download Scanning" "ACTIVE" -Status Pass
        
        Add-AuditFinding `
            -Id "Def_IOAV" `
            -Title "Download Scanning" `
            -Value "Active" `
            -Severity 1 `
            -Category "Defender"
    }
    else {
        Write-AuditResult "Download Scanning" "DISABLED" -Status Warn
        
        Add-AuditFinding `
            -Id "Def_IOAV" `
            -Title "Download Scanning" `
            -Value "Disabled" `
            -Severity 2 `
            -Category "Defender"
    }
    
    # Cloud Protection
    if ($Defender.MAPSReporting -ne 0) {
        Write-AuditResult "Cloud Protection" "ENABLED" -Status Pass
        
        Add-AuditFinding `
            -Id "Def_Cloud" `
            -Title "Cloud-Delivered Protection" `
            -Value "Enabled" `
            -Severity 1 `
            -Category "Defender"
    }
    else {
        Write-AuditResult "Cloud Protection" "DISABLED" -Status Warn
        
        $notes = Format-FixRecommendation `
            -Problem "Cloud protection provides faster threat detection using Microsoft's cloud intelligence." `
            -QuickFix "Set-MpPreference -MAPSReporting Advanced" `
            -ManualSteps @(
                "Open Windows Security",
                "Go to Virus & threat protection",
                "Click 'Manage settings'",
                "Enable 'Cloud-delivered protection'"
            ) `
            -MoreInfo "https://support.microsoft.com/cloud-delivered-protection" `
            -IsSafe $true
        
        Add-AuditFinding `
            -Id "Def_Cloud" `
            -Title "Cloud-Delivered Protection" `
            -Value "Disabled" `
            -Severity 2 `
            -Notes $notes `
            -Category "Defender"
    }
}

function Test-DefenderSignatures {
    param($Defender)
    
    Write-Host "Checking signature updates..." -ForegroundColor Cyan
    
    if ($Defender.AntivirusSignatureLastUpdated) {
        $daysSince = (New-TimeSpan -Start $Defender.AntivirusSignatureLastUpdated -End (Get-Date)).Days
        
        if ($daysSince -le 2) {
            Write-AuditResult "Signature Update" "Updated $daysSince day(s) ago" -Status Pass
            
            Add-AuditFinding `
                -Id "Def_Signatures" `
                -Title "Antivirus Signatures" `
                -Value "Updated $daysSince day(s) ago" `
                -Severity 1 `
                -Category "Defender"
        }
        elseif ($daysSince -le 7) {
            Write-AuditResult "Signature Update" "Updated $daysSince day(s) ago" -Status Warn
            
            $notes = Format-FixRecommendation `
                -Problem "Antivirus signatures are slightly outdated ($daysSince days old)." `
                -QuickFix "Update-MpSignature" `
                -ManualSteps @(
                    "Open Windows Security",
                    "Go to Virus & threat protection",
                    "Click 'Check for updates'",
                    "Or run Windows Update"
                ) `
                -IsSafe $true
            
            Add-AuditFinding `
                -Id "Def_Signatures" `
                -Title "Antivirus Signatures" `
                -Value "Updated $daysSince day(s) ago" `
                -Severity 2 `
                -Notes $notes `
                -Category "Defender"
        }
        else {
            Write-AuditResult "Signature Update" "Updated $daysSince day(s) ago (OUTDATED)" -Status Fail
            
            $notes = Format-FixRecommendation `
                -Problem "CRITICAL: Antivirus signatures are severely outdated ($daysSince days old). You are vulnerable to recent malware." `
                -QuickFix "Update-MpSignature -UpdateSource MicrosoftUpdateServer" `
                -ManualSteps @(
                    "Open Settings -> Windows Update",
                    "Click 'Check for updates'",
                    "Install all available updates",
                    "Restart if required",
                    "Then run: Update-MpSignature in PowerShell"
                ) `
                -MoreInfo "https://support.microsoft.com/update-windows-defender" `
                -IsSafe $true
            
            Add-AuditFinding `
                -Id "Def_Signatures" `
                -Title "Antivirus Signatures" `
                -Value "Updated $daysSince day(s) ago" `
                -Severity 0 `
                -Weight 20 `
                -Notes $notes `
                -Category "Defender"
        }
        
        Write-Host "  Last updated: $($Defender.AntivirusSignatureLastUpdated)" -ForegroundColor Gray
        Write-Host "  Signature version: $($Defender.AntivirusSignatureVersion)" -ForegroundColor Gray
    }
    else {
        Write-AuditResult "Signature Update" "Unknown" -Status Warn
        
        Add-AuditFinding `
            -Id "Def_Signatures" `
            -Title "Antivirus Signatures" `
            -Value "Unknown" `
            -Severity 2 `
            -Category "Defender"
    }
}

function Test-DefenderScans {
    param($Defender)
    
    Write-Host "Checking scan history..." -ForegroundColor Cyan
    
    # Quick Scan
    if ($Defender.QuickScanEndTime) {
        $daysSince = (New-TimeSpan -Start $Defender.QuickScanEndTime -End (Get-Date)).Days
        Write-AuditResult "Last Quick Scan" "$daysSince day(s) ago" -Status Info
    }
    else {
        Write-AuditResult "Last Quick Scan" "Never run" -Status Warn
    }
    
    # Full Scan
    if ($Defender.FullScanEndTime) {
        $daysSince = (New-TimeSpan -Start $Defender.FullScanEndTime -End (Get-Date)).Days
        
        if ($daysSince -le 30) {
            Write-AuditResult "Last Full Scan" "$daysSince day(s) ago" -Status Pass
        }
        else {
            Write-AuditResult "Last Full Scan" "$daysSince day(s) ago (Consider running)" -Status Warn
        }
    }
    else {
        Write-AuditResult "Last Full Scan" "Never run" -Status Warn
        
        $notes = Format-FixRecommendation `
            -Problem "Full system scan has never been run. A full scan checks all files for malware." `
            -QuickFix "Start-MpScan -ScanType FullScan" `
            -ManualSteps @(
                "Open Windows Security",
                "Go to Virus & threat protection",
                "Click 'Scan options'",
                "Select 'Full scan'",
                "Click 'Scan now' (takes 1-2 hours)"
            ) `
            -MoreInfo "https://support.microsoft.com/run-scan-windows-security" `
            -IsSafe $false
        
        Add-AuditFinding `
            -Id "Def_FullScan" `
            -Title "Full System Scan" `
            -Value "Never run" `
            -Severity 2 `
            -Notes $notes `
            -Category "Defender"
    }
    
    Add-AuditFinding `
        -Id "Def_ScanHistory" `
        -Title "Defender Scan History" `
        -Value "Quick: $($Defender.QuickScanEndTime), Full: $($Defender.FullScanEndTime)" `
        -Severity 3 `
        -Category "Defender"
}

function Test-TamperProtection {
    Write-Host "Checking Tamper Protection..." -ForegroundColor Cyan
    
    try {
        $tp = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" `
            -Name "TamperProtection" -ErrorAction Stop
        
        if ($tp.TamperProtection -eq 5) {
            Write-AuditResult "Tamper Protection" "ENABLED" -Status Pass
            
            Add-AuditFinding `
                -Id "Def_TamperProtection" `
                -Title "Tamper Protection" `
                -Value "Enabled" `
                -Severity 1 `
                -Category "Defender"
        }
        else {
            Write-AuditResult "Tamper Protection" "DISABLED" -Status Warn
            
            $notes = Format-FixRecommendation `
                -Problem "Tamper Protection prevents malware from disabling Windows Defender." `
                -ManualSteps @(
                    "Open Windows Security",
                    "Go to Virus & threat protection",
                    "Click 'Manage settings'",
                    "Scroll down and toggle 'Tamper Protection' to ON"
                ) `
                -MoreInfo "https://support.microsoft.com/tamper-protection"
            
            Add-AuditFinding `
                -Id "Def_TamperProtection" `
                -Title "Tamper Protection" `
                -Value "Disabled" `
                -Severity 2 `
                -Notes $notes `
                -Category "Defender"
        }
    }
    catch {
        Write-AuditResult "Tamper Protection" "Unknown" -Status Info
        
        Add-AuditFinding `
            -Id "Def_TamperProtection" `
            -Title "Tamper Protection" `
            -Value "Unknown" `
            -Severity 3 `
            -Category "Defender"
    }
}

function Test-DefenderThreats {
    Write-Host "Checking recent threat detections..." -ForegroundColor Cyan
    
    $threats = Invoke-SafeCommand {
        Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 10
    }
    
    if ($threats) {
        Write-AuditResult "Recent Threats" "Found $($threats.Count) detection(s)" -Status Warn
        
        foreach ($threat in $threats) {
            Write-Host "  - $($threat.ThreatName) detected on $($threat.InitialDetectionTime)" -ForegroundColor Yellow
        }
        
        $threatNames = $threats | ForEach-Object { $_.ThreatName } | Select-Object -Unique
        
        $notes = Format-FixRecommendation `
            -Problem "Threats were recently detected: $($threatNames -join ', ')" `
            -QuickFix "Remove-MpThreat" `
            -ManualSteps @(
                "Open Windows Security",
                "Go to Virus & threat protection",
                "Click 'Protection history'",
                "Review each threat and take recommended action",
                "Run a full scan to ensure all threats are removed"
            ) `
            -MoreInfo "https://support.microsoft.com/remove-malware"
        
        Add-AuditFinding `
            -Id "Def_Threats" `
            -Title "Recent Threat Detections" `
            -Value "$($threats.Count) detection(s)" `
            -Severity 2 `
            -Notes $notes `
            -Category "Defender"
    }
    else {
        Write-AuditResult "Recent Threats" "No recent detections" -Status Pass
        
        Add-AuditFinding `
            -Id "Def_Threats" `
            -Title "Recent Threat Detections" `
            -Value "None" `
            -Severity 1 `
            -Category "Defender"
    }
}

function Test-SecurityCenter {
    Write-Host "Checking Security Center for registered antivirus products..." -ForegroundColor Cyan
    
    try {
        $avProducts = Get-CimInstance -Namespace root/SecurityCenter2 `
            -ClassName AntiVirusProduct -ErrorAction Stop
        
        if ($avProducts) {
            Write-AuditResult "Registered AV Products" "$($avProducts.Count) product(s)" -Status Info
            
            $productNames = @()
            foreach ($av in $avProducts) {
                Write-Host "  - $($av.displayName)" -ForegroundColor Gray
                $productNames += $av.displayName
            }
            
            Add-AuditFinding `
                -Id "Def_SecurityCenter" `
                -Title "Registered Antivirus Products" `
                -Value ($productNames -join ", ") `
                -Severity 1 `
                -Category "Defender"
        }
        else {
            Write-AuditResult "Registered AV Products" "None found" -Status Warn
            
            Add-AuditFinding `
                -Id "Def_SecurityCenter" `
                -Title "Registered Antivirus Products" `
                -Value "None" `
                -Severity 2 `
                -Notes "No antivirus products registered with Security Center." `
                -Category "Defender"
        }
    }
    catch {
        Write-AuditResult "Security Center" "Query failed" -Status Info
        
        Add-AuditFinding `
            -Id "Def_SecurityCenter" `
            -Title "Security Center Status" `
            -Value "Query failed" `
            -Severity 3 `
            -Category "Defender"
    }
}

Export-ModuleMember -Function Invoke-DefenderAudit