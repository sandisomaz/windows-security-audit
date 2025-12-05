<#
.SYNOPSIS
    Windows Defender and antivirus analysis module
.DESCRIPTION
    Checks:
    - Windows Defender status
    - Real-time protection
    - Signature updates
    - Tamper protection
    - Cloud-delivered protection
    - Recent threat detections
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
        
        Add-AuditFinding `
            -Id "Def_NotAvailable" `
            -Title "Windows Defender" `
            -Value "Not available" `
            -Severity 2 `
            -Notes "Defender may be disabled by third-party antivirus. Verify alternative protection is active." `
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
        
        Add-AuditFinding `
            -Id "Def_RealTime" `
            -Title "Real-Time Protection" `
            -Value "Disabled" `
            -Severity 0 `
            -Weight 25 `
            -Notes "CRITICAL: Real-time protection is disabled. Your system is vulnerable to malware." `
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
        
        Add-AuditFinding `
            -Id "Def_AntiSpyware" `
            -Title "Anti-Spyware Protection" `
            -Value "Disabled" `
            -Severity 0 `
            -Weight 25 `
            -Notes "CRITICAL: Anti-spyware protection is disabled." `
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
        
        Add-AuditFinding `
            -Id "Def_Behavior" `
            -Title "Behavior Monitoring" `
            -Value "Disabled" `
            -Severity 2 `
            -Notes "Behavior monitoring detects suspicious activity. Recommended to enable." `
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
        
        Add-AuditFinding `
            -Id "Def_Cloud" `
            -Title "Cloud-Delivered Protection" `
            -Value "Disabled" `
            -Severity 2 `
            -Notes "Cloud protection provides faster threat detection. Recommended to enable." `
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
            
            Add-AuditFinding `
                -Id "Def_Signatures" `
                -Title "Antivirus Signatures" `
                -Value "Updated $daysSince day(s) ago" `
                -Severity 2 `
                -Notes "Signatures are slightly outdated. Update Windows Defender." `
                -Category "Defender"
        }
        else {
            Write-AuditResult "Signature Update" "Updated $daysSince day(s) ago (OUTDATED)" -Status Fail
            
            Add-AuditFinding `
                -Id "Def_Signatures" `
                -Title "Antivirus Signatures" `
                -Value "Updated $daysSince day(s) ago" `
                -Severity 0 `
                -Weight 20 `
                -Notes "CRITICAL: Signatures are severely outdated. Update immediately: Update-MpSignature" `
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
        
        Add-AuditFinding `
            -Id "Def_FullScan" `
            -Title "Full System Scan" `
            -Value "Never run" `
            -Severity 2 `
            -Notes "Run a full scan: Start-MpScan -ScanType FullScan" `
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
            
            Add-AuditFinding `
                -Id "Def_TamperProtection" `
                -Title "Tamper Protection" `
                -Value "Disabled" `
                -Severity 2 `
                -Notes "Tamper Protection prevents malware from disabling Defender. Enable in Windows Security." `
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
        
        Add-AuditFinding `
            -Id "Def_Threats" `
            -Title "Recent Threat Detections" `
            -Value "$($threats.Count) detection(s)" `
            -Severity 2 `
            -Notes "Threats detected: $($threatNames -join ', '). Ensure all were successfully removed." `
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
                Write-Host "  - $($av.displayName) (State: $($av.productState))" -ForegroundColor Gray
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