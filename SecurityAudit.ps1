<#
.SYNOPSIS
    Windows Security Audit Framework - Main Orchestrator
.DESCRIPTION
    Comprehensive security audit tool that performs:
    - System hardening checks
    - Defender & AV status
    - Firewall configuration
    - Deep process triage (injection detection, fileless malware)
    - WMI persistence hunting
    - File system corruption detection
    - Browser extension audit
    - Network analysis
    - And much more...
    
.PARAMETER Mode
    Scan mode: Quick, Standard, Deep, Forensic
.PARAMETER ConfigPath
    Path to custom configuration file
.PARAMETER ReportPath
    Custom path for report output
    
.EXAMPLE
    .\SecurityAudit.ps1
    Run with default settings (Deep scan)
    
.EXAMPLE
    .\SecurityAudit.ps1 -Mode Quick
    Run a quick scan (core security checks only)
    
.EXAMPLE
    .\SecurityAudit.ps1 -Mode Forensic -ReportPath C:\SecurityAudits
    Full forensic analysis with custom report location
    
.NOTES
    Author: Sandiso Mazibuko
    Version: 5.1
    Requires: PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Quick', 'Standard', 'Deep', 'Forensic')]
    [string]$Mode = 'Deep',
    
    [Parameter()]
    [string]$ConfigPath,
    
    [Parameter()]
    [string]$ReportPath
)

#region Initialization

# Set strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Get script directory
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# Import Core module first (required by all others)
Import-Module (Join-Path $ScriptRoot "Modules\Core.psm1") -Force

# Check for admin rights
if (-not (Test-IsAdministrator)) {
    Write-Warning "Administrator privileges required for complete audit."
    Write-Warning "Some checks may be skipped or incomplete."
    Write-Host ""
    $continue = Read-Host "Continue anyway? (Y/N)"
    if ($continue -ne 'Y') {
        exit
    }
}

# Load configuration
if ($ConfigPath -and (Test-Path $ConfigPath)) {
    $Config = Import-PowerShellDataFile -Path $ConfigPath
} else {
    $Config = Import-PowerShellDataFile -Path (Join-Path $ScriptRoot "Config.psd1")
}

# Override config with parameters if provided
if ($Mode) {
    $Config.ScanProfile.Mode = $Mode
}
if ($ReportPath) {
    $Config.Output.ReportPath = $ReportPath
}

# Adjust config based on mode
switch ($Mode) {
    'Quick' {
        $Config.ScanProfile.EnableProcessTriage = $true
        $Config.ScanProfile.EnablePersistenceHunting = $false
        $Config.ScanProfile.EnableForensicChecks = $false
        $Config.ScanProfile.EnableFileSystemAudit = $true
    }
    'Standard' {
        $Config.ScanProfile.EnableProcessTriage = $true
        $Config.ScanProfile.EnablePersistenceHunting = $true
        $Config.ScanProfile.EnableForensicChecks = $false
    }
    'Deep' {
        # All enabled by default
    }
    'Forensic' {
        # All enabled, plus verbose logging
        $Config.Output.VerboseLogging = $true
    }
}

#endregion

#region Startup

# Clear any previous findings
Clear-AuditFindings

# Start transcript if enabled
if ($Config.Output.EnableTranscript) {
    $transcriptPath = Join-Path $Config.Output.ReportPath "audit_transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Start-Transcript -Path $transcriptPath -Force | Out-Null
}

# Display banner
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                            ║" -ForegroundColor Cyan
Write-Host "║       Windows Security Audit Framework v5.1               ║" -ForegroundColor Cyan
Write-Host "║       Forensic Suite - Comprehensive Analysis             ║" -ForegroundColor Cyan
Write-Host "║                                                            ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "Mode: $Mode" -ForegroundColor Yellow
Write-Host "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ""

# Display system info
$sysInfo = Get-SystemInfo
Write-Host "System Information:" -ForegroundColor Cyan
Write-Host "  Computer: $($sysInfo.ComputerName)" -ForegroundColor Gray
Write-Host "  OS: $($sysInfo.OSName)" -ForegroundColor Gray
Write-Host "  Architecture: $($sysInfo.Architecture)" -ForegroundColor Gray
Write-Host ""

#endregion

#region Core Audit Modules

try {
    # === CRITICAL MODULE: File System Audit ===
    # This is loaded first because it detects severe system corruption
    if ($Config.ScanProfile.EnableFileSystemAudit) {
        Import-Module (Join-Path $ScriptRoot "Modules\FileSystemAudit.psm1") -Force
        Invoke-FileSystemAudit -Config $Config
    }
    
    # === Process Triage - Your most advanced feature ===
    if ($Config.ScanProfile.EnableProcessTriage) {
        Import-Module (Join-Path $ScriptRoot "Modules\ProcessTriage.psm1") -Force
        Invoke-ProcessTriage -Config $Config
    }
    
    # === System Hardening ===
    if ($Config.ScanProfile.EnableSystemHardening) {
        Import-Module (Join-Path $ScriptRoot "Modules\SystemHardening.psm1") -Force
        Invoke-SystemHardeningAudit -Config $Config
    }
    
    # === Windows Defender ===
    if ($Config.ScanProfile.EnableDefenderAudit) {
        Import-Module (Join-Path $ScriptRoot "Modules\DefenderAudit.psm1") -Force
        Invoke-DefenderAudit -Config $Config
    }
    
    # === Firewall ===
    if ($Config.ScanProfile.EnableFirewallAudit) {
        Import-Module (Join-Path $ScriptRoot "Modules\FirewallAudit.psm1") -Force
        Invoke-FirewallAudit -Config $Config
    }
    
    # === Persistence Hunting ===
    if ($Config.ScanProfile.EnablePersistenceHunting) {
        Import-Module (Join-Path $ScriptRoot "Modules\PersistenceHunting.psm1") -Force
        Invoke-PersistenceHunting -Config $Config
    }
    
    # === Network Analysis ===
    if ($Config.ScanProfile.EnableNetworkAudit) {
        Import-Module (Join-Path $ScriptRoot "Modules\NetworkAudit.psm1") -Force
        Invoke-NetworkAudit -Config $Config
    }
    
    # === Forensic Checks ===
    if ($Config.ScanProfile.EnableForensicChecks) {
        Import-Module (Join-Path $ScriptRoot "Modules\ForensicChecks.psm1") -Force
        Invoke-ForensicChecks -Config $Config
    }
    
}
catch {
    Write-Host "ERROR during audit: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
}

#endregion

#region Risk Scoring & Reporting

Write-AuditHeader "Risk Assessment"

$riskScore = Get-RiskScore

Write-Host ""
Write-Host "Risk Analysis Complete" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Raw Score: $($riskScore.RawScore) / $($riskScore.MaxPossible)" -ForegroundColor Gray
Write-Host "  Risk Level: $($riskScore.RiskPercent)%" -ForegroundColor $(
    if ($riskScore.SeverityLabel -eq 'HIGH') { 'Red' }
    elseif ($riskScore.SeverityLabel -eq 'MEDIUM') { 'Yellow' }
    else { 'Green' }
)
Write-Host "  Severity: $($riskScore.SeverityLabel)" -ForegroundColor $(
    if ($riskScore.SeverityLabel -eq 'HIGH') { 'Red' }
    elseif ($riskScore.SeverityLabel -eq 'MEDIUM') { 'Yellow' }
    else { 'Green' }
)
Write-Host ""

# Generate reports
Import-Module (Join-Path $ScriptRoot "Modules\ReportGenerator.psm1") -Force
$reportFolder = New-AuditReport -ReportPath $Config.Output.ReportPath -Config $Config

#endregion

#region Cleanup & Summary

# Stop transcript
if ($Config.Output.EnableTranscript) {
    Stop-Transcript | Out-Null
}

# Final summary
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                    AUDIT COMPLETE                          ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Duration: $((Get-Date) - $script:StartTime | Select-Object -ExpandProperty TotalSeconds) seconds" -ForegroundColor Gray
Write-Host ""

# Recommendations based on severity
if ($riskScore.SeverityLabel -eq 'HIGH') {
    Write-Host "⚠️  CRITICAL: Immediate action required!" -ForegroundColor Red
    Write-Host "Your system has serious security issues that need immediate attention." -ForegroundColor Red
    Write-Host ""
    Write-Host "Recommended Actions:" -ForegroundColor Yellow
    Write-Host "  1. Review all FAIL items in the report" -ForegroundColor Gray
    Write-Host "  2. Run 'sfc /scannow' to repair system files" -ForegroundColor Gray
    Write-Host "  3. Run 'DISM /Online /Cleanup-Image /RestoreHealth'" -ForegroundColor Gray
    Write-Host "  4. Update Windows and all software" -ForegroundColor Gray
    Write-Host "  5. Consider backing up data and reinstalling Windows" -ForegroundColor Gray
}
elseif ($riskScore.SeverityLabel -eq 'MEDIUM') {
    Write-Host "⚠️  WARNING: Action recommended" -ForegroundColor Yellow
    Write-Host "Your system has moderate security concerns." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Recommended Actions:" -ForegroundColor Yellow
    Write-Host "  1. Review WARN and FAIL items in the report" -ForegroundColor Gray
    Write-Host "  2. Update Windows and security software" -ForegroundColor Gray
    Write-Host "  3. Enable Windows Defender if disabled" -ForegroundColor Gray
}
else {
    Write-Host "✓ Your system appears to be in good security health" -ForegroundColor Green
    Write-Host "Continue regular security practices and keep software updated." -ForegroundColor Gray
}

Write-Host ""
Write-Host "Thank you for using Windows Security Audit Framework!" -ForegroundColor Cyan
Write-Host ""

#endregion