<#
.SYNOPSIS
    Windows Security Audit Framework - Main Orchestrator
.DESCRIPTION
    This script coordinates the execution of various security audit modules.
.NOTES
    Author: Sandiso Mazibuko
    Version: 5.2 (Fixes Type Mismatch)
#>

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [ValidateSet('Quick', 'Standard', 'Deep', 'Forensic')]
    [string]$Mode = 'Deep',

    [Parameter()]
    [string]$ConfigPath = (Join-Path $PSScriptRoot "Config.psd1"),

    [Parameter()]
    [string]$ReportPath
)

#region Initialization & Configuration
$ScriptRoot = $PSScriptRoot
# Stop on terminating errors, but continue on non-terminating ones
$ErrorActionPreference = 'Continue' 

# --- Load Core Utilities ---
Import-Module (Join-Path $ScriptRoot "Modules\Core.psm1") -Force

# --- Admin Rights Check ---
if (-not (Test-IsAdministrator)) {
    Write-Warning "This script provides the most accurate results when run as an Administrator."
}

# --- Load Configuration ---
# FIX: Load the configuration file directly as a hashtable.
$Config = Invoke-SafeCommand { Import-PowerShellDataFile -Path $ConfigPath }
if (-not $Config) {
    Write-Error "Failed to load configuration from $ConfigPath. Exiting."
    exit 1
}

# Override config with command-line parameters
$Config.ScanProfile.Mode = $Mode
if ($ReportPath) { $Config.Output.ReportPath = $ReportPath }
if ($Mode -eq 'Forensic') { $Config.Output.VerboseLogging = $true }

# Resolve final report path
$finalReportPath = $Config.Output.ReportPath
if (-not [System.IO.Path]::IsPathRooted($finalReportPath)) {
    $finalReportPath = Join-Path $ScriptRoot $finalReportPath
}
if (-not (Test-Path $finalReportPath)) { New-Item -Path $finalReportPath -ItemType Directory -Force | Out-Null }
#endregion

#region Startup
# Start Transcript if enabled
if ($Config.Output.EnableTranscript) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $transcriptPath = Join-Path $finalReportPath "transcript_$timestamp.log"
    Start-Transcript -Path $transcriptPath -Force | Out-Null
}

Write-AuditHeader "Windows Security Audit Framework v5.2"
Write-Host "Scan Mode: $Mode" -ForegroundColor Yellow
Write-Host "Start Time: $(Get-Date)" -ForegroundColor Gray
#endregion

#region Module Execution
try {
    # Define which modules run in which mode
    $moduleExecutionPlan = @{
        'Quick'    = @('FileSystemAudit', 'ProcessTriage')
        'Standard' = @('FileSystemAudit', 'ProcessTriage', 'PersistenceHunting')
        'Deep'     = @('FileSystemAudit', 'ProcessTriage', 'PersistenceHunting', 'SystemHardening', 'DefenderAudit', 'NetworkAudit', 'ForensicChecks')
        'Forensic' = @('FileSystemAudit', 'ProcessTriage', 'PersistenceHunting', 'SystemHardening', 'DefenderAudit', 'NetworkAudit', 'ForensicChecks', 'CryptoMinerDetection', 'ThreatIntelligence')
    }

    $modulesToRun = $moduleExecutionPlan[$Mode]

    foreach ($moduleName in $modulesToRun) {
        $moduleFile = "$moduleName.psm1"
        $functionName = "Invoke-$moduleName"
        
        Import-Module (Join-Path $ScriptRoot "Modules\$moduleFile") -Force
        
        if (Get-Command $functionName -ErrorAction SilentlyContinue) {
            & $functionName -Config $Config
        } else {
            Write-Warning "Function $functionName not found in module $moduleFile."
        }
    }
}
catch {
    # This will catch any script-terminating errors that might still occur
    Write-Error "A critical error occurred during the audit: $($_.Exception.Message)"
}
finally {
    #region Report Generation & Cleanup
    Write-AuditHeader "Finalizing Report"
    
    Import-Module (Join-Path $ScriptRoot "Modules\ReportGenerator.psm1") -Force
    
    New-AuditReport -ReportPath $finalReportPath -Config $Config
    
    Write-AuditHeader "Audit Complete"
    
    if (Get-Transcript) {
        Stop-Transcript
    }
    #endregion
}