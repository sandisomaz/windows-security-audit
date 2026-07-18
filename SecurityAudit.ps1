<#
.SYNOPSIS
    Windows Security Audit Framework - Main Orchestrator (PRODUCTION v5.4)
.DESCRIPTION
    Coordinates execution of security audit modules with proper error handling
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
$ErrorActionPreference = 'Continue'

# Load Core Utilities
$coreModule = Join-Path $ScriptRoot "Modules\Core.psm1"
if (Test-Path $coreModule) {
    Import-Module $coreModule -Force
} else {
    Write-Error "CRITICAL: Core module not found at $coreModule"
    exit 1
}

# Admin Rights Check
if (-not (Test-IsAdministrator)) {
    Write-Warning "This script provides the most accurate results when run as an Administrator."
}

# Load Configuration
$RawConfig = Invoke-SafeCommand { Import-PowerShellDataFile -Path $ConfigPath }
if (-not $RawConfig) {
    Write-Error "Failed to load configuration from $ConfigPath. Exiting."
    exit 1
}

# --- THE MIGRATION FIX: Force Cast [PSCustomObject] to [hashtable] ---
# This converts the parsed PSCustomObject into a standard, deeply nested hashtable
$Config = @{}
foreach ($key in $RawConfig.Keys) {
    $Config[$key] = $RawConfig[$key]
}
# ---------------------------------------------------------------------

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
$transcriptStarted = $false
if ($Config.Output.EnableTranscript) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $transcriptPath = Join-Path $finalReportPath "transcript_$timestamp.log"
    try {
        Start-Transcript -Path $transcriptPath -Force | Out-Null
        $transcriptStarted = $true
    }
    catch {
        Write-Warning "Could not start transcript: $($_.Exception.Message)"
    }
}

Write-AuditHeader "Windows Security Audit Framework v5.4"
Write-Host "Scan Mode: $Mode" -ForegroundColor Yellow
Write-Host "Start Time: $(Get-Date)" -ForegroundColor Gray
#endregion

#region Module Execution
try {
    # Module-to-function mapping
    $moduleExecutionPlan = @{
        'Quick'    = @(
            @{Module='FileSystemAudit'; Function='Invoke-FileSystemAudit'},
            @{Module='ProcessTriage'; Function='Invoke-ProcessTriage'}
        )
        'Standard' = @(
            @{Module='FileSystemAudit'; Function='Invoke-FileSystemAudit'},
            @{Module='ProcessTriage'; Function='Invoke-ProcessTriage'},
            @{Module='PersistenceHunting'; Function='Invoke-PersistenceHunting'}
        )
        'Deep'     = @(
            @{Module='FileSystemAudit'; Function='Invoke-FileSystemAudit'},
            @{Module='ProcessTriage'; Function='Invoke-ProcessTriage'},
            @{Module='PersistenceHunting'; Function='Invoke-PersistenceHunting'},
            @{Module='DefenderAudit'; Function='Invoke-DefenderAudit'},
            @{Module='FirewallAudit'; Function='Invoke-FirewallAudit'},
            @{Module='NetworkAudit'; Function='Invoke-NetworkAudit'},
            @{Module='ForensicChecks'; Function='Invoke-ForensicChecks'},
            @{Module='SystemHardening'; Function='Invoke-SystemHardeningAudit'}
        )
        'Forensic' = @(
            @{Module='FileSystemAudit'; Function='Invoke-FileSystemAudit'},
            @{Module='ProcessTriage'; Function='Invoke-ProcessTriage'},
            @{Module='PersistenceHunting'; Function='Invoke-PersistenceHunting'},
            @{Module='DefenderAudit'; Function='Invoke-DefenderAudit'},
            @{Module='FirewallAudit'; Function='Invoke-FirewallAudit'},
            @{Module='NetworkAudit'; Function='Invoke-NetworkAudit'},
            @{Module='ForensicChecks'; Function='Invoke-ForensicChecks'},
            @{Module='SystemHardening'; Function='Invoke-SystemHardeningAudit'},
            @{Module='CryptoMinerDetection'; Function='Invoke-CryptoMinerDetection'},
            @{Module='BrowserAudit'; Function='Invoke-BrowserAudit'}
        )
    }

    $modulesToRun = $moduleExecutionPlan[$Mode]

    foreach ($moduleInfo in $modulesToRun) {
        $moduleFile = "$($moduleInfo.Module).psm1"
        $modulePath = Join-Path $ScriptRoot "Modules\$moduleFile"
        $functionName = $moduleInfo.Function
        
        # Check if module file exists
        if (-not (Test-Path $modulePath)) {
            Write-Warning "Module file not found: $modulePath. Skipping."
            continue
        }
        
        # Try to import module
        try {
            Import-Module $modulePath -Force -ErrorAction Stop
            
            # Check if function exists
            if (Get-Command $functionName -ErrorAction SilentlyContinue) {
                # Execute function
                & $functionName -Config $Config
            } else {
                Write-Warning "Function $functionName not found in module $moduleFile."
            }
        }
        catch {
            # --- FIX FOR THE ERROR IS HERE ---
            $errMessage = $_.Exception.Message
            Write-Warning "Failed to load or execute $moduleFile : $errMessage"
            Write-AuditLog "Module execution error for $moduleFile : $errMessage" -Level Error
        }
    }
}
catch {
    Write-Error "A critical error occurred during the audit: $($_.Exception.Message)"
}
finally {
    #region Report Generation & Cleanup
    Write-AuditHeader "Finalizing Report"
    
    $reportModule = Join-Path $ScriptRoot "Modules\ReportGenerator.psm1"
    if (Test-Path $reportModule) {
        Import-Module $reportModule -Force
        New-AuditReport -ReportPath $finalReportPath -Config $Config
    } else {
        Write-Error "Report Generator module missing!"
    }
    
    Write-AuditHeader "Audit Complete"
    
    if ($transcriptStarted) {
        try {
            Stop-Transcript | Out-Null
        }
        catch {}
    }
    #endregion
}