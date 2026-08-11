#Requires -Version 5.1
<#
.SYNOPSIS
    Core utilities for the Windows Security Audit Framework.
.DESCRIPTION
    Provides shared state management, risk scoring, finding accumulation,
    logging helpers, and utility functions consumed by all audit modules.
    This module MUST be loaded before any other framework module.
.NOTES
    Version : 5.5.0
    Requires: PowerShell 5.1+
#>

# ---------------------------------------------------------------------------
# Framework version — single source of truth, referenced by other components
# ---------------------------------------------------------------------------
$script:FrameworkVersion = '5.5.0'

# ---------------------------------------------------------------------------
# Global State
# ---------------------------------------------------------------------------
# Use a generic List instead of @() to avoid O(n) array re-allocation on +=
$script:Findings  = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:StartTime = Get-Date

# Console colour palette
$script:Colors = @{
    Header = 'Cyan'
    Pass   = 'Green'
    Warn   = 'Yellow'
    Fail   = 'Red'
    Info   = 'Gray'
}

# ---------------------------------------------------------------------------
# Logging & Output
# ---------------------------------------------------------------------------

function Write-AuditHeader {
    <#
    .SYNOPSIS Prints a section divider to the console.
    #>
    param([Parameter(Mandatory)][string]$Text)
    Write-Host ''
    Write-Host "=== $Text ===" -ForegroundColor $script:Colors.Header
}

function Write-AuditResult {
    <#
    .SYNOPSIS Prints a labelled result line with a status prefix.
    #>
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$Value,
        [ValidateSet('Pass', 'Warn', 'Fail', 'Info')]
        [string]$Status = 'Info'
    )

    $color = $script:Colors[$Status]
    $prefix = switch ($Status) {
        'Pass' { '[OK]  ' }
        'Warn' { '[WARN]' }
        'Fail' { '[FAIL]' }
        'Info' { '      ' }
    }
    Write-Host "$prefix $Label : $Value" -ForegroundColor $color
}

function Write-AuditLog {
    <#
    .SYNOPSIS Writes a timestamped diagnostic entry to the verbose stream.
    #>
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Info'
    )
    $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Verbose $logMessage
}

# ---------------------------------------------------------------------------
# Finding Management
# ---------------------------------------------------------------------------

function Add-AuditFinding {
    <#
    .SYNOPSIS
        Registers a security finding in the shared findings store.
    .PARAMETER Id
        Unique dot-separated identifier (e.g. "Defender.RealTime").
    .PARAMETER Title
        Short, human-readable title shown in reports.
    .PARAMETER Value
        The observed value or result string.
    .PARAMETER Severity
        0 = FAIL (Critical), 1 = PASS, 2 = WARN, 3 = INFO
    .PARAMETER Weight
        Importance weight for risk scoring (0-25). Auto-derived from Severity
        when omitted.
    .PARAMETER Notes
        Detailed remediation guidance (plain text, supports "Run: <cmd>").
    .PARAMETER Category
        Logical grouping shown in the report (e.g. "Defender", "Firewall").
    #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][ValidateSet(0, 1, 2, 3)][int]$Severity,
        [int]$Weight    = -1,
        [string]$Notes  = '',
        [string]$Category = 'General'
    )

    # Derive default weight from severity when not explicitly supplied
    if ($Weight -eq -1) {
        $Weight = switch ($Severity) {
            0 { 25 }   # FAIL — Critical
            2 { 10 }   # WARN — Moderate
            3 {  5 }   # INFO — Minor
            1 {  0 }   # PASS — No risk
        }
    }

    $finding = [PSCustomObject]@{
        Id        = $Id
        Title     = $Title
        Value     = $Value
        Severity  = $Severity
        Weight    = $Weight
        Notes     = $Notes
        Category  = $Category
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }

    $script:Findings.Add($finding)
    Write-AuditLog "Finding registered: [$Id] $Title" -Level Info
}

function Get-AuditFindings {
    <#
    .SYNOPSIS Returns the full list of registered findings.
    #>
    return $script:Findings
}

function Clear-AuditFindings {
    <#
    .SYNOPSIS Resets the findings store (used between test runs).
    #>
    $script:Findings = [System.Collections.Generic.List[PSCustomObject]]::new()
}

function Get-FrameworkVersion {
    <#
    .SYNOPSIS Returns the current framework version string.
    #>
    return $script:FrameworkVersion
}

# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

function Invoke-SafeCommand {
    <#
    .SYNOPSIS
        Executes a scriptblock and returns its output, or $null on any error.
    .DESCRIPTION
        Wraps every module-level system query so a single failed WMI/CIM call
        never aborts the entire audit run.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )
    try {
        return & $ScriptBlock
    }
    catch {
        Write-AuditLog "Command failed: $($_.Exception.Message)" -Level Warning
        return $null
    }
}

function Test-IsAdministrator {
    <#
    .SYNOPSIS Returns $true if the current session has Administrator privileges.
    #>
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SystemInfo {
    <#
    .SYNOPSIS Retrieves basic OS and hardware metadata for the report header.
    #>
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem  -ErrorAction Stop

    return [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        OSName       = $os.Caption
        OSVersion    = $os.Version
        Architecture = $os.OSArchitecture
        Manufacturer = $cs.Manufacturer
        Model        = $cs.Model
        TotalRAM_GB  = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        LastBoot     = $os.LastBootUpTime
    }
}

function ConvertTo-SeverityText {
    <#
    .SYNOPSIS Converts an integer severity code to its label string.
    #>
    param([int]$Severity)
    switch ($Severity) {
        0 { return 'FAIL' }
        1 { return 'PASS' }
        2 { return 'WARN' }
        3 { return 'INFO' }
        default { return 'UNKNOWN' }
    }
}

function Get-FileHashSafe {
    <#
    .SYNOPSIS Calculates a file hash and returns 'N/A' on any access error.
    #>
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string]$Algorithm = 'SHA256'
    )
    try {
        return (Get-FileHash -Path $FilePath -Algorithm $Algorithm -ErrorAction Stop).Hash
    }
    catch {
        return 'N/A'
    }
}

# ---------------------------------------------------------------------------
# Remediation Formatting
# ---------------------------------------------------------------------------

function Format-FixRecommendation {
    <#
    .SYNOPSIS
        Formats a structured remediation note for inclusion in a finding.
    .PARAMETER Problem
        One-line description of the security issue.
    .PARAMETER QuickFix
        A single PowerShell command that resolves the issue automatically.
        The report UI will render a "Copy Fix" button for this value.
    .PARAMETER ManualSteps
        Ordered list of manual remediation steps.
    .PARAMETER MoreInfo
        URL to vendor/community documentation.
    .PARAMETER IsSafe
        Set to $true to indicate the QuickFix command is safe to run non-interactively.
    #>
    param(
        [Parameter(Mandatory)][string]$Problem,
        [string]$QuickFix    = '',
        [string[]]$ManualSteps = @(),
        [string]$MoreInfo    = '',
        [bool]$IsSafe        = $false
    )

    $recommendation = "$Problem`n`n"

    if ($QuickFix) {
        $recommendation += "Run: $QuickFix`n`n"
    }

    if ($ManualSteps.Count -gt 0) {
        $recommendation += "MANUAL FIX:`n"
        for ($i = 0; $i -lt $ManualSteps.Count; $i++) {
            $recommendation += "   $($i + 1). $($ManualSteps[$i])`n"
        }
        $recommendation += "`n"
    }

    if ($MoreInfo) {
        $recommendation += "MORE INFO:`n   $MoreInfo`n"
    }

    return $recommendation.TrimEnd()
}

# ---------------------------------------------------------------------------
# Risk Scoring
# ---------------------------------------------------------------------------

function Get-RiskScore {
    <#
    .SYNOPSIS
        Calculates the weighted risk score from all registered findings.
    .DESCRIPTION
        Formula:
          RawScore    = SUM(FAIL weights) + SUM(WARN weights / 2) + (2 * INFO count)
          MaxPossible = SUM(all weights)
          RiskPercent = Round((RawScore / MaxPossible) * 100, 2)
          SecurityScore = 100 - RiskPercent

        Risk Tiers:  LOW < 25% | MEDIUM 25-49% | HIGH >= 50%
    #>
    $findings = Get-AuditFindings

    if ($findings.Count -eq 0) {
        return [PSCustomObject]@{
            RawScore      = 0
            MaxPossible   = 0
            RiskPercent   = 0
            SeverityLabel = 'LOW'
        }
    }

    $score       = 0
    $maxPossible = 0

    foreach ($finding in $findings) {
        $maxPossible += $finding.Weight

        switch ($finding.Severity) {
            0 { $score += $finding.Weight }          # FAIL: full weight
            2 { $score += ($finding.Weight / 2) }    # WARN: half weight
            1 { $score += 0 }                        # PASS: no penalty
            3 { $score += 2 }                        # INFO: fixed 2-point penalty
        }
    }

    $riskPercent = if ($maxPossible -gt 0) {
        [math]::Round(($score / $maxPossible) * 100, 2)
    } else {
        0
    }

    $severityLabel = if ($riskPercent -ge 50) { 'HIGH' }
                     elseif ($riskPercent -ge 25) { 'MEDIUM' }
                     else { 'LOW' }

    return [PSCustomObject]@{
        RawScore      = $score
        MaxPossible   = $maxPossible
        RiskPercent   = $riskPercent
        SeverityLabel = $severityLabel
    }
}

# ---------------------------------------------------------------------------
# Module Exports
# ---------------------------------------------------------------------------
Export-ModuleMember -Function @(
    'Write-AuditHeader',
    'Write-AuditResult',
    'Write-AuditLog',
    'Add-AuditFinding',
    'Get-AuditFindings',
    'Clear-AuditFindings',
    'Get-FrameworkVersion',
    'Invoke-SafeCommand',
    'Test-IsAdministrator',
    'Get-SystemInfo',
    'ConvertTo-SeverityText',
    'Get-FileHashSafe',
    'Get-RiskScore',
    'Format-FixRecommendation'
) -Variable 'FrameworkVersion'