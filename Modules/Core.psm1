<#
.SYNOPSIS
    Core utilities for Windows Security Audit Framework
.DESCRIPTION
    Shared functions, logging, and utilities used across all modules
#>

# Global variables
$script:Findings = @()
$script:StartTime = Get-Date

# Color constants
$script:Colors = @{
    Header = "Cyan"
    Pass   = "Green"
    Warn   = "Yellow"
    Fail   = "Red"
    Info   = "Gray"
}

#region Logging and Output Functions

function Write-AuditHeader {
    param([string]$Text)
    Write-Host ""
    Write-Host "=== $Text ===" -ForegroundColor $script:Colors.Header
}

function Write-AuditResult {
    param(
        [string]$Label,
        [string]$Value,
        [ValidateSet('Pass', 'Warn', 'Fail', 'Info')]
        [string]$Status = 'Info'
    )
    
    $prefix = switch ($Status) {
        'Pass' { "[OK]  "; $color = $script:Colors.Pass }
        'Warn' { "[WARN]"; $color = $script:Colors.Warn }
        'Fail' { "[FAIL]"; $color = $script:Colors.Fail }
        'Info' { "      "; $color = $script:Colors.Info }
    }
    
    Write-Host "$prefix $Label : $Value" -ForegroundColor $color
}

function Write-AuditLog {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to transcript (if active)
    Write-Verbose $logMessage
}

#endregion

#region Finding Management

function Add-AuditFinding {
    <#
    .SYNOPSIS
        Adds a finding to the audit results
    .PARAMETER Id
        Unique identifier for the finding
    .PARAMETER Title
        Human-readable title
    .PARAMETER Value
        The actual value/result
    .PARAMETER Severity
        0=Fail, 1=Pass, 2=Warn, 3=Info
    .PARAMETER Weight
        Importance weight for risk scoring (0-25)
    .PARAMETER Notes
        Additional context or recommendations
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Id,
        
        [Parameter(Mandatory)]
        [string]$Title,
        
        [Parameter(Mandatory)]
        [string]$Value,
        
        [Parameter(Mandatory)]
        [ValidateSet(0, 1, 2, 3)]
        [int]$Severity,
        
        [int]$Weight = -1,
        
        [string]$Notes = "",
        
        [string]$Category = "General"
    )
    
    # Auto-calculate weight if not provided
    if ($Weight -eq -1) {
        $Weight = switch ($Severity) {
            0 { 25 }  # FAIL - Critical
            2 { 10 }  # WARN - Moderate
            1 { 0 }   # PASS - No risk
            3 { 5 }   # INFO - Minor
        }
    }
    
    $finding = [PSCustomObject]@{
        Id       = $Id
        Title    = $Title
        Value    = $Value
        Severity = $Severity
        Weight   = $Weight
        Notes    = $Notes
        Category = $Category
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $script:Findings += $finding
    
    Write-AuditLog "Finding added: $Id - $Title" -Level Info
}

function Get-AuditFindings {
    return $script:Findings
}

function Clear-AuditFindings {
    $script:Findings = @()
}

#endregion

#region Utility Functions

function Invoke-SafeCommand {
    <#
    .SYNOPSIS
        Safely executes a command and returns result or null on error
    #>
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock
    )
    
    try {
        return & $ScriptBlock
    }
    catch {
        Write-AuditLog "Error executing command: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Checks if the current session is running as Administrator
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-Administrator {
    <#
    .SYNOPSIS
        Re-launches the script with Administrator privileges
    #>
    if (-not (Test-IsAdministrator)) {
        Write-Warning "Administrator privileges required. Re-launching..."
        
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -Verb RunAs
        exit
    }
}

function Get-SystemInfo {
    <#
    .SYNOPSIS
        Retrieves basic system information
    #>
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    
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
    param([int]$Severity)
    
    switch ($Severity) {
        0 { return "FAIL" }
        1 { return "PASS" }
        2 { return "WARN" }
        3 { return "INFO" }
        default { return "UNKNOWN" }
    }
}

function Get-FileHashSafe {
    <#
    .SYNOPSIS
        Safely calculates file hash, returns N/A on error
    #>
    param(
        [string]$FilePath,
        [string]$Algorithm = "SHA256"
    )
    
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm $Algorithm -ErrorAction Stop
        return $hash.Hash
    }
    catch {
        return "N/A"
    }
}

#endregion

#region Risk Scoring

function Get-RiskScore {
    <#
    .SYNOPSIS
        Calculates overall risk score from findings
    .DESCRIPTION
        Returns a percentage (0-100) where higher = more risk
    #>
    $findings = Get-AuditFindings
    
    if ($findings.Count -eq 0) {
        return [PSCustomObject]@{
            RawScore      = 0
            MaxPossible   = 0
            RiskPercent   = 0
            SeverityLabel = "UNKNOWN"
        }
    }
    
    $score = 0
    $maxPossible = 0
    
    foreach ($finding in $findings) {
        $maxPossible += $finding.Weight
        
        switch ($finding.Severity) {
            0 { $score += $finding.Weight }           # FAIL: Full weight
            2 { $score += ($finding.Weight / 2) }     # WARN: Half weight
            1 { $score += 0 }                         # PASS: No penalty
            3 { $score += 2 }                         # INFO: Small fixed penalty
        }
    }
    
    $riskPercent = if ($maxPossible -gt 0) { 
        [math]::Round(($score / $maxPossible) * 100, 2) 
    } else { 
        0 
    }
    
    $severityLabel = if ($riskPercent -ge 50) { 
        "HIGH" 
    } elseif ($riskPercent -ge 25) { 
        "MEDIUM" 
    } else { 
        "LOW" 
    }
    
    return [PSCustomObject]@{
        RawScore      = $score
        MaxPossible   = $maxPossible
        RiskPercent   = $riskPercent
        SeverityLabel = $severityLabel
    }
}

#endregion

# Export module members
Export-ModuleMember -Function @(
    'Write-AuditHeader',
    'Write-AuditResult',
    'Write-AuditLog',
    'Add-AuditFinding',
    'Get-AuditFindings',
    'Clear-AuditFindings',
    'Invoke-SafeCommand',
    'Test-IsAdministrator',
    'Request-Administrator',
    'Get-SystemInfo',
    'ConvertTo-SeverityText',
    'Get-FileHashSafe',
    'Get-RiskScore'
)