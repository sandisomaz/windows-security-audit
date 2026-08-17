#Requires -Version 5.1
<#
.SYNOPSIS
    Deep process triage module.
.DESCRIPTION
    Detects process injection, high RAM usage, and processes running from
    suspicious locations. Includes a vendor whitelist to suppress false positives.
.NOTES
    Version : 5.5.0
    Requires: PowerShell 5.1+, Administrator
#>

using module .\Core.psm1

function Invoke-ProcessTriage {
    [CmdletBinding()]
    param([hashtable]$Config)

    Write-AuditHeader 'Deep Process & Performance Triage'

    # --- RAM Usage ---
    $os           = Get-CimInstance Win32_OperatingSystem
    $totalRam     = $os.TotalVisibleMemorySize
    $freeRam      = $os.FreePhysicalMemory
    $usedPercent  = [math]::Round((($totalRam - $freeRam) / $totalRam) * 100, 1)

    if ($usedPercent -gt 85) {
        Write-AuditResult 'Memory Usage' "$usedPercent% (CRITICAL)" -Status Fail
        Add-AuditFinding -Id 'Proc_Mem_Crit' -Title 'Critical Memory Usage' -Value "$usedPercent% used" `
            -Severity 0 `
            -Notes 'System is running out of RAM. This can cause 100% Disk Usage as Windows pages to disk. Close unused applications and browser tabs.' `
            -Category 'Performance'
    } elseif ($usedPercent -gt 75) {
        Write-AuditResult 'Memory Usage' "$usedPercent% (High)" -Status Warn
        Add-AuditFinding -Id 'Proc_Mem_High' -Title 'High Memory Usage' -Value "$usedPercent% used" `
            -Severity 2 -Notes 'RAM usage is elevated. System may slow down under load.' -Category 'Performance'
    } else {
        Write-AuditResult 'Memory Usage' "$usedPercent% (Normal)" -Status Pass
    }

    # --- Process Security Scan ---
    # Trusted vendor name fragments — processes matching these are skipped
    $vendorWhitelist = @(
        'Lenovo', 'Intel', 'NVIDIA', 'Realtek', 'Proton',
        'Microsoft', 'Google', 'Brave', 'Mozilla', 'Discord',
        'Steam', 'Dropbox', 'Zoom', 'Adobe', 'AMD', 'Qualcomm',
        'System Idle Process', 'Secure System', 'Registry', 'Memory Compression'
    )

    # Canonical system process names that are allowed to have no ExecutablePath
    $systemAllowList = @(
        'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe',
        'svchost.exe', 'winlogon.exe', 'LsaIso.exe', 'fontdrvhost.exe',
        'WUDFHost.exe', 'dwm.exe', 'spoolsv.exe', 'WmiPrvSE.exe',
        'unsecapp.exe', 'conhost.exe', 'SearchIndexer.exe', 'Taskmgr.exe',
        'taskhostw.exe', 'dasHost.exe', 'ctfmon.exe', 'WmiApSrv.exe'
    )

    # Append any user-configured exclusions
    if ($Config.Advanced -and $Config.Advanced.ExcludedProcesses) {
        $systemAllowList += $Config.Advanced.ExcludedProcesses
    }

    $processes = Get-CimInstance -ClassName Win32_Process |
        Select-Object Name, ProcessId, ExecutablePath, CommandLine

    $suspiciousProcesses = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($proc in $processes) {
        # Skip vendor-whitelisted apps
        $isSafe = $false
        foreach ($vendor in $vendorWhitelist) {
            if ($proc.Name -match $vendor -or ($proc.ExecutablePath -and $proc.ExecutablePath -match $vendor)) {
                $isSafe = $true
                break
            }
        }
        if ($isSafe) { continue }
        if ($proc.Name -in $systemAllowList) { continue }

        $reasons = @()

        # Rule 1: No executable path outside of known-safe system processes
        if (-not $proc.ExecutablePath) {
            $reasons += 'Hidden executable path (potential injection)'
        }

        # Rule 2: Running from a temporary or public folder
        if ($proc.ExecutablePath -match 'AppData\\Local\\Temp' -or
            $proc.ExecutablePath -match 'Users\\Public') {
            $reasons += 'Running from Temp/Public folder'
        }

        if ($reasons.Count -gt 0) {
            $suspiciousProcesses.Add([PSCustomObject]@{
                Name    = $proc.Name
                PID     = $proc.ProcessId
                Reasons = $reasons -join '; '
            })
        }
    }

    if ($suspiciousProcesses.Count -gt 0) {
        Write-AuditResult 'Suspicious Processes' "Found $($suspiciousProcesses.Count)" -Status Warn
        $procList = ($suspiciousProcesses | ForEach-Object { "$($_.Name) (PID: $($_.PID)) - $($_.Reasons)" }) -join "; "
        $notes    = Format-FixRecommendation `
            -Problem "Detected $($suspiciousProcesses.Count) process(es) with suspicious characteristics." `
            -ManualSteps @(
                "Processes to investigate: $procList",
                '1. Open Task Manager and locate the process by PID.',
                "2. Right-click and select 'Open file location'.",
                '3. If the binary is in a Temp or Public folder, terminate and delete it.',
                '4. Run a full antivirus scan.'
            )
        Add-AuditFinding -Id 'Proc_Suspicious' -Title 'Suspicious Process Activity' `
            -Value "$($suspiciousProcesses.Count) process(es)" -Severity 2 -Notes $notes -Category 'Process'
    } else {
        Write-AuditResult 'Suspicious Processes' 'None detected' -Status Pass
    }
}

Export-ModuleMember -Function Invoke-ProcessTriage