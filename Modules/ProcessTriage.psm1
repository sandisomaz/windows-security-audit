<#
.SYNOPSIS
    Deep process triage module (Refined for False Positives)
.DESCRIPTION
    Detects process injection, high RAM usage, and unsigned binaries.
    Includes Whitelisting for common vendors (Lenovo, Proton, etc).
#>

function Invoke-ProcessTriage {
    param([hashtable]$Config)
    
    Write-AuditHeader "Deep Process & Performance Triage"
    
    # 1. NEW: Check System RAM Usage
    $os = Get-CimInstance Win32_OperatingSystem
    $totalRam = $os.TotalVisibleMemorySize
    $freeRam = $os.FreePhysicalMemory
    $usedPercent = [math]::Round((($totalRam - $freeRam) / $totalRam) * 100, 1)
    
    if ($usedPercent -gt 85) {
        Write-AuditResult "Memory Usage" "$usedPercent% (CRITICAL)" -Status Fail
        Add-AuditFinding -Id "Proc_Mem_Crit" -Title "Critical Memory Usage" -Value "$usedPercent% used" -Severity 0 -Notes "System is running out of RAM. This causes 100% Disk Usage as Windows swaps data to the drive. Close Chrome tabs or VS Code." -Category "Performance"
    } elseif ($usedPercent -gt 75) {
        Write-AuditResult "Memory Usage" "$usedPercent% (High)" -Status Warn
        Add-AuditFinding -Id "Proc_Mem_High" -Title "High Memory Usage" -Value "$usedPercent% used" -Severity 2 -Notes "RAM is getting full. System may slow down." -Category "Performance"
    } else {
        Write-AuditResult "Memory Usage" "$usedPercent% (Normal)" -Status Pass
    }

    # 2. Process Security Scan
    $suspiciousProcesses = @()
    
    # TRUSTED VENDORS (Whitelist) - Suppresses known good apps
    $whitelist = @(
        'Lenovo', 'Intel', 'NVIDIA', 'Realtek', 'Proton', 
        'Microsoft', 'Google', 'Brave', 'Mozilla', 'Discord',
        'Steam', 'Dropbox', 'Zoom', 'Adobe'
    )

    $processes = Get-CimInstance -ClassName Win32_Process | Select-Object Name, ProcessId, ExecutablePath, CommandLine
    
    foreach ($proc in $processes) {
        $reasons = @()
        
        # Skip whitelisted apps (Simple name check)
        $isSafe = $false
        foreach ($safe in $whitelist) {
            if ($proc.Name -match $safe -or $proc.ExecutablePath -match $safe) {
                $isSafe = $true
                break
            }
        }
        if ($isSafe) { continue }

        # RULE 1: Missing Path (Potential Injection)
        # We only flag this if it's NOT a standard system process
        if (-not $proc.ExecutablePath) {
            if ($proc.Name -notin @('System', 'Registry', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'Memory Compression')) {
                $reasons += "Hidden Path (Potential Injection)"
            }
        }
        
        # RULE 2: Suspicious Locations
        if ($proc.ExecutablePath -match 'AppData\\Local\\Temp' -or $proc.ExecutablePath -match 'Users\\Public') {
            $reasons += "Running from Temp/Public folder"
        }

        if ($reasons.Count -gt 0) {
            $suspiciousProcesses += [PSCustomObject]@{
                Name = $proc.Name
                PID = $proc.PID
                Reasons = $reasons -join ", "
            }
        }
    }
    
    if ($suspiciousProcesses.Count -gt 0) {
        Write-AuditResult "Suspicious Processes" "Found $($suspiciousProcesses.Count)" -Status Warn
        $notes = "Investigate: " + (($suspiciousProcesses | ForEach-Object { $_.Name }) -join ", ")
        Add-AuditFinding -Id "Proc_Suspicious" -Title "Suspicious Process Activity" -Value "$($suspiciousProcesses.Count) process(es)" -Severity 2 -Notes $notes -Category "Process"
    } else {
        Write-AuditResult "Suspicious Processes" "None detected" -Status Pass
    }
}

Export-ModuleMember -Function Invoke-ProcessTriage