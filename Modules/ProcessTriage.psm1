<#
.SYNOPSIS
    Deep process triage and memory inspection module
#>

using module .\Core.psm1

function Invoke-ProcessTriage {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )
    
    Write-AuditHeader "Deep Process Triage (Memory Inspection)"
    
    $vtApiKey = $Config.Advanced.VirusTotalAPIKey
    
    $suspiciousPaths = $Config.Detection.SuspiciousPaths
    $suspiciousCmdKeywords = $Config.Detection.SuspiciousCmdKeywords
    $pathlessWhitelist = $Config.Detection.PathlessWhitelist
    
    $listeningPIDs = @{}
    $listeners = Invoke-SafeCommand { Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue }
    if ($listeners) { 
        $listeners | ForEach-Object { $listeningPIDs[$_.OwningProcess] = $true } 
    }
    
    $processes = Get-CimInstance -ClassName Win32_Process | Select-Object Name, ExecutablePath, ProcessId, CommandLine, CreationDate
    
    $suspiciousProcesses = @()
    $unsignedProcesses = @()
    $counter = 0
    $total = $processes.Count
    
    Write-Host "Analyzing $total processes..." -ForegroundColor Cyan
    
    foreach ($proc in $processes) {
        $counter++
        Write-Progress -Activity "Deep Process Triage" -Status "Checking $($proc.Name) (PID $($proc.ProcessId))" -PercentComplete (($counter / $total) * 100)
        
        $reasons = @()
        
        if (-not $proc.ExecutablePath -and $proc.Name -notin $pathlessWhitelist) {
            $reasons += "Missing Executable Path (Possible Injection)"
        }
        
        if ($proc.CommandLine) {
            foreach ($keyword in $suspiciousCmdKeywords) {
                if ($proc.CommandLine -match [regex]::Escape($keyword)) {
                    if ($proc.CommandLine -notmatch 'Windows Defender|SecurityHealth') {
                        $reasons += "Suspicious CommandLine: Contains '$keyword'"
                        break
                    }
                }
            }
        }
        
        if ($proc.ExecutablePath) {
            $inSuspiciousPath = $false
            foreach ($suspPath in $suspiciousPaths) {
                if ($proc.ExecutablePath -match [regex]::Escape($suspPath)) {
                    $inSuspiciousPath = $true
                    break
                }
            }
            
            if ($inSuspiciousPath) {
                $signature = Invoke-SafeCommand { Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction Stop }
                if ($signature -and $signature.Status -ne 'Valid') {
                    $reasons += "Unsigned Binary in Suspicious Directory"
                }
            }
        }

        if ($listeningPIDs.ContainsKey($proc.ProcessId)) {
            $reasons += "Listening on Network Port"
        }
        
        if ($reasons.Count -gt 0) {
            $suspiciousProcesses += [PSCustomObject]@{
                Name = $proc.Name; PID = $proc.ProcessId; Path = $proc.ExecutablePath; Reasons = $reasons -join "; "; CommandLine = $proc.CommandLine
            }
        }
    }
    
    Write-Progress -Activity "Deep Process Triage" -Completed
    
    if ($suspiciousProcesses.Count -gt 0) {
        Write-AuditResult "High-Risk Processes" "Found $($suspiciousProcesses.Count) suspicious process(es)" -Status Fail
        $notes = "CRITICAL: Detected processes with high-risk characteristics. Investigate each process listed in the report. Details: " + ($suspiciousProcesses | ConvertTo-Json -Compress)
        Add-AuditFinding -Id "Proc_HighRisk" -Title "High-Risk Process Activity" -Value "Found $($suspiciousProcesses.Count) process(es)" -Severity 0 -Weight 25 -Notes $notes -Category "Process"
    } else {
        Write-AuditResult "High-Risk Processes" "None detected" -Status Pass
        Add-AuditFinding -Id "Proc_Clean" -Title "High-Risk Process Activity" -Value "None detected" -Severity 1 -Category "Process"
    }
}

Export-ModuleMember -Function Invoke-ProcessTriage