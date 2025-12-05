<#
.SYNOPSIS
    Deep process triage and memory inspection module
.DESCRIPTION
    Performs advanced process analysis including:
    - Process injection detection (missing paths)
    - Fileless malware detection (suspicious command lines)
    - Unsigned binary detection in suspicious locations
    - Network listening process detection
#>

using module .\Core.psm1

function Invoke-ProcessTriage {
    <#
    .SYNOPSIS
        Performs comprehensive process analysis
    .PARAMETER Config
        Configuration object from Config.psd1
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )
    
    Write-AuditHeader "Deep Process Triage (Memory Inspection)"
    
    # Get configuration
    $suspiciousPaths = $Config.Detection.SuspiciousPaths
    $suspiciousCmdKeywords = $Config.Detection.SuspiciousCmdKeywords
    $pathlessWhitelist = $Config.Detection.PathlessWhitelist
    
    # Get all listening TCP connections once for efficiency
    $listeningPIDs = @{}
    $listeners = Invoke-SafeCommand { 
        Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue 
    }
    if ($listeners) { 
        $listeners | ForEach-Object { $listeningPIDs[$_.OwningProcess] = $true } 
    }
    
    # Get all processes with detailed information
    $processes = Get-CimInstance -ClassName Win32_Process | 
        Select-Object Name, ExecutablePath, ProcessId, CommandLine, CreationDate
    
    $suspiciousProcesses = @()
    $unsignedProcesses = @()
    $counter = 0
    $total = $processes.Count
    
    Write-Host "Analyzing $total processes..." -ForegroundColor Cyan
    
    foreach ($proc in $processes) {
        $counter++
        
        if ($counter % 10 -eq 0) {
            Write-Progress -Activity "Deep Process Triage" `
                -Status "Checking $($proc.Name) (PID $($proc.ProcessId))" `
                -PercentComplete (($counter / $total) * 100)
        }
        
        $reasons = @()
        
        # === CHECK 1: Missing Executable Path (Process Injection) ===
        if (-not $proc.ExecutablePath) {
            if ($proc.Name -notin $pathlessWhitelist) {
                if ([string]::IsNullOrEmpty($proc.Name)) {
                    $reasons += "CRITICAL: Process with no name and no path"
                } else {
                    $reasons += "Missing Executable Path (Possible Injection)"
                }
            }
        }
        
        # === CHECK 2: Suspicious Command Line (Fileless Malware) ===
        if ($proc.CommandLine) {
            foreach ($keyword in $suspiciousCmdKeywords) {
                if ($proc.CommandLine -match [regex]::Escape($keyword)) {
                    # Exclude benign PowerShell usage
                    if ($proc.CommandLine -notmatch 'Windows Defender|SecurityHealth') {
                        $reasons += "Suspicious CommandLine: Contains '$keyword'"
                        break
                    }
                }
            }
        }
        
        # === CHECK 3: Unsigned Binary in Suspicious Location ===
        if ($proc.ExecutablePath) {
            $inSuspiciousPath = $false
            
            foreach ($suspPath in $suspiciousPaths) {
                if ($proc.ExecutablePath -match [regex]::Escape($suspPath)) {
                    $inSuspiciousPath = $true
                    break
                }
            }
            
            if ($inSuspiciousPath) {
                $signature = Invoke-SafeCommand {
                    Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction Stop
                }
                
                if ($signature -and $signature.Status -ne 'Valid') {
                    $reasons += "Unsigned Binary in Suspicious Directory"
                    
                    $unsignedProcesses += [PSCustomObject]@{
                        Name = $proc.Name
                        PID = $proc.ProcessId
                        Path = $proc.ExecutablePath
                        SignatureStatus = $signature.Status
                    }
                }
            }
        }
        
        # === CHECK 4: Listening on Network Port ===
        if ($listeningPIDs.ContainsKey($proc.ProcessId)) {
            $reasons += "Listening on Network Port"
        }
        
        # === CHECK 5: Recently Created Process ===
        if ($proc.CreationDate) {
            $age = (Get-Date) - $proc.CreationDate
            if ($age.TotalMinutes -lt 5) {
                $reasons += "Recently Started (< 5 minutes ago)"
            }
        }
        
        # If any suspicious indicators found, log it
        if ($reasons.Count -gt 0) {
            $suspiciousProcesses += [PSCustomObject]@{
                Name = $proc.Name
                PID = $proc.ProcessId
                Path = $proc.ExecutablePath
                Reasons = $reasons -join "; "
                CommandLine = $proc.CommandLine
                Created = $proc.CreationDate
            }
        }
    }
    
    Write-Progress -Activity "Deep Process Triage" -Completed
    
    # === REPORT RESULTS ===
    
    # High-risk processes
    if ($suspiciousProcesses.Count -gt 0) {
        Write-AuditResult "High-Risk Processes" `
            "Found $($suspiciousProcesses.Count) suspicious process(es)" `
            -Status Fail
        
        $detailsJson = $suspiciousProcesses | ConvertTo-Json -Compress
        
        Add-AuditFinding `
            -Id "Proc_HighRisk" `
            -Title "High-Risk Process Activity" `
            -Value "Found $($suspiciousProcesses.Count) process(es)" `
            -Severity 0 `
            -Weight 25 `
            -Notes "CRITICAL: Detected suspicious processes. Details: $detailsJson" `
            -Category "Process"
        
        Write-Host ""
        Write-Host "!!! CRITICAL: High-Risk Processes Detected !!!" -ForegroundColor Red
        $suspiciousProcesses | Format-Table -Wrap -AutoSize
        Write-Host ""
    } else {
        Write-AuditResult "High-Risk Processes" "None detected" -Status Pass
        
        Add-AuditFinding `
            -Id "Proc_Clean" `
            -Title "High-Risk Process Activity" `
            -Value "None detected" `
            -Severity 1 `
            -Category "Process"
    }
    
    # Unsigned processes summary
    if ($unsignedProcesses.Count -gt 0) {
        Write-AuditResult "Unsigned Processes" `
            "Found $($unsignedProcesses.Count) unsigned process(es) in suspicious locations" `
            -Status Warn
        
        Add-AuditFinding `
            -Id "Proc_Unsigned" `
            -Title "Unsigned Processes" `
            -Value "$($unsignedProcesses.Count) found" `
            -Severity 2 `
            -Weight 15 `
            -Category "Process"
    } else {
        Write-AuditResult "Unsigned Processes" "None found in suspicious locations" -Status Pass
    }
    
    # Top CPU/Memory processes (informational)
    Write-Host ""
    Write-Host "Top Resource-Consuming Processes:" -ForegroundColor Gray
    $topProc = Get-Process | 
        Sort-Object CPU -Descending | 
        Select-Object -First 5
    
    foreach ($p in $topProc) {
        $memMB = [math]::Round($p.WorkingSet / 1MB, 2)
        $cpuRounded = [math]::Round($p.CPU, 2)
        
        Write-AuditResult "  Top Process" `
            "$($p.Name) (PID:$($p.Id)) - CPU:$cpuRounded | Mem:${memMB}MB" `
            -Status Info
        
        Add-AuditFinding `
            -Id "Proc_Top_$($p.Id)" `
            -Title "High Resource Process" `
            -Value "$($p.Name) - CPU:$cpuRounded | Mem:${memMB}MB" `
            -Severity 3 `
            -Category "Process"
    }
}

Export-ModuleMember -Function Invoke-ProcessTriage