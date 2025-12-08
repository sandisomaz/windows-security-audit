<#
.SYNOPSIS
    Deep process triage module (FIXED: Eliminates false positives)
.DESCRIPTION
    Detects process injection, fileless malware, unsigned binaries
    NOW WITH: Smart whitelisting of legitimate kernel processes
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
    
    # FIX: Comprehensive whitelist of legitimate Windows processes
    $legitimateProcesses = @(
        # Core Windows Kernel
        'System Idle Process', 'System', 'Secure System', 'Registry',
        
        # Windows Security
        'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe',
        'winlogon.exe', 'fontdrvhost.exe',
        
        # Windows Defender Components
        'MsMpEng.exe',        # Microsoft Malware Protection Engine
        'NisSrv.exe',         # Network Inspection Service
        'SecurityHealthService.exe',  # Windows Security Health
        'SgrmBroker.exe',     # System Guard Runtime Monitor
        
        # Windows Security Isolation
        'LsaIso.exe',         # Credential Guard (Virtualization-based security)
        'NgcIso.exe',         # Windows Hello isolation process
        
        # Windows Core Services
        'svchost.exe', 'dwm.exe', 'RuntimeBroker.exe',
        'taskhostw.exe', 'dllhost.exe', 'conhost.exe',
        
        # Memory Management
        'Memory Compression',  # Windows Memory Compression (kernel process)
        
        # Print Spooler (legitimate listening service)
        'spoolsv.exe'
    )
    
    # Get listening ports mapping
    $listeningPIDs = @{}
    $listeners = Invoke-SafeCommand { Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue }
    if ($listeners) { 
        $listeners | ForEach-Object { $listeningPIDs[$_.OwningProcess] = $true } 
    }
    
    $processes = Get-CimInstance -ClassName Win32_Process | 
                 Select-Object Name, ExecutablePath, ProcessId, CommandLine, CreationDate
    
    $suspiciousProcesses = @()
    $counter = 0
    $total = $processes.Count
    
    Write-Host "Analyzing $total processes..." -ForegroundColor Cyan
    
    foreach ($proc in $processes) {
        $counter++
        Write-Progress -Activity "Deep Process Triage" -Status "Checking $($proc.Name) (PID $($proc.ProcessId))" -PercentComplete (($counter / $total) * 100)
        
        $reasons = @()
        
        # SKIP: Legitimate Windows processes completely
        if ($proc.Name -in $legitimateProcesses) {
            continue
        }
        
        # RULE 1: Missing Executable Path (BUT NOT if whitelisted)
        if (-not $proc.ExecutablePath -and $proc.Name -notin $pathlessWhitelist) {
            $reasons += "Missing Executable Path (Possible Injection)"
        }
        
        # RULE 2: Suspicious Command Line (BUT NOT for Windows components)
        if ($proc.CommandLine) {
            # Skip Windows system processes
            if ($proc.ExecutablePath -notmatch 'Windows\\System32|Windows\\SysWOW64|Program Files') {
                foreach ($keyword in $suspiciousCmdKeywords) {
                    if ($proc.CommandLine -match [regex]::Escape($keyword)) {
                        if ($proc.CommandLine -notmatch 'Windows Defender|SecurityHealth') {
                            $reasons += "Suspicious CommandLine: Contains '$keyword'"
                            break
                        }
                    }
                }
            }
        }
        
        # RULE 3: Unsigned Binary in Suspicious Directory
        if ($proc.ExecutablePath) {
            $inSuspiciousPath = $false
            foreach ($suspPath in $suspiciousPaths) {
                if ($proc.ExecutablePath -match [regex]::Escape($suspPath)) {
                    $inSuspiciousPath = $true
                    break
                }
            }
            
            # ONLY flag if BOTH suspicious path AND unsigned
            if ($inSuspiciousPath) {
                $signature = Invoke-SafeCommand { 
                    Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction Stop 
                }
                if ($signature -and $signature.Status -ne 'Valid') {
                    $reasons += "Unsigned Binary in Suspicious Directory"
                }
            }
        }

        # RULE 4: Listening on Network Port (BUT ONLY if in suspicious location)
        if ($listeningPIDs.ContainsKey($proc.ProcessId)) {
            # ALLOW: System processes and signed applications
            if ($proc.ExecutablePath) {
                # If in System32 or Program Files, it's probably legitimate
                if ($proc.ExecutablePath -notmatch 'Windows\\System32|Windows\\SysWOW64|Program Files') {
                    # Check if signed
                    $signature = Invoke-SafeCommand { 
                        Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction Stop 
                    }
                    if (-not $signature -or $signature.Status -ne 'Valid') {
                        $reasons += "Listening on Network Port (Unsigned)"
                    }
                }
            }
        }
        
        # ONLY add if we found actual suspicious reasons
        if ($reasons.Count -gt 0) {
            $suspiciousProcesses += [PSCustomObject]@{
                Name = $proc.Name
                PID = $proc.ProcessId
                Path = $proc.ExecutablePath
                Reasons = $reasons -join "; "
                CommandLine = $proc.CommandLine
            }
        }
    }
    
    Write-Progress -Activity "Deep Process Triage" -Completed
    
    if ($suspiciousProcesses.Count -gt 0) {
        Write-AuditResult "High-Risk Processes" "Found $($suspiciousProcesses.Count) suspicious process(es)" -Status Fail
        
        # Show details
        Write-Host "`nSuspicious Processes Detected:" -ForegroundColor Red
        foreach ($proc in $suspiciousProcesses) {
            Write-Host "  - $($proc.Name) (PID: $($proc.PID))" -ForegroundColor Yellow
            Write-Host "    Reasons: $($proc.Reasons)" -ForegroundColor Gray
            if ($proc.Path) {
                Write-Host "    Path: $($proc.Path)" -ForegroundColor Gray
            }
        }
        
        $notes = "CRITICAL: Detected processes with high-risk characteristics. Investigate each process listed in the report. Details: " + ($suspiciousProcesses | ConvertTo-Json -Compress)
        
        Add-AuditFinding `
            -Id "Proc_HighRisk" `
            -Title "High-Risk Process Activity" `
            -Value "Found $($suspiciousProcesses.Count) process(es)" `
            -Severity 0 `
            -Weight 25 `
            -Notes $notes `
            -Category "Process"
    } else {
        Write-AuditResult "High-Risk Processes" "None detected" -Status Pass
        
        Add-AuditFinding `
            -Id "Proc_Clean" `
            -Title "High-Risk Process Activity" `
            -Value "None detected" `
            -Severity 1 `
            -Category "Process"
    }
}

Export-ModuleMember -Function Invoke-ProcessTriage