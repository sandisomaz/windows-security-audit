<#
.SYNOPSIS
    Crypto miner detection module (FIXED: DateTime bug)
.DESCRIPTION
    Detects cryptocurrency miners with proper error handling for processes without StartTime
#>

using module .\Core.psm1

function Invoke-CryptoMinerDetection {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )
    
    Write-AuditHeader "Cryptocurrency Miner & Resource Hijacking Detection"
    
    # Known miner signatures
    $minerSignatures = @{
        Executables = @('xmrig.exe', 'cgminer.exe', 'claymore.exe', 'ethminer.exe', 
                       'nicehash.exe', 'minergate.exe', 'cpuminer.exe', 'bfgminer.exe',
                       'phoenixminer.exe', 'teamredminer.exe', 'lolminer.exe',
                       'trex.exe', 'nbminer.exe', 'gminer.exe')
        
        MiningPools = @('xmr-pool', 'nanopool', 'ethermine', 'f2pool', 'antpool',
                       'nicehash', 'minergate', 'monero', 'pool.supportxmr',
                       'monerohash', 'hashvault', 'minexmr')
        
        CommandLinePatterns = @('--algo', '--pool', '--user', '--pass', 
                               'stratum+tcp', 'stratum+ssl', '--donate-level',
                               '--cpu-priority', '--threads', 'cryptonight')
        
        SuspiciousFileSizes = @(
            @{Min=5.0; Max=6.0; Name="XMRig-like"},
            @{Min=3.5; Max=4.5; Name="CGMiner-like"},
            @{Min=8.0; Max=10.0; Name="Claymore-like"}
        )
    }
    
    Test-HighCPUProcesses
    Test-KnownMinerExecutables -Signatures $minerSignatures
    Test-MiningPoolConnections -Signatures $minerSignatures
    Test-SuspiciousAppDataExecutables -Signatures $minerSignatures
    Test-GPUUsage
    Test-HiddenMiningProcesses -Signatures $minerSignatures
}

function Test-HighCPUProcesses {
    Write-Host "Analyzing CPU usage patterns..." -ForegroundColor Cyan
    
    $cpuThreshold = 30
    $processes = Get-Process | Where-Object { $_.CPU -gt $cpuThreshold } | 
                 Sort-Object CPU -Descending | 
                 Select-Object -First 10
    
    if ($processes) {
        $suspiciousHighCPU = @()
        
        foreach ($proc in $processes) {
            # FIX: Properly check if StartTime exists and is valid
            if ($proc.StartTime -and $proc.StartTime -is [DateTime]) {
                try {
                    $runTime = (Get-Date) - $proc.StartTime
                    
                    # Only calculate CPU% if process has been running more than 1 second
                    if ($runTime.TotalSeconds -gt 1) {
                        $cpuPercent = [math]::Round(($proc.CPU / $runTime.TotalSeconds), 2)
                        
                        if ($cpuPercent -gt 50) {
                            $suspiciousHighCPU += [PSCustomObject]@{
                                Name = $proc.ProcessName
                                PID = $proc.Id
                                CPU_Percent = $cpuPercent
                                Path = $proc.Path
                                StartTime = $proc.StartTime
                            }
                        }
                    }
                }
                catch {
                    # Silently skip processes where calculation fails
                    Write-AuditLog "Could not calculate CPU for $($proc.ProcessName): $($_.Exception.Message)" -Level Debug
                }
            }
        }
        
        if ($suspiciousHighCPU.Count -gt 0) {
            Write-AuditResult "High CPU Usage" "Found $($suspiciousHighCPU.Count) process(es) with sustained high CPU" -Status Warn
            
            $details = $suspiciousHighCPU | ForEach-Object { "$($_.Name) ($($_.CPU_Percent)%)" }
            
            $notes = Format-FixRecommendation `
                -Problem "Detected processes with abnormally high CPU usage. This may indicate crypto mining or resource hijacking." `
                -ManualSteps @(
                    "Investigate these processes:",
                    ($details -join "`n"),
                    "",
                    "If suspicious:",
                    "1. Open Task Manager (Ctrl+Shift+Esc)",
                    "2. Right-click the process → 'Open file location'",
                    "3. If in AppData/Temp/Public → likely malware",
                    "4. End process and delete the file",
                    "5. Run full antivirus scan"
                ) `
                -MoreInfo "https://www.malwarebytes.com/blog/news/2018/03/cryptojacking"
            
            Add-AuditFinding `
                -Id "Miner_HighCPU" `
                -Title "Abnormal CPU Usage Pattern" `
                -Value "Found $($suspiciousHighCPU.Count) suspicious process(es)" `
                -Severity 2 `
                -Weight 15 `
                -Notes $notes `
                -Category "CryptoMiner"
        } else {
            Write-AuditResult "High CPU Usage" "No abnormal CPU usage detected" -Status Pass
            
            Add-AuditFinding `
                -Id "Miner_CPU_Clean" `
                -Title "CPU Usage Analysis" `
                -Value "Normal" `
                -Severity 1 `
                -Category "CryptoMiner"
        }
    } else {
        Write-AuditResult "High CPU Usage" "No high CPU processes found" -Status Pass
        
        Add-AuditFinding `
            -Id "Miner_CPU_Clean" `
            -Title "CPU Usage Analysis" `
            -Value "Normal" `
            -Severity 1 `
            -Category "CryptoMiner"
    }
}

function Test-KnownMinerExecutables {
    param($Signatures)
    
    Write-Host "Scanning for known mining software..." -ForegroundColor Cyan
    
    $foundMiners = @()
    $processes = Get-Process | Where-Object { $_.Path }
    
    foreach ($proc in $processes) {
        $procName = $proc.ProcessName.ToLower()
        
        foreach ($minerName in $Signatures.Executables) {
            if ($procName -like "*$($minerName.Replace('.exe','').ToLower())*") {
                $foundMiners += [PSCustomObject]@{
                    Name = $proc.ProcessName
                    PID = $proc.Id
                    Path = $proc.Path
                    MinerType = $minerName
                }
                
                Write-Host "  [!] Found known miner: $($proc.ProcessName) at $($proc.Path)" -ForegroundColor Red
            }
        }
    }
    
    if ($foundMiners.Count -gt 0) {
        Write-AuditResult "Known Mining Software" "DETECTED: $($foundMiners.Count) known miner(s)" -Status Fail
        
        $notes = Format-FixRecommendation `
            -Problem "CRITICAL: Known cryptocurrency mining software detected running on your system." `
            -QuickFix "Get-Process | Where-Object { `$_.ProcessName -match 'xmrig|cgminer|claymore' } | Stop-Process -Force" `
            -ManualSteps @(
                "IMMEDIATE ACTIONS:",
                "1. Disconnect from internet",
                "2. End these processes in Task Manager",
                "3. Delete the executable files",
                "4. Check startup entries (Autoruns)",
                "5. Run full antivirus scan",
                "",
                "Detected miners:",
                ($foundMiners | ForEach-Object { "- $($_.Name) ($($_.MinerType))" } | Out-String)
            ) `
            -IsSafe $false
        
        Add-AuditFinding `
            -Id "Miner_Known_Software" `
            -Title "Known Mining Software Detected" `
            -Value "Found: $($foundMiners.Count) miner(s)" `
            -Severity 0 `
            -Weight 25 `
            -Notes $notes `
            -Category "CryptoMiner"
    } else {
        Write-AuditResult "Known Mining Software" "None detected" -Status Pass
        
        Add-AuditFinding `
            -Id "Miner_Known_Clean" `
            -Title "Known Mining Software Scan" `
            -Value "Clean" `
            -Severity 1 `
            -Category "CryptoMiner"
    }
}

function Test-MiningPoolConnections {
    param($Signatures)
    
    Write-Host "Checking for connections to mining pools..." -ForegroundColor Cyan
    
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    $suspiciousConnections = @()
    
    foreach ($conn in $connections) {
        $remoteAddr = $conn.RemoteAddress
        $remotePort = $conn.RemotePort
        
        $miningPorts = @(3333, 4444, 5555, 7777, 8888, 9999, 14433, 14444)
        
        if ($remotePort -in $miningPorts) {
            $proc = Invoke-SafeCommand {
                (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue)
            }
            
            $suspiciousConnections += [PSCustomObject]@{
                ProcessName = if($proc){$proc.ProcessName}else{"Unknown"}
                PID = $conn.OwningProcess
                LocalPort = $conn.LocalPort
                RemoteAddress = $remoteAddr
                RemotePort = $remotePort
            }
        }
    }
    
    if ($suspiciousConnections.Count -gt 0) {
        Write-AuditResult "Mining Pool Connections" "DETECTED: $($suspiciousConnections.Count) suspicious connection(s)" -Status Fail
        
        $connDetails = $suspiciousConnections | ForEach-Object {
            "$($_.ProcessName) → $($_.RemoteAddress):$($_.RemotePort)"
        }
        
        $notes = Format-FixRecommendation `
            -Problem "Active connections to ports commonly used by mining pools detected." `
            -ManualSteps @(
                "Suspicious connections found:",
                ($connDetails -join "`n"),
                "",
                "Common mining pool ports: 3333, 4444, 5555, 7777",
                "",
                "TO INVESTIGATE:",
                "1. Note the process name and PID",
                "2. Open Task Manager and find the process",
                "3. Right-click → 'Open file location'",
                "4. If location is suspicious (AppData/Temp) → malware",
                "5. Kill process and delete file",
                "6. Block the IP in firewall"
            )
        
        Add-AuditFinding `
            -Id "Miner_PoolConnection" `
            -Title "Mining Pool Network Connections" `
            -Value "Found $($suspiciousConnections.Count) connection(s)" `
            -Severity 0 `
            -Weight 25 `
            -Notes $notes `
            -Category "CryptoMiner"
    } else {
        Write-AuditResult "Mining Pool Connections" "None detected" -Status Pass
        
        Add-AuditFinding `
            -Id "Miner_Pool_Clean" `
            -Title "Mining Pool Connection Check" `
            -Value "Clean" `
            -Severity 1 `
            -Category "CryptoMiner"
    }
}

function Test-SuspiciousAppDataExecutables {
    param($Signatures)
    
    Write-Host "Scanning AppData for suspicious executables..." -ForegroundColor Cyan
    
    $scanPaths = @(
        "$env:USERPROFILE\AppData\Local",
        "$env:USERPROFILE\AppData\Roaming",
        "$env:PROGRAMDATA"
    )
    
    $suspiciousFiles = @()
    $foundPaths = [System.Collections.Generic.HashSet[string]]::new()
    
    foreach ($path in $scanPaths) {
        if (-not (Test-Path $path)) { continue }
        
        try {
            $files = Get-ChildItem -Path $path -Include @('*.exe', '*.bin') -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -gt 3MB -and $_.Length -lt 12MB } |
                Select-Object -First 50
            
            foreach ($file in $files) {
                $fileSizeMB = [math]::Round($file.Length / 1MB, 1)
                
                foreach ($sizePattern in $Signatures.SuspiciousFileSizes) {
                    if ($foundPaths.Contains($file.FullName)) { continue }

                    if ($fileSizeMB -ge $sizePattern.Min -and $fileSizeMB -le $sizePattern.Max) {
                        if ($foundPaths.Add($file.FullName)) {
                            $suspiciousFiles += [PSCustomObject]@{
                                Name     = $file.Name
                                Path     = $file.FullName
                                SizeMB   = $fileSizeMB
                                Modified = $file.LastWriteTime
                                Pattern  = $sizePattern.Name
                            }
                        }
                    }
                }
                
                if ($file.DirectoryName -match 'updates?|service|system|windows' -and 
                    $file.Name -notmatch 'microsoft|windows|intel|nvidia|amd' -and
                    -not $foundPaths.Contains($file.FullName)) {
                    if ($foundPaths.Add($file.FullName)) {
                        $suspiciousFiles += [PSCustomObject]@{
                            Name     = $file.Name
                            Path = $file.FullName
                            SizeMB = $fileSizeMB
                            Modified = $file.LastWriteTime
                            Pattern = "Suspicious folder name"
                        }
                    }
                }
            }
        }
        catch {
            Write-AuditLog "Error scanning $path : $($_.Exception.Message)" -Level Warning
        }
    }
    
    if ($suspiciousFiles.Count -gt 0) {
        Write-AuditResult "Suspicious Executables in AppData" "Found $($suspiciousFiles.Count) suspicious file(s)" -Status Fail
        
        $fileList = $suspiciousFiles | ForEach-Object {
            "$($_.Name) ($($_.SizeMB) MB) - $($_.Path) - Pattern: $($_.Pattern)"
        }
        
        $notes = Format-FixRecommendation `
            -Problem "Suspicious executable files found in user directories. These match known crypto miner patterns." `
            -ManualSteps @(
                "Suspicious files detected:",
                ($fileList -join "`n"),
                "",
                "TO REMOVE:",
                "1. Boot into Safe Mode (Shift + Restart)",
                "2. Delete these files and their parent folders",
                "3. Check registry for persistence (Autoruns)",
                "4. Run: sfc /scannow",
                "5. Full antivirus scan"
            )
        
        Add-AuditFinding `
            -Id "Miner_SuspiciousFiles" `
            -Title "Suspicious Executables in User Directories" `
            -Value "Found $($suspiciousFiles.Count) file(s)" `
            -Severity 0 `
            -Weight 25 `
            -Notes $notes `
            -Category "CryptoMiner"
    } else {
        Write-AuditResult "Suspicious Executables" "None detected" -Status Pass
        
        Add-AuditFinding `
            -Id "Miner_Files_Clean" `
            -Title "Suspicious Executable Scan" `
            -Value "Clean" `
            -Severity 1 `
            -Category "CryptoMiner"
    }
}

function Test-GPUUsage {
    Write-Host "Checking GPU usage (if available)..." -ForegroundColor Cyan
    
    $nvidiaPath = "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
    
    if (Test-Path $nvidiaPath) {
        try {
            $gpuInfo = & $nvidiaPath --query-gpu=utilization.gpu,temperature.gpu --format=csv,noheader,nounits
            
            if ($gpuInfo) {
                $usage, $temp = $gpuInfo -split ','
                $usage = [int]$usage.Trim()
                $temp = [int]$temp.Trim()
                
                if ($usage -gt 80) {
                    Write-AuditResult "GPU Usage" "$usage% (High - Potential mining activity)" -Status Warn
                    
                    $notes = Format-FixRecommendation `
                        -Problem "GPU usage is abnormally high ($usage%). This may indicate GPU-based crypto mining." `
                        -ManualSteps @(
                            "Check which process is using the GPU:",
                            "1. Open Task Manager → Performance tab → GPU",
                            "2. Look for unfamiliar processes using GPU",
                            "3. Common GPU miners: ethminer, phoenixminer, claymore",
                            "4. If found, end process and delete"
                        )
                    
                    Add-AuditFinding `
                        -Id "Miner_GPU_High" `
                        -Title "High GPU Usage" `
                        -Value "$usage% utilization" `
                        -Severity 2 `
                        -Notes $notes `
                        -Category "CryptoMiner"
                } else {
                    Write-AuditResult "GPU Usage" "$usage% (Normal)" -Status Pass
                }
            }
        }
        catch {
            Write-AuditResult "GPU Usage" "Could not query" -Status Info
        }
    } else {
        Write-AuditResult "GPU Usage" "nvidia-smi not found (may not have NVIDIA GPU)" -Status Info
    }
}

function Test-HiddenMiningProcesses {
    param($Signatures)
    
    Write-Host "Searching for hidden/renamed mining processes..." -ForegroundColor Cyan
    
    $processes = Get-CimInstance Win32_Process | 
                 Where-Object { $_.CommandLine } |
                 Select-Object ProcessId, Name, CommandLine, ExecutablePath
    
    $hiddenMiners = @()
    
    foreach ($proc in $processes) {
        $cmdLine = $proc.CommandLine.ToLower()
        
        foreach ($pattern in $Signatures.CommandLinePatterns) {
            if ($cmdLine -match $pattern.ToLower()) {
                $hiddenMiners += [PSCustomObject]@{
                    Name = $proc.Name
                    PID = $proc.ProcessId
                    Path = $proc.ExecutablePath
                    CommandLine = $proc.CommandLine
                    DetectedPattern = $pattern
                }
                break
            }
        }
    }
    
    if ($hiddenMiners.Count -gt 0) {
        Write-AuditResult "Hidden Mining Processes" "DETECTED: $($hiddenMiners.Count) process(es) with mining arguments" -Status Fail
        
        $notes = Format-FixRecommendation `
            -Problem "Processes with cryptocurrency mining command-line arguments detected. These may be renamed or disguised miners." `
            -ManualSteps @(
                "Detected processes:",
                ($hiddenMiners | ForEach-Object { "- $($_.Name) (PID: $($_.PID))" } | Out-String),
                "",
                "These processes contain mining-related arguments like:",
                "- Pool addresses (stratum+tcp://...)",
                "- Mining algorithms (--algo)",
                "- Worker credentials",
                "",
                "REMOVE IMMEDIATELY"
            )
        
        Add-AuditFinding `
            -Id "Miner_Hidden" `
            -Title "Hidden Mining Processes" `
            -Value "Found $($hiddenMiners.Count) process(es)" `
            -Severity 0 `
            -Weight 25 `
            -Notes $notes `
            -Category "CryptoMiner"
    } else {
        Write-AuditResult "Hidden Mining Processes" "None detected" -Status Pass
        
        Add-AuditFinding `
            -Id "Miner_Hidden_Clean" `
            -Title "Hidden Mining Process Scan" `
            -Value "Clean" `
            -Severity 1 `
            -Category "CryptoMiner"
    }
}

Export-ModuleMember -Function Invoke-CryptoMinerDetection