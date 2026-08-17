#Requires -Version 5.1
<#
.SYNOPSIS
    Crypto-currency miner detection module.
.DESCRIPTION
    Detects mining malware via CPU usage analysis, known executable signatures,
    stratum pool connections, GPU utilization, and command-line pattern matching.
    All signature lists are configured in Config.psd1 under Signatures.Miner*.
.NOTES
    Version : 5.5.0
    Requires: PowerShell 5.1+, Administrator
#>

using module .\Core.psm1

function Invoke-CryptoMinerDetection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )

    Write-AuditHeader 'Crypto-Miner Detection'

    # Resolve signature lists from Config with safe defaults
    $script:MinerExes    = if ($Config.Signatures.MinerExecutables)    { $Config.Signatures.MinerExecutables }    else { @('xmrig.exe','cgminer.exe','ethminer.exe','cpuminer.exe') }
    $script:MinerPools   = if ($Config.Signatures.MiningPools)         { $Config.Signatures.MiningPools }         else { @('xmr-pool','nanopool','ethermine','nicehash') }
    $script:MinerPorts   = if ($Config.Signatures.MiningPorts)         { $Config.Signatures.MiningPorts }         else { @(3333,4444,5555,7777,8888,9999,14433,14444) }
    $script:MinerCmds    = if ($Config.Signatures.MinerCommandPatterns) { $Config.Signatures.MinerCommandPatterns } else { @('--algo=','--algo ','--pool=','stratum+tcp://','stratum+ssl://','--donate-level=','cryptonight','randomx') }
    $script:CpuThreshold = if ($Config.Thresholds.SuspiciousCPUPercent) { $Config.Thresholds.SuspiciousCPUPercent } else { 40 }
    $script:NvidiaSmi    = if ($Config.Advanced.NvidiaSmiPath -and (Test-Path $Config.Advanced.NvidiaSmiPath)) { $Config.Advanced.NvidiaSmiPath } else { 'nvidia-smi' }

    Test-HighCPUProcesses
    Test-KnownMinerExecutables
    Test-MiningPoolConnections
    Test-SuspiciousMinerFiles -Config $Config
    Test-GPUUtilization
    Test-HiddenMinerPatterns
}

function Test-HighCPUProcesses {
    Write-Host 'Checking for processes with sustained high CPU usage...' -ForegroundColor Cyan

    $logicalCores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    if ($logicalCores -lt 1) { $logicalCores = 1 }

    $processes = Get-Process | Where-Object { $_.CPU -gt 0 -and $_.TotalProcessorTime } | Sort-Object CPU -Descending

    $highCpuProcesses = @()
    foreach ($proc in $processes) {
        try {
            $elapsedSeconds = ([datetime]::Now - $proc.StartTime).TotalSeconds
        } catch { continue } # Access denied on some processes

        if ($elapsedSeconds -lt 10) { continue }  # Ignore very new processes

        # Normalise: percentage of one logical core per elapsed real second
        $cpuPercent = [math]::Round(($proc.CPU / $elapsedSeconds / $logicalCores) * 100, 1)

        if ($cpuPercent -gt $script:CpuThreshold) {
            $highCpuProcesses += [PSCustomObject]@{
                Name       = $proc.ProcessName
                PID        = $proc.Id
                CPUPercent = $cpuPercent
                Path       = $proc.Path
            }
        }
    }

    if ($highCpuProcesses.Count -gt 0) {
        Write-AuditResult 'High CPU Processes' "Found $($highCpuProcesses.Count) process(es) above ${script:CpuThreshold}%" -Status Warn
        $detail = ($highCpuProcesses | ForEach-Object { "$($_.Name) (PID $($_.PID)): $($_.CPUPercent)%" }) -join ', '
        $notes  = Format-FixRecommendation `
            -Problem "One or more processes are consuming >$($script:CpuThreshold)% of a CPU core continuously, which is a common mining indicator." `
            -ManualSteps @(
                "Processes: $detail",
                '1. Open Task Manager and confirm the CPU usage.',
                '2. Check the process file location; miners often run from AppData.',
                '3. Search the process name online to verify legitimacy.',
                '4. If confirmed as a miner, terminate and delete the binary.'
            )
        Add-AuditFinding -Id 'Miner_HighCPU' -Title 'High CPU Usage (Potential Miner)' `
            -Value "$($highCpuProcesses.Count) process(es)" -Severity 2 -Weight 15 -Notes $notes -Category 'CryptoMiner'
    } else {
        Write-AuditResult 'High CPU Processes' 'None detected' -Status Pass
        Add-AuditFinding -Id 'Miner_CPU_Clean' -Title 'CPU Usage' -Value 'No sustained high usage' -Severity 1 -Category 'CryptoMiner'
    }
}

function Test-KnownMinerExecutables {
    Write-Host 'Checking for known miner executables...' -ForegroundColor Cyan

    $running = Get-Process | Select-Object ProcessName, Id, Path
    $detected = @()

    foreach ($proc in $running) {
        foreach ($miner in $script:MinerExes) {
            $exeName = [IO.Path]::GetFileName($miner)
            if ($proc.ProcessName -like ($exeName -replace '\.exe$', '')) {
                $detected += $proc
            }
        }
    }

    if ($detected.Count -gt 0) {
        Write-AuditResult 'Known Miner Executables' "DETECTED: $($detected.Count)" -Status Fail
        $info  = ($detected | ForEach-Object { "$($_.ProcessName) (PID: $($_.Id))" }) -join ', '
        $notes = Format-FixRecommendation `
            -Problem "A process matching a known cryptocurrency miner signature is actively running." `
            -ManualSteps @(
                "Detected: $info",
                '1. Immediately terminate the process via Task Manager.',
                '2. Locate and delete the binary from disk.',
                '3. Check startup locations (Task Scheduler, Registry Run keys) for persistence.',
                '4. Run a full antivirus scan.'
            )
        Add-AuditFinding -Id 'Miner_Known_Software' -Title 'Known Miner Running' `
            -Value "$($detected.Count) found" -Severity 0 -Weight 25 -Notes $notes -Category 'CryptoMiner'
    } else {
        Write-AuditResult 'Known Miner Executables' 'None detected' -Status Pass
    }
}

function Test-MiningPoolConnections {
    Write-Host 'Checking for active mining pool connections...' -ForegroundColor Cyan

    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    $miningConns = $connections | Where-Object { $_.RemotePort -in $script:MinerPorts }

    if ($miningConns) {
        Write-AuditResult 'Mining Pool Connections' "DETECTED: $($miningConns.Count)" -Status Fail
        $detail = $miningConns | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            "Port $($_.RemotePort) -> $($_.RemoteAddress) by '$($proc.ProcessName)' (PID $($_.OwningProcess))"
        }
        $notes = Format-FixRecommendation `
            -Problem 'Active TCP connections to well-known stratum mining pool ports were detected.' `
            -ManualSteps @(
                ($detail -join "`n"),
                '1. Identify the owning process in Task Manager.',
                '2. Terminate the process and delete its binary.',
                '3. Create a Windows Firewall outbound block rule for these ports.'
            )
        Add-AuditFinding -Id 'Miner_PoolConnection' -Title 'Mining Pool Connection' `
            -Value "$($miningConns.Count) active connection(s)" -Severity 0 -Weight 25 -Notes $notes -Category 'CryptoMiner'
    } else {
        Write-AuditResult 'Mining Pool Connections' 'None detected' -Status Pass
    }
}

function Test-SuspiciousMinerFiles {
    param([hashtable]$Config)
    Write-Host 'Scanning for miner binaries in user-writable directories...' -ForegroundColor Cyan

    $searchPaths = @(
        $env:LOCALAPPDATA,
        $env:APPDATA,
        $env:ProgramData
    )

    $suspiciousFiles = @()

    foreach ($path in $searchPaths) {
        if (-not (Test-Path $path)) { continue }
        $exeFiles = Get-ChildItem -Path $path -Filter '*.exe' -Recurse -ErrorAction SilentlyContinue -Depth 4 |
            Where-Object { $_.Length -gt 1MB -and $_.Length -lt 50MB }

        foreach ($file in $exeFiles) {
            $isMiner = $false
            foreach ($minerName in $script:MinerExes) {
                if ($file.Name -like $minerName) { $isMiner = $true; break }
            }
            if ($isMiner) { $suspiciousFiles += $file }
        }
    }

    if ($suspiciousFiles.Count -gt 0) {
        Write-AuditResult 'Miner Binaries in AppData' "Found $($suspiciousFiles.Count)" -Status Fail
        $fileList = ($suspiciousFiles | ForEach-Object { $_.FullName }) -join ', '
        $notes = Format-FixRecommendation `
            -Problem 'Executable files matching known miner names were found in user-writable directories.' `
            -ManualSteps @(
                "Files: $fileList",
                '1. Confirm these are not legitimate applications.',
                '2. Delete the files.',
                '3. Check Task Scheduler and Registry autoruns for persistence.'
            )
        Add-AuditFinding -Id 'Miner_SuspiciousFiles' -Title 'Miner Binary in AppData' `
            -Value "$($suspiciousFiles.Count) file(s)" -Severity 0 -Weight 20 -Notes $notes -Category 'CryptoMiner'
    } else {
        Write-AuditResult 'Miner Binaries in AppData' 'None found' -Status Pass
    }
}

function Test-GPUUtilization {
    Write-Host 'Checking GPU utilization (NVIDIA)...' -ForegroundColor Cyan

    try {
        $nvOutput = & $script:NvidiaSmi '--query-gpu=utilization.gpu' '--format=csv,noheader,nounits' 2>$null
        if (-not $nvOutput) { Write-AuditResult 'GPU (NVIDIA)' 'Not detected or driver unavailable' -Status Info; return }

        $gpuPercent = [int]($nvOutput -replace '[^0-9]', '')
        if ($gpuPercent -gt 80) {
            Write-AuditResult 'GPU Utilization' "$gpuPercent% (HIGH)" -Status Warn
            Add-AuditFinding -Id 'Miner_GPU_High' -Title 'High GPU Utilization' -Value "$gpuPercent%" `
                -Severity 2 -Notes 'GPU utilization exceeds 80%. GPU miners silently consume graphics card resources.' -Category 'CryptoMiner'
        } else {
            Write-AuditResult 'GPU Utilization' "$gpuPercent% (Normal)" -Status Pass
        }
    } catch {
        Write-AuditResult 'GPU (NVIDIA)' 'Check skipped (nvidia-smi unavailable)' -Status Info
    }
}

function Test-HiddenMinerPatterns {
    Write-Host 'Scanning process command lines for miner argument patterns...' -ForegroundColor Cyan

    $processes  = Get-CimInstance -ClassName Win32_Process | Select-Object Name, ProcessId, CommandLine
    $flagged    = @()

    foreach ($proc in $processes) {
        if (-not $proc.CommandLine) { continue }
        foreach ($pattern in $script:MinerCmds) {
            if ($proc.CommandLine -match [regex]::Escape($pattern)) {
                $flagged += $proc
                break
            }
        }
    }

    if ($flagged.Count -gt 0) {
        Write-AuditResult 'Hidden Miner Patterns' "Detected in $($flagged.Count) process(es)" -Status Fail
        $detail = ($flagged | ForEach-Object { "$($_.Name) (PID $($_.ProcessId))" }) -join ', '
        $notes  = Format-FixRecommendation `
            -Problem 'Process command lines contain arguments typical of cryptocurrency miners.' `
            -ManualSteps @(
                "Processes: $detail",
                '1. Terminate the process.',
                '2. Delete the binary and check for persistence mechanisms.'
            )
        Add-AuditFinding -Id 'Miner_Hidden' -Title 'Hidden Miner Pattern Detected' `
            -Value "$($flagged.Count) process(es)" -Severity 0 -Weight 25 -Notes $notes -Category 'CryptoMiner'
    } else {
        Write-AuditResult 'Hidden Miner Patterns' 'None detected' -Status Pass
    }
}

Export-ModuleMember -Function Invoke-CryptoMinerDetection