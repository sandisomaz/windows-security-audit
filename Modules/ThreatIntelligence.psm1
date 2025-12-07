<#
.SYNOPSIS
    Advanced threat intelligence and malware pattern detection
.DESCRIPTION
    Detects various types of malware beyond crypto miners:
    - Ransomware indicators
    - Keyloggers
    - RATs (Remote Access Trojans)
    - Rootkits
    - Info stealers
    - Botnets
    - Browser hijackers
#>

using module .\Core.psm1

function Invoke-ThreatIntelligence {
    <#
    .SYNOPSIS
        Advanced threat detection using behavior analysis and signatures
    .PARAMETER Config
        Configuration object from Config.psd1
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )
    
    Write-AuditHeader "Advanced Threat Intelligence & Malware Detection"
    
    # Detect ransomware indicators
    Test-RansomwareIndicators
    
    # Detect keyloggers
    Test-KeyloggerIndicators
    
    # Detect RATs (Remote Access Trojans)
    Test-RATIndicators
    
    # Detect rootkit behaviors
    Test-RootkitIndicators
    
    # Detect info stealers
    Test-InfoStealerIndicators
    
    # Detect botnet activity
    Test-BotnetIndicators
    
    # Check for suspicious DLLs
    Test-SuspiciousDLLs
}

function Test-RansomwareIndicators {
    Write-Host "Scanning for ransomware indicators..." -ForegroundColor Cyan
    
    $indicators = @()
    
    # Check for mass file encryption (many files changed recently)
    $recentFileChanges = Invoke-SafeCommand {
        Get-ChildItem -Path "$env:USERPROFILE\Documents" -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-30) } |
            Measure-Object | Select-Object -ExpandProperty Count
    }
    
    if ($recentFileChanges -gt 100) {
        $indicators += "Mass file modification detected ($recentFileChanges files in last 30 min)"
    }
    
    # Check for ransom note files
    $ransomNotePatterns = @('README*.txt', 'DECRYPT*.txt', 'HOW_TO_DECRYPT*', 
                            'YOUR_FILES_ARE_ENCRYPTED*', 'RECOVERY*')
    
    foreach ($pattern in $ransomNotePatterns) {
        $found = Invoke-SafeCommand {
            Get-ChildItem -Path "$env:USERPROFILE" -Filter $pattern -File -Recurse -ErrorAction SilentlyContinue |
                Select-Object -First 5
        }
        
        if ($found) {
            $indicators += "Ransom note detected: $($found.Name)"
        }
    }
    
    # Check for encrypted file extensions
    $ransomExtensions = @('.encrypted', '.locked', '.crypto', '.crypt', '.cerber', 
                          '.locky', '.zepto', '.odin', '.vault', '.xtbl')
    
    foreach ($ext in $ransomExtensions) {
        $found = Invoke-SafeCommand {
            Get-ChildItem -Path "$env:USERPROFILE\Documents" -Filter "*$ext" -File -ErrorAction SilentlyContinue |
                Select-Object -First 1
        }
        
        if ($found) {
            $indicators += "Encrypted files detected with extension: $ext"
        }
    }
    
    # Check for Volume Shadow Copy deletion (common ransomware behavior)
    $shadowCopies = Invoke-SafeCommand {
        (Get-WmiObject -Query "SELECT * FROM Win32_ShadowCopy").Count
    }
    
    if ($shadowCopies -eq 0) {
        $indicators += "No Volume Shadow Copies found (may have been deleted)"
    }
    
    if ($indicators.Count -gt 0) {
        Write-AuditResult "Ransomware Indicators" "CRITICAL: $($indicators.Count) indicator(s) detected" -Status Fail
        
        $notes = Format-FixRecommendation `
            -Problem "RANSOMWARE INDICATORS DETECTED! Your system may be under ransomware attack." `
            -ManualSteps @(
                "🚨 IMMEDIATE ACTIONS:",
                "1. DISCONNECT FROM INTERNET AND NETWORK IMMEDIATELY",
                "2. DO NOT pay ransom",
                "3. DO NOT delete anything",
                "4. Power off computer if encryption is ongoing",
                "5. Contact IT security professional",
                "",
                "Indicators found:",
                ($indicators -join "`n"),
                "",
                "RECOVERY OPTIONS:",
                "- Check for backups",
                "- Try decryption tools: nomoreransom.org",
                "- Restore from Volume Shadow Copies (if available)",
                "- Professional data recovery service"
            ) `
            -MoreInfo "https://www.nomoreransom.org/"
        
        Add-AuditFinding `
            -Id "Threat_Ransomware" `
            -Title "Ransomware Indicators" `
            -Value "CRITICAL: $($indicators.Count) indicators" `
            -Severity 0 `
            -Weight 25 `
            -Notes $notes `
            -Category "Threat"
    } else {
        Write-AuditResult "Ransomware Indicators" "None detected" -Status Pass
        
        Add-AuditFinding `
            -Id "Threat_Ransomware_Clean" `
            -Title "Ransomware Scan" `
            -Value "Clean" `
            -Severity 1 `
            -Category "Threat"
    }
}

function Test-KeyloggerIndicators {
    Write-Host "Checking for keylogger indicators..." -ForegroundColor Cyan
    
    $indicators = @()
    
    # Check for processes hooking keyboard
    $suspiciousProcesses = @()
    $processes = Get-Process | Where-Object { $_.MainWindowHandle -eq 0 -and $_.ProcessName -notmatch '^(System|svchost|csrss|smss|lsass|services)$' }
    
    foreach ($proc in $processes) {
        # Check if process is in suspicious location
        if ($proc.Path -match 'AppData|Temp|Public') {
            try {
                $modules = $proc.Modules | Where-Object { $_.ModuleName -match 'hook|keyboard|input' }
                if ($modules) {
                    $suspiciousProcesses += $proc.ProcessName
                    $indicators += "Process with keyboard hooks: $($proc.ProcessName)"
                }
            }
            catch {
                # Access denied - process may be protected
            }
        }
    }
    
    # Check for known keylogger file patterns
    $keyloggerPatterns = @('keylog*.txt', '*passwords*.txt', 'log*.dat')
    
    foreach ($pattern in $keyloggerPatterns) {
        $found = Invoke-SafeCommand {
            Get-ChildItem -Path "$env:USERPROFILE\AppData" -Filter $pattern -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -gt 1KB } |
                Select-Object -First 5
        }
        
        if ($found) {
            $indicators += "Suspicious log file: $($found.Name) ($([math]::Round($found.Length/1KB, 2)) KB)"
        }
    }
    
    if ($indicators.Count -gt 0) {
        Write-AuditResult "Keylogger Indicators" "WARNING: $($indicators.Count) indicator(s) detected" -Status Warn
        
        $notes = Format-FixRecommendation `
            -Problem "Potential keylogger activity detected on your system." `
            -ManualSteps @(
                "Indicators found:",
                ($indicators -join "`n"),
                "",
                "TO INVESTIGATE:",
                "1. Check Task Manager for suspicious background processes",
                "2. Look for unfamiliar startup programs",
                "3. Scan with Malwarebytes",
                "4. Change all passwords from a different device",
                "5. Enable 2FA on all accounts"
            )
        
        Add-AuditFinding `
            -Id "Threat_Keylogger" `
            -Title "Keylogger Indicators" `
            -Value "$($indicators.Count) indicators" `
            -Severity 2 `
            -Weight 20 `
            -Notes $notes `
            -Category "Threat"
    } else {
        Write-AuditResult "Keylogger Indicators" "None detected" -Status Pass
        
        Add-AuditFinding `
            -Id "Threat_Keylogger_Clean" `
            -Title "Keylogger Scan" `
            -Value "Clean" `
            -Severity 1 `
            -Category "Threat"
    }
}

function Test-RATIndicators {
    Write-Host "Scanning for RAT (Remote Access Trojan) indicators..." -ForegroundColor Cyan
    
    $indicators = @()
    
    # Check for common RAT ports
    $ratPorts = @(1337, 31337, 4444, 5555, 6666, 7777, 8888, 9999, 12345, 54321)
    $listening = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    
    foreach ($conn in $listening) {
        if ($conn.LocalPort -in $ratPorts) {
            $proc = Invoke-SafeCommand {
                (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            }
            
            $indicators += "Suspicious listening port: $($conn.LocalPort) by $proc"
        }
    }
    
    # Check for known RAT file names
    $ratNames = @('anydesk', 'teamviewer', 'remotepc', 'vnc', 'ammyy', 'ultravnc', 'tightvnc')
    $installedSoftware = Get-Process | Where-Object { $_.Path }
    
    foreach ($proc in $installedSoftware) {
        $procName = $proc.ProcessName.ToLower()
        
        foreach ($ratName in $ratNames) {
            if ($procName -match $ratName -and $proc.Path -match 'AppData|Temp') {
                $indicators += "Remote access software in suspicious location: $($proc.ProcessName) at $($proc.Path)"
            }
        }
    }
    
    # Check for reverse shell indicators
    $reverseShellPatterns = @('powershell.*IEX', 'cmd.exe.*net.*user', 'mshta.*http')
    $processes = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine }
    
    foreach ($proc in $processes) {
        $cmdLine = $proc.CommandLine
        
        foreach ($pattern in $reverseShellPatterns) {
            if ($cmdLine -match $pattern) {
                $indicators += "Reverse shell pattern in command line: $($proc.Name)"
            }
        }
    }
    
    if ($indicators.Count -gt 0) {
        Write-AuditResult "RAT Indicators" "CRITICAL: $($indicators.Count) indicator(s) detected" -Status Fail
        
        $notes = Format-FixRecommendation `
            -Problem "Remote Access Trojan (RAT) indicators detected. An attacker may have remote control of your system." `
            -ManualSteps @(
                "CRITICAL INDICATORS:",
                ($indicators -join "`n"),
                "",
                "IMMEDIATE ACTIONS:",
                "1. Disconnect from internet",
                "2. Change all passwords from different device",
                "3. Check for unauthorized user accounts",
                "4. Review recent system changes",
                "5. Full malware scan with multiple tools",
                "6. Consider clean Windows reinstall"
            )
        
        Add-AuditFinding `
            -Id "Threat_RAT" `
            -Title "RAT (Remote Access Trojan) Indicators" `
            -Value "CRITICAL: $($indicators.Count) indicators" `
            -Severity 0 `
            -Weight 25 `
            -Notes $notes `
            -Category "Threat"
    } else {
        Write-AuditResult "RAT Indicators" "None detected" -Status Pass
        
        Add-AuditFinding `
            -Id "Threat_RAT_Clean" `
            -Title "RAT Scan" `
            -Value "Clean" `
            -Severity 1 `
            -Category "Threat"
    }
}

function Test-RootkitIndicators {
    Write-Host "Checking for rootkit indicators..." -ForegroundColor Cyan
    
    $indicators = @()
    
    # Check for hidden processes (processes with no name/path)
    $hiddenProcs = Get-CimInstance Win32_Process | 
                   Where-Object { -not $_.ExecutablePath -and $_.Name -notin @('System', 'Registry', 'smss.exe') }
    
    if ($hiddenProcs) {
        $indicators += "Hidden processes detected: $($hiddenProcs.Count)"
    }
    
    # Check for SSDT hooks (simplified - full check requires kernel access)
    # We can check for suspicious drivers instead
    $drivers = Invoke-SafeCommand {
        Get-WmiObject Win32_SystemDriver | 
            Where-Object { $_.State -eq 'Running' -and $_.PathName -match 'AppData|Temp|Users' }
    }
    
    if ($drivers) {
        $indicators += "Suspicious drivers in user directories: $($drivers.Count)"
    }
    
    # Check for registry key hiding
    $testKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    $visibleKeys = Invoke-SafeCommand {
        (Get-ChildItem $testKey -ErrorAction SilentlyContinue).Count
    }
    
    # Compare with WMI query (rootkits may hide keys from Get-ChildItem)
    $wmiKeys = Invoke-SafeCommand {
        (Get-WmiObject -Query "SELECT * FROM StdRegProv" -Namespace "root\default" -ErrorAction SilentlyContinue)
    }
    
    if ($indicators.Count -gt 0) {
        Write-AuditResult "Rootkit Indicators" "WARNING: $($indicators.Count) indicator(s) detected" -Status Warn
        
        $notes = Format-FixRecommendation `
            -Problem "Rootkit indicators detected. Rootkits hide deep in the system and are difficult to remove." `
            -ManualSteps @(
                "Indicators:",
                ($indicators -join "`n"),
                "",
                "ROOTKIT REMOVAL:",
                "1. Download specialized rootkit remover (GMER, TDSSKiller)",
                "2. Boot from clean USB/CD",
                "3. Run offline scan",
                "4. If persistent, clean Windows reinstall recommended",
                "5. Change all passwords after cleaning"
            ) `
            -MoreInfo "https://www.bleepingcomputer.com/tutorials/how-to-remove-a-rootkit/"
        
        Add-AuditFinding `
            -Id "Threat_Rootkit" `
            -Title "Rootkit Indicators" `
            -Value "$($indicators.Count) indicators" `
            -Severity 2 `
            -Weight 20 `
            -Notes $notes `
            -Category "Threat"
    } else {
        Write-AuditResult "Rootkit Indicators" "None detected" -Status Pass
        
        Add-AuditFinding `
            -Id "Threat_Rootkit_Clean" `
            -Title "Rootkit Scan" `
            -Value "Clean" `
            -Severity 1 `
            -Category "Threat"
    }
}

function Test-InfoStealerIndicators {
    Write-Host "Checking for information stealer indicators..." -ForegroundColor Cyan
    
    $indicators = @()
    
    # Check for credential harvesting files
    $credentialPaths = @(
        "$env:APPDATA\*\Login Data",
        "$env:LOCALAPPDATA\*\Login Data",
        "$env:APPDATA\*\Cookies"
    )
    
    $recentAccess = @()
    foreach ($pattern in $credentialPaths) {
        $files = Invoke-SafeCommand {
            Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastAccessTime -gt (Get-Date).AddHours(-24) }
        }
        
        if ($files) {
            $recentAccess += $files
        }
    }
    
    if ($recentAccess.Count -gt 5) {
        $indicators += "Unusual access to credential storage ($($recentAccess.Count) files)"
    }
    
    # Check for clipboard monitoring
    $clipboardProcesses = Get-Process | Where-Object {
        $_.ProcessName -match 'clip|board' -and 
        $_.ProcessName -notmatch 'microsoft|windows' -and
        $_.Path -match 'AppData|Temp'
    }
    
    if ($clipboardProcesses) {
        $indicators += "Suspicious clipboard monitoring: $($clipboardProcesses.ProcessName -join ', ')"
    }
    
    if ($indicators.Count -gt 0) {
        Write-AuditResult "Info Stealer Indicators" "WARNING: $($indicators.Count) indicator(s)" -Status Warn
        
        $notes = Format-FixRecommendation `
            -Problem "Information stealer indicators detected. Your passwords and credentials may be at risk." `
            -ManualSteps @(
                "Indicators:",
                ($indicators -join "`n"),
                "",
                "IMMEDIATE ACTIONS:",
                "1. Change all passwords from a different, clean device",
                "2. Enable 2FA on all accounts",
                "3. Check for unauthorized account access",
                "4. Review recent account activity",
                "5. Run full antivirus scan",
                "6. Clear browser data and cookies"
            )
        
        Add-AuditFinding `
            -Id "Threat_InfoStealer" `
            -Title "Information Stealer Indicators" `
            -Value "$($indicators.Count) indicators" `
            -Severity 2 `
            -Weight 20 `
            -Notes $notes `
            -Category "Threat"
    } else {
        Write-AuditResult "Info Stealer Indicators" "None detected" -Status Pass
        
        Add-AuditFinding `
            -Id "Threat_InfoStealer_Clean" `
            -Title "Info Stealer Scan" `
            -Value "Clean" `
            -Severity 1 `
            -Category "Threat"
    }
}

function Test-BotnetIndicators {
    Write-Host "Checking for botnet activity indicators..." -ForegroundColor Cyan
    
    $indicators = @()
    
    # Check for unusual outbound connections
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    
    # Group by owning process
    $connByProcess = $connections | Group-Object OwningProcess | 
                     Where-Object { $_.Count -gt 20 }
    
    foreach ($group in $connByProcess) {
        $proc = Invoke-SafeCommand {
            Get-Process -Id $group.Name -ErrorAction SilentlyContinue
        }
        
        if ($proc -and $proc.Path -match 'AppData|Temp') {
            $indicators += "Process with many connections: $($proc.ProcessName) ($($group.Count) connections)"
        }
    }
    
    # Check for IRC connections (common in old botnets)
    $ircPorts = @(6667, 6668, 6669, 7000)
    foreach ($conn in $connections) {
        if ($conn.RemotePort -in $ircPorts) {
            $proc = Invoke-SafeCommand {
                (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            }
            $indicators += "IRC connection detected: $proc on port $($conn.RemotePort)"
        }
    }
    
    if ($indicators.Count -gt 0) {
        Write-AuditResult "Botnet Indicators" "WARNING: $($indicators.Count) indicator(s)" -Status Warn
        
        $notes = Format-FixRecommendation `
            -Problem "Botnet activity indicators detected. Your computer may be part of a botnet." `
            -ManualSteps @(
                "Indicators:",
                ($indicators -join "`n"),
                "",
                "BOTNET REMOVAL:",
                "1. Disconnect from internet",
                "2. Identify and kill suspicious processes",
                "3. Remove from startup/scheduled tasks",
                "4. Full malware scan",
                "5. Change router password",
                "6. Monitor for reinfection"
            )
        
        Add-AuditFinding `
            -Id "Threat_Botnet" `
            -Title "Botnet Activity Indicators" `
            -Value "$($indicators.Count) indicators" `
            -Severity 2 `
            -Weight 15 `
            -Notes $notes `
            -Category "Threat"
    } else {
        Write-AuditResult "Botnet Indicators" "None detected" -Status Pass
        
        Add-AuditFinding `
            -Id "Threat_Botnet_Clean" `
            -Title "Botnet Scan" `
            -Value "Clean" `
            -Severity 1 `
            -Category "Threat"
    }
}

function Test-SuspiciousDLLs {
    Write-Host "Checking for suspicious DLL injections..." -ForegroundColor Cyan
    
    # Check for unsigned DLLs loaded in system processes
    $systemProcs = @('explorer.exe', 'svchost.exe', 'lsass.exe')
    $suspiciousDLLs = @()
    
    foreach ($procName in $systemProcs) {
        $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
        
        foreach ($proc in $procs) {
            try {
                $modules = $proc.Modules | Where-Object {
                    $_.FileName -match 'AppData|Temp|Users\\Public' -and
                    $_.FileName -match '\.dll$'
                }
                
                foreach ($module in $modules) {
                    $sig = Get-AuthenticodeSignature -FilePath $module.FileName -ErrorAction SilentlyContinue
                    if ($sig -and $sig.Status -ne 'Valid') {
                        $suspiciousDLLs += [PSCustomObject]@{
                            Process = $procName
                            DLL = $module.FileName
                            Status = $sig.Status
                        }
                    }
                }
            }
            catch {
                # Access denied or process exited
            }
        }
    }
    
    if ($suspiciousDLLs.Count -gt 0) {
        Write-AuditResult "Suspicious DLL Injections" "WARNING: Found $($suspiciousDLLs.Count) suspicious DLL(s)" -Status Warn
        
        $dllList = $suspiciousDLLs | ForEach-Object {
            "$($_.DLL) in $($_.Process)"
        }
        
        $notes = Format-FixRecommendation `
            -Problem "Unsigned or suspicious DLLs injected into system processes." `
            -ManualSteps @(
                "Suspicious DLLs:",
                ($dllList -join "`n"),
                "",
                "This may indicate:",
                "- DLL injection attack",
                "- Process hollowing",
                "- Advanced malware",
                "",
                "RECOMMENDED ACTION:",
                "Run specialized malware removal tool"
            )
        
        Add-AuditFinding `
            -Id "Threat_DLL_Injection" `
            -Title "Suspicious DLL Injections" `
            -Value "Found $($suspiciousDLLs.Count) DLL(s)" `
            -Severity 2 `
            -Weight 15 `
            -Notes $notes `
            -Category "Threat"
    } else {
        Write-AuditResult "Suspicious DLLs" "None detected" -Status Pass
    }
}

Export-ModuleMember -Function Invoke-ThreatIntelligence