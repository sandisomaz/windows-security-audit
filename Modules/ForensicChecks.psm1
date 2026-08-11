#Requires -Version 5.1
<#
.SYNOPSIS
    Forensic analysis and artifact detection
.DESCRIPTION
    Checks:
    - HOSTS file modifications
    - Browser extensions (Chrome, Edge)
    - Recently modified executables
    - PUPs (Potentially Unwanted Programs)
.NOTES
    Version : 5.5.0
#>

using module .\Core.psm1

function Invoke-ForensicChecks {
    <#
    .SYNOPSIS
        Performs forensic analysis and artifact detection
    .PARAMETER Config
        Configuration object from Config.psd1
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )
    
    Write-AuditHeader "Forensic Analysis & Artifacts"
    
    # === HOSTS File ===
    Test-HOSTS
    
    # === Browser Extensions ===
    Test-BrowserExtensions
    
    # === Backdoor Discovery (New) ===
    Test-BackdoorPaths -Config $Config

    # === Potentially Unwanted Programs ===
    Test-PUPs -Config $Config
    
    # === Recent Executables ===
    Test-RecentExecutables -Config $Config
}

function Test-BackdoorPaths {
    param([hashtable]$Config)

    Write-Host "Scanning for specific backdoor indicators (User Discovery Patterns)..." -ForegroundColor Cyan
    
    # Resolve backdoor directory list from Config; expand environment variables at runtime
    $suspiciousPaths = if ($Config.Signatures -and $Config.Signatures.BackdoorDirectories) {
        $Config.Signatures.BackdoorDirectories | ForEach-Object {
            $ExecutionContext.InvokeCommand.ExpandString($_)
        }
    } else {
        @(
            "$env:LOCALAPPDATA\Updates",
            "$env:LOCALAPPDATA\Windows",
            "$env:APPDATA\Updates",
            'C:\Users\Public\Updates'
        )
    }
    
    $foundBackdoors = @()
    
    foreach ($path in $suspiciousPaths) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -File -Recurse -ErrorAction SilentlyContinue
            if ($files) {
                Write-Host "  [!] Found suspicious directory: $path" -ForegroundColor Red
                $foundBackdoors += [PSCustomObject]@{
                    Path = $path
                    FileCount = $files.Count
                    Files = ($files.Name | Select-Object -First 5) -join ", "
                }
            }
        }
    }
    
    # Check for VBScripts in root AppData or Temp (High risk)
    $scriptPaths = @("$env:LOCALAPPDATA", "$env:APPDATA", "$env:TEMP")
    $suspiciousScripts = @()
    foreach ($path in $scriptPaths) {
        $scripts = Get-ChildItem -Path $path -Filter "*.vbs" -File -ErrorAction SilentlyContinue 
        $scripts += Get-ChildItem -Path $path -Filter "*.js" -File -ErrorAction SilentlyContinue
        foreach ($s in $scripts) {
            # Skip legitimate looking ones if any exist (usually none in root AppData)
            $suspiciousScripts += $s.FullName
            Write-Host "  [!] Found suspicious script: $($s.FullName)" -ForegroundColor Yellow
        }
    }

    if ($foundBackdoors.Count -gt 0 -or $suspiciousScripts.Count -gt 0) {
        $notes = "CRITICAL: Detected specific patterns associated with known backdoors.`n`n"
        if ($foundBackdoors) {
            $notes += "Suspicious Folders Found:`n"
            foreach ($b in $foundBackdoors) {
                $notes += " - $($b.Path) (Contains: $($b.Files)...)`n"
            }
        }
        if ($suspiciousScripts) {
            $notes += "`nSuspicious Scripts Found:`n - " + ($suspiciousScripts -join "`n - ")
        }

        Add-AuditFinding `
            -Id "Forensic_Backdoor" `
            -Title "Backdoor Indicators Detected" `
            -Value "Found $($foundBackdoors.Count) folder(s) / $($suspiciousScripts.Count) script(s)" `
            -Severity 0 `
            -Weight 25 `
            -Notes $notes `
            -Category "Forensics"
        
        Write-AuditResult "Backdoor Paths" "DETECTED" -Status Fail
    } else {
        Write-AuditResult "Backdoor Paths" "Clean" -Status Pass
    }
}

function Test-HOSTS {
    Write-Host "Auditing HOSTS file..." -ForegroundColor Cyan
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path $hostsPath) {
        # Get entries that are not comments or empty/whitespace-only
        $entries = @()
        $content = Get-Content $hostsPath -ErrorAction SilentlyContinue
        if ($content) {
            $entries = $content | Where-Object { $_ -match '^\s*[^#\s]' -and $_ -notmatch 'localhost' }
        }
        
        if ($entries -and ($entries.Count -gt 0 -or ($entries -isnot [array] -and $entries -ne $null))) {
            Write-AuditResult "HOSTS File" "Found $($entries.Count) custom entry(s)" -Status Warn
            Add-AuditFinding -Id "Forensic_HOSTS" -Title "HOSTS File Modifications" -Value "$($entries.Count) custom entry(s)" -Severity 2 -Notes "Review custom HOSTS entries for potential hijacking." -Category "Forensics"
        } else {
            Write-AuditResult "HOSTS File" "Clean" -Status Pass
            Add-AuditFinding -Id "Forensic_HOSTS" -Title "HOSTS File" -Value "Clean" -Severity 1 -Category "Forensics"
        }
    }
}

function Test-BrowserExtensions {
    Write-Host "Auditing browser extensions..." -ForegroundColor Cyan
    
    # Chrome
    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
    if (Test-Path $chromePath) {
        $chromeExts = Get-ChildItem $chromePath -Directory -ErrorAction SilentlyContinue
        
        if ($chromeExts) {
            Write-AuditResult "Chrome Extensions" "$($chromeExts.Count) extension(s)" -Status Info
            
            $extensionList = @()
            foreach ($ext in $chromeExts | Select-Object -First 10) {
                $extensionList += $ext.Name
            }
            
            $notes = Format-FixRecommendation `
                -Problem "A review of installed browser extensions is recommended. Malicious extensions can steal data and monitor activity." `
                -ManualSteps @(
                    "Open Chrome and navigate to 'chrome://extensions'.",
                    "Review each extension. If you don't recognize it or no longer use it, remove it.",
                    "Pay close attention to extensions with powerful permissions."
                )

            Add-AuditFinding `
                -Id "Forensic_Chrome" `
                -Title "Chrome Extensions" `
                -Value "$($chromeExts.Count) extension(s) installed" `
                -Severity 3 `
                -Notes $notes `
                -Category "Forensics"
        }
    }
    
    # Edge
    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
    if (Test-Path $edgePath) {
        $edgeExts = Get-ChildItem $edgePath -Directory -ErrorAction SilentlyContinue
        
        if ($edgeExts) {
            Write-AuditResult "Edge Extensions" "$($edgeExts.Count) extension(s)" -Status Info
            
            $notes = Format-FixRecommendation `
                -Problem "A review of installed browser extensions is recommended." `
                -ManualSteps @(
                    "Open Edge and navigate to 'edge://extensions'.",
                    "Review and remove any extensions that are unfamiliar or no longer needed."
                )

            Add-AuditFinding `
                -Id "Forensic_Edge" `
                -Title "Edge Extensions" `
                -Value "$($edgeExts.Count) extension(s) installed" `
                -Severity 3 `
                -Notes $notes `
                -Category "Forensics"
        }
    }
}

function Test-PUPs {
    param([hashtable]$Config)
    
    Write-Host "Scanning for Potentially Unwanted Programs (PUPs)..." -ForegroundColor Cyan
    
    $pupKeywords = $Config.Detection.PUPKeywords
    $foundPUPs = @()
    
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    
    $appCount = 0
    
    foreach ($path in $uninstallPaths) {
        $keys = Invoke-SafeCommand {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue
        }
        
        if (-not $keys) { continue }
        
        foreach ($key in $keys) {
            $appName = Invoke-SafeCommand {
                $key.GetValue("DisplayName")
            }
            
            if ($appName) {
                $appCount++
                
                # Check if app name matches PUP keywords
                foreach ($keyword in $pupKeywords) {
                    if ($appName -match $keyword) {
                        $foundPUPs += $appName
                        Write-Host "  - $appName" -ForegroundColor Yellow
                        break
                    }
                }
            }
        }
    }
    
    if ($foundPUPs.Count -gt 0) {
        Write-AuditResult "PUP Scan" "Found $($foundPUPs.Count) potential PUP(s)" -Status Warn
        
        $notes = Format-FixRecommendation `
            -Problem "Potentially Unwanted Programs (PUPs) like 'PC Cleaners', 'Optimizers', or 'Driver Updaters' were detected. These often cause more harm than good and can be a security risk." `
            -ManualSteps @(
                "Go to 'Add or remove programs' in Windows Settings.",
                "Find and uninstall the following applications:",
                (($foundPUPs | Select-Object -Unique) -join "`n"),
                "Be careful during uninstallation to decline any additional offers."
            )

        Add-AuditFinding `
            -Id "Forensic_PUPs" `
            -Title "Potentially Unwanted Programs" `
            -Value "Found $($foundPUPs.Count) PUP(s)" `
            -Severity 2 `
            -Notes $notes `
            -Category "Forensics"
    }
    else {
        Write-AuditResult "PUP Scan" "No common PUPs detected (scanned $appCount apps)" -Status Pass
        
        Add-AuditFinding `
            -Id "Forensic_PUPs" `
            -Title "PUP Scan" `
            -Value "No common PUPs detected" `
            -Severity 1 `
            -Category "Forensics"
    }
}

function Test-RecentExecutables {
    param([hashtable]$Config)
    
    Write-Host "Scanning for recently modified executables..." -ForegroundColor Cyan
    Write-Host "  (This may take a few minutes)" -ForegroundColor Gray
    
    $cutoffDate = (Get-Date).AddDays(-$Config.Thresholds.RecentExecutablesAge)
    $scanPaths = @(
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents"
    )
    
    $recentFiles = @()
    
    foreach ($path in $scanPaths) {
        if (-not (Test-Path $path)) { continue }
        
        $files = Invoke-SafeCommand {
            Get-ChildItem -Path $path -Include @('*.exe', '*.dll', '*.ps1', '*.bat', '*.vbs') `
                -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.LastWriteTime -gt $cutoffDate -and 
                    $_.FullName -notmatch '\\\.venv\\|\\node_modules\\|\\target\\|\\bin\\|\\obj\\'
                } |
                Select-Object -First 20
        }
        
        if ($files) {
            foreach ($file in $files) {
                $hash = Get-FileHashSafe -FilePath $file.FullName
                
                $recentFiles += [PSCustomObject]@{
                    Name = $file.Name
                    Path = $file.FullName
                    Modified = $file.LastWriteTime
                    Hash = $hash
                }
                
                Write-Host "  - $($file.Name) ($($file.LastWriteTime))" -ForegroundColor Yellow
            }
        }
    }
    
    if ($recentFiles.Count -gt 0) {
        Write-AuditResult "Recent Executables" "Found $($recentFiles.Count) recent file(s)" -Status Warn
        
        $fileDetails = $recentFiles | ForEach-Object { "- $($_.Name) at $($_.Path)" }
        $notes = Format-FixRecommendation `
            -Problem "Found executable files that were recently created or modified in user directories. This is a common tactic for malware droppers." `
            -ManualSteps @(
                "Review the following files:",
                ($fileDetails -join "`n"),
                "1. If you do not recognize these files, do not run them.",
                "2. Get the file hash and submit it to VirusTotal.com to check for malware.",
                "3. If malicious, delete the file and run a full antivirus scan."
            )
        
        Add-AuditFinding `
            -Id "Forensic_RecentExe" `
            -Title "Recently Modified Executables" `
            -Value "Found $($recentFiles.Count) file(s)" `
            -Severity 2 `
            -Notes $notes `
            -Category "Forensics"
    }
    else {
        Write-AuditResult "Recent Executables" "None found" -Status Pass
        
        Add-AuditFinding `
            -Id "Forensic_RecentExe" `
            -Title "Recently Modified Executables" `
            -Value "None found" `
            -Severity 1 `
            -Category "Forensics"
    }
}

Export-ModuleMember -Function Invoke-ForensicChecks