<#
.SYNOPSIS
    Forensic analysis and artifact detection
.DESCRIPTION
    Checks:
    - HOSTS file modifications
    - Browser extensions (Chrome, Edge)
    - Recently modified executables
    - PUPs (Potentially Unwanted Programs)
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
    Test-HostsFile
    
    # === Browser Extensions ===
    Test-BrowserExtensions
    
    # === Potentially Unwanted Programs ===
    Test-PUPs -Config $Config
    
    # === Recent Executables ===
    Test-RecentExecutables -Config $Config
}

function Test-HostsFile {
    Write-Host "Analyzing HOSTS file..." -ForegroundColor Cyan
    
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    
    try {
        $content = Get-Content $hostsPath -ErrorAction Stop
        
        # Filter out comments and blank lines
        $activeLines = $content | Where-Object {
            $_ -notmatch "^\s*#" -and $_ -match "\w"
        }
        
        # Filter out default localhost entries
        $customEntries = $activeLines | Where-Object {
            $_ -notmatch '127\.0\.0\.1\s+localhost' -and $_ -notmatch '::1\s+localhost'
        }
        
        if ($customEntries) {
            Write-AuditResult "HOSTS File" "MODIFIED ($($customEntries.Count) custom entry/ies)" -Status Warn
            
            foreach ($entry in $customEntries) {
                Write-Host "  $entry" -ForegroundColor Yellow
            }
            
            Add-AuditFinding `
                -Id "Forensic_HOSTS" `
                -Title "HOSTS File Modifications" `
                -Value "Found $($customEntries.Count) custom entry/ies" `
                -Severity 2 `
                -Notes "Custom entries found: $($customEntries -join '; '). This may indicate cracked software or malware network blocking." `
                -Category "Forensics"
        }
        else {
            Write-AuditResult "HOSTS File" "Clean (default state)" -Status Pass
            
            Add-AuditFinding `
                -Id "Forensic_HOSTS" `
                -Title "HOSTS File" `
                -Value "Clean" `
                -Severity 1 `
                -Category "Forensics"
        }
    }
    catch {
        Write-AuditResult "HOSTS File" "Read failed" -Status Warn
        
        Add-AuditFinding `
            -Id "Forensic_HOSTS" `
            -Title "HOSTS File" `
            -Value "Read failed" `
            -Severity 2 `
            -Category "Forensics"
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
            
            Add-AuditFinding `
                -Id "Forensic_Chrome" `
                -Title "Chrome Extensions" `
                -Value "$($chromeExts.Count) extension(s) installed" `
                -Severity 3 `
                -Notes "Review extensions in Chrome. Remove any suspicious or unused extensions." `
                -Category "Forensics"
        }
    }
    
    # Edge
    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
    if (Test-Path $edgePath) {
        $edgeExts = Get-ChildItem $edgePath -Directory -ErrorAction SilentlyContinue
        
        if ($edgeExts) {
            Write-AuditResult "Edge Extensions" "$($edgeExts.Count) extension(s)" -Status Info
            
            Add-AuditFinding `
                -Id "Forensic_Edge" `
                -Title "Edge Extensions" `
                -Value "$($edgeExts.Count) extension(s) installed" `
                -Severity 3 `
                -Notes "Review extensions in Edge. Remove any suspicious or unused extensions." `
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
        
        Add-AuditFinding `
            -Id "Forensic_PUPs" `
            -Title "Potentially Unwanted Programs" `
            -Value "Found $($foundPUPs.Count) PUP(s)" `
            -Severity 2 `
            -Notes "Detected: $($foundPUPs -join ', '). Consider uninstalling these programs." `
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
                Where-Object { $_.LastWriteTime -gt $cutoffDate } |
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
        
        $hashList = $recentFiles | ForEach-Object { "$($_.Name): $($_.Hash)" }
        
        Add-AuditFinding `
            -Id "Forensic_RecentExe" `
            -Title "Recently Modified Executables" `
            -Value "Found $($recentFiles.Count) file(s)" `
            -Severity 2 `
            -Notes "Files modified in last $($Config.Thresholds.RecentExecutablesAge) days. Hashes: $($hashList -join '; ')" `
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