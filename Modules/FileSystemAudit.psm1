<#
.SYNOPSIS
    File system corruption and integrity checking module
.DESCRIPTION
    Detects:
    - File system corruption
    - Gibberish/corrupted filenames
    - Undeletable files
    - Missing system folders
    - Disk health issues
#>

using module .\Core.psm1

function Invoke-FileSystemAudit {
    <#
    .SYNOPSIS
        Performs comprehensive file system integrity checks
    .PARAMETER Config
        Configuration object from Config.psd1
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )
    
    Write-AuditHeader "File System Integrity Audit"
    
    # === CHECK 1: Critical System Folders ===
    Test-CriticalFolders
    
    # === CHECK 2: Disk Health ===
    Test-DiskHealth
    
    # === CHECK 3: File System Corruption ===
    Test-FileSystemCorruption -Config $Config
    
    # === CHECK 4: Gibberish Filenames ===
    if ($Config.FileSystem.CheckGibberishFilenames) {
        Test-GibberishFilenames -Config $Config
    }
    
    # === CHECK 5: Undeletable Files ===
    if ($Config.FileSystem.CheckUndeletableFiles) {
        Test-UndeletableFiles -Config $Config
    }
}

function Test-CriticalFolders {
    <#
    .SYNOPSIS
        Checks if critical Windows system folders exist
    #>
    Write-Host "Checking critical system folders..." -ForegroundColor Cyan
    
    $criticalFolders = @(
        "$env:SystemRoot\System32",
        "$env:SystemRoot\System32\drivers",
        "$env:SystemRoot\System32\config",
        "$env:ProgramFiles",
        "$env:ProgramData",
        "$env:USERPROFILE"
    )
    
    $missingFolders = @()
    
    foreach ($folder in $criticalFolders) {
        if (-not (Test-Path $folder)) {
            $missingFolders += $folder
            
            Write-AuditResult "Critical Folder" `
                "$folder - MISSING" `
                -Status Fail
            
            Add-AuditFinding `
                -Id "FS_MissingFolder_$(Split-Path $folder -Leaf)" `
                -Title "Missing Critical System Folder" `
                -Value $folder `
                -Severity 0 `
                -Weight 25 `
                -Notes "CRITICAL: System folder is missing. This indicates severe system corruption or malware activity." `
                -Category "FileSystem"
        }
    }
    
    if ($missingFolders.Count -eq 0) {
        Write-AuditResult "Critical Folders" "All present" -Status Pass
        
        Add-AuditFinding `
            -Id "FS_CriticalFolders" `
            -Title "Critical System Folders" `
            -Value "All present" `
            -Severity 1 `
            -Category "FileSystem"
    } else {
        Write-Host ""
        Write-Host "!!! CRITICAL: Missing System Folders Detected !!!" -ForegroundColor Red
        Write-Host "This usually indicates:" -ForegroundColor Yellow
        Write-Host "  - Malware deleted system files" -ForegroundColor Yellow
        Write-Host "  - Cracked software modified the system" -ForegroundColor Yellow
        Write-Host "  - Severe file system corruption" -ForegroundColor Yellow
        Write-Host "  - Incomplete Windows installation" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "RECOMMENDED ACTION: Run 'sfc /scannow' and 'DISM /Online /Cleanup-Image /RestoreHealth'" -ForegroundColor Green
        Write-Host ""
    }
}

function Test-DiskHealth {
    <#
    .SYNOPSIS
        Checks physical disk health status
    #>
    Write-Host "Checking disk health..." -ForegroundColor Cyan
    
    $disks = Invoke-SafeCommand {
        Get-PhysicalDisk | Select-Object FriendlyName, DeviceId, HealthStatus, OperationalStatus
    }
    
    if (-not $disks) {
        Write-AuditResult "Disk Health" "Could not query disks" -Status Warn
        
        Add-AuditFinding `
            -Id "FS_DiskHealth_Error" `
            -Title "Disk Health Check" `
            -Value "Query failed" `
            -Severity 2 `
            -Category "FileSystem"
        return
    }
    
    $unhealthyDisks = @()
    
    foreach ($disk in $disks) {
        if ($disk.HealthStatus -ne "Healthy") {
            $unhealthyDisks += $disk
            
            Write-AuditResult "Disk" `
                "$($disk.FriendlyName) - $($disk.HealthStatus)" `
                -Status Fail
            
            Add-AuditFinding `
                -Id "FS_Disk_$($disk.DeviceId)" `
                -Title "Unhealthy Disk Detected" `
                -Value "$($disk.FriendlyName) - $($disk.HealthStatus)" `
                -Severity 0 `
                -Weight 20 `
                -Notes "Physical disk is unhealthy. This can cause file corruption, data loss, and system instability." `
                -Category "FileSystem"
        } else {
            Write-AuditResult "Disk" `
                "$($disk.FriendlyName) - Healthy" `
                -Status Pass
        }
    }
    
    if ($unhealthyDisks.Count -eq 0) {
        Add-AuditFinding `
            -Id "FS_DiskHealth" `
            -Title "Disk Health" `
            -Value "All disks healthy" `
            -Severity 1 `
            -Category "FileSystem"
    }
}

function Test-FileSystemCorruption {
    <#
    .SYNOPSIS
        Tests for file system corruption using built-in Windows tools
    #>
    param([hashtable]$Config)
    
    Write-Host "Checking for file system corruption indicators..." -ForegroundColor Cyan
    
    foreach ($drive in $Config.FileSystem.DrivesToScan) {
        if (-not (Test-Path $drive)) {
            continue
        }
        
        # Get volume information
        $volume = Invoke-SafeCommand {
            Get-Volume -DriveLetter $drive.TrimEnd(':') -ErrorAction Stop
        }
        
        if (-not $volume) {
            continue
        }
        
        # Check file system health
        if ($volume.HealthStatus -ne "Healthy") {
            Write-AuditResult "Volume $drive" `
                "Health Status: $($volume.HealthStatus)" `
                -Status Fail
            
            Add-AuditFinding `
                -Id "FS_Volume_$drive" `
                -Title "File System Health Issue" `
                -Value "$drive - $($volume.HealthStatus)" `
                -Severity 0 `
                -Weight 20 `
                -Notes "Volume is not healthy. Run 'chkdsk $drive /f' to repair." `
                -Category "FileSystem"
        } else {
            Write-AuditResult "Volume $drive" "Healthy" -Status Pass
        }
        
        # Check for operational issues
        if ($volume.OperationalStatus -ne "OK") {
            Write-AuditResult "Volume $drive Operational Status" `
                $volume.OperationalStatus `
                -Status Warn
            
            Add-AuditFinding `
                -Id "FS_VolOp_$drive" `
                -Title "Volume Operational Issue" `
                -Value "$drive - $($volume.OperationalStatus)" `
                -Severity 2 `
                -Category "FileSystem"
        }
    }
}

function Test-GibberishFilenames {
    <#
    .SYNOPSIS
        Scans for corrupted/gibberish filenames (indicates file system corruption)
    #>
    param([hashtable]$Config)
    
    Write-Host "Scanning for corrupted filenames..." -ForegroundColor Cyan
    Write-Host "  (This may take a few minutes)" -ForegroundColor Gray
    
    $suspiciousFiles = @()
    $scanPaths = @(
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents"
    )
    
    foreach ($path in $scanPaths) {
        if (-not (Test-Path $path)) {
            continue
        }
        
        try {
            $files = Get-ChildItem -Path $path -File -ErrorAction Stop | 
                Select-Object -First 100
            
            foreach ($file in $files) {
                # Check for non-ASCII or excessive special characters
                $name = $file.Name
                
                # Pattern for gibberish: lots of special chars or non-printable chars
                if ($name -match '[^\u0020-\u007E]') { # Check for any non-printable ASCII characters
                    
                    $suspiciousFiles += $file
                    
                    Write-AuditResult "Suspicious File" `
                        "$($file.Name) (Corrupted Name)" `
                        -Status Warn
                }
            }
        }
        catch {
            Write-AuditLog "Error scanning $path : $($_.Exception.Message)" -Level Warning
        }
    }
    
    if ($suspiciousFiles.Count -gt 0) {
        Add-AuditFinding `
            -Id "FS_GibberishFiles" `
            -Title "Corrupted Filenames Detected" `
            -Value "Found $($suspiciousFiles.Count) suspicious filename(s)" `
            -Severity 2 ` # WARN
            -Weight 15 `
            -Notes "Files with corrupted/gibberish names detected. This can indicate severe file system corruption. Example: $($suspiciousFiles[0].FullName)" `
            -Category "FileSystem"
    } else {
        Write-AuditResult "Gibberish Filenames" "None detected" -Status Pass
        Add-AuditFinding `
            -Id "FS_GibberishFiles" `
            -Title "Corrupted Filenames" `
            -Value "None detected" `
            -Severity 1 `
            -Category "FileSystem"
    }
}

function Test-UndeletableFiles {
    <#
    .SYNOPSIS
        Checks for files that cannot be deleted (locked/corrupted)
    #>
    param([hashtable]$Config)
    
    Write-Host "Checking for locked/undeletable files..." -ForegroundColor Cyan
    
    # This is a basic check - comprehensive check requires more time
    Write-AuditResult "Undeletable Files" "Manual check recommended" -Status Info
    
    Add-AuditFinding `
        -Id "FS_UndeletableFiles" `
        -Title "Locked File Check" `
        -Value "Informational - manual verification recommended" `
        -Severity 3 `
        -Notes "If you're experiencing undeletable files, try: 1) Boot into Safe Mode 2) Use 'chkdsk /f' 3) Use Unlocker tool" `
        -Category "FileSystem"
}

Export-ModuleMember -Function Invoke-FileSystemAudit