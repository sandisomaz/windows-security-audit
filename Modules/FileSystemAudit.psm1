#Requires -Version 5.1
<#
.SYNOPSIS
    File system corruption and integrity checking module (ENHANCED)
.DESCRIPTION
    Detects file system issues with detailed fix recommendations
.NOTES
    Version : 5.5.0
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
    
    Test-CriticalFolders
    Test-DiskHealth
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
            
            $notes = Format-FixRecommendation `
                -Problem "CRITICAL: System folder '$folder' is missing. This indicates severe system corruption, possibly from cracked software or malware." `
                -ManualSteps @(
                    "STEP 1: Backup all important personal files immediately",
                    "STEP 2: Try system repair: Run 'sfc /scannow' as Administrator",
                    "STEP 3: If that fails: Run 'DISM /Online /Cleanup-Image /RestoreHealth'",
                    "STEP 4: If still not fixed: You may need to reinstall Windows",
                    "STEP 5: For Windows reinstall (keeps files):",
                    "   - Download Windows 11 Media Creation Tool from Microsoft",
                    "   - Create bootable USB",
                    "   - Boot from USB and select 'Upgrade' option",
                    "   - Choose 'Keep personal files and apps'",
                    "WARNING: This is often caused by cracked software modifying system files"
                ) `
                -MoreInfo "https://support.microsoft.com/sfc-scannow"
            
            Add-AuditFinding `
                -Id "FS_MissingFolder_$(Split-Path $folder -Leaf)" `
                -Title "Missing Critical System Folder" `
                -Value $folder `
                -Severity 0 `
                -Weight 25 `
                -Notes $notes `
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
        Write-Host "  - Cracked/pirated software deleted system files" -ForegroundColor Yellow
        Write-Host "  - Malware modified the system" -ForegroundColor Yellow
        Write-Host "  - Severe file system corruption" -ForegroundColor Yellow
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
        return
    }
    
    $unhealthyDisks = @()
    
    foreach ($disk in $disks) {
        if ($disk.HealthStatus -ne "Healthy") {
            $unhealthyDisks += $disk
            
            Write-AuditResult "Disk" `
                "$($disk.FriendlyName) - $($disk.HealthStatus)" `
                -Status Fail
            
            $notes = Format-FixRecommendation `
                -Problem "CRITICAL: Physical disk '$($disk.FriendlyName)' is unhealthy (Status: $($disk.HealthStatus)). This causes file corruption, gibberish filenames, and undeletable files." `
                -ManualSteps @(
                    "IMMEDIATE ACTION REQUIRED:",
                    "1. BACKUP ALL IMPORTANT DATA NOW (disk may fail soon)",
                    "2. Check SMART status: Run 'wmic diskdrive get status'",
                    "3. Run disk check: 'chkdsk /f /r' (requires restart)",
                    "4. If SD card/external drive: Try different USB port",
                    "5. If SD card: Card may be physically damaged - replace it",
                    "6. If HDD shows 'Predictive Failure': Replace immediately",
                    "7. Do NOT try to format yet - recover data first",
                    "8. Use data recovery tool if needed (Recuva, PhotoRec)",
                    "",
                    "SYMPTOMS OF FAILING DRIVE:",
                    "- Files become gibberish when moved/renamed",
                    "- Can't delete files",
                    "- Can't format drive",
                    "- System freezes randomly",
                    "- Terminal pops up with errors"
                ) `
                -MoreInfo "https://support.microsoft.com/check-disk-errors"
            
            Add-AuditFinding `
                -Id "FS_Disk_$($disk.DeviceId)" `
                -Title "Unhealthy Disk Detected" `
                -Value "$($disk.FriendlyName) - $($disk.HealthStatus)" `
                -Severity 0 `
                -Weight 25 `
                -Notes $notes `
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
    
    Write-Host "Checking for file system corruption..." -ForegroundColor Cyan
    
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
            
            $notes = Format-FixRecommendation `
                -Problem "Volume $drive file system is corrupted (Status: $($volume.HealthStatus)). This causes the symptoms you're experiencing: gibberish files, can't delete files, terminal errors." `
                -QuickFix "chkdsk $drive /f /r" `
                -ManualSteps @(
                    "STEP 1: Backup important data from $drive",
                    "STEP 2: Run Check Disk:",
                    "   - Open PowerShell as Administrator",
                    "   - Run: chkdsk $drive /f /r",
                    "   - If prompted to schedule on restart, type Y",
                    "   - Restart computer (this will take 30-60 minutes)",
                    "STEP 3: If chkdsk fails:",
                    "   - The drive may be physically damaged",
                    "   - Try data recovery software first",
                    "   - Then format the drive (WARNING: Deletes all data)",
                    "STEP 4: To format (last resort):",
                    "   - Open Disk Management",
                    "   - Right-click the volume",
                    "   - Select 'Format'",
                    "   - If that fails, use diskpart:",
                    "     diskpart",
                    "     list disk",
                    "     select disk X (replace X with your disk number)",
                    "     clean",
                    "     create partition primary",
                    "     format fs=ntfs quick"
                ) `
                -MoreInfo "https://support.microsoft.com/chkdsk" `
                -IsSafe $false
            
            Add-AuditFinding `
                -Id "FS_Volume_$drive" `
                -Title "File System Corruption" `
                -Value "$drive - $($volume.HealthStatus)" `
                -Severity 0 `
                -Weight 25 `
                -Notes $notes `
                -Category "FileSystem"
        } else {
            Write-AuditResult "Volume $drive" "Healthy" -Status Pass
        }
        
        # Check for operational issues
        if ($volume.OperationalStatus -ne "OK") {
            Write-AuditResult "Volume $drive Operational Status" `
                $volume.OperationalStatus `
                -Status Warn
            
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
        $notes = Format-FixRecommendation `
            -Problem "Found $($suspiciousFiles.Count) files with corrupted/gibberish names. This is a strong indicator of file system corruption or failing storage device." `
            -ManualSteps @(
                "This problem is caused by:",
                "- Failing hard drive or SD card",
                "- File system corruption",
                "- Removing USB/SD card without 'Safely Remove'",
                "- Power loss during file operations",
                "",
                "TO FIX:",
                "1. Check disk health (see Disk Health section of this report)",
                "2. Run chkdsk on affected drive",
                "3. If SD card: It's likely dead - replace it",
                "4. Backup any readable files immediately",
                "5. After backup, try renaming files manually",
                "6. If files are unrecoverable, delete them",
                "",
                "EXAMPLE FILES AFFECTED:",
                "$(($suspiciousFiles | Select-Object -First 5 | ForEach-Object { $_.FullName }) -join ', ')"
            )
        
        Add-AuditFinding `
            -Id "FS_GibberishFiles" `
            -Title "Corrupted Filenames Detected" `
            -Value "Found $($suspiciousFiles.Count) suspicious filename(s)" `
            -Severity 2 `
            -Weight 15 `
            -Notes $notes `
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
    
    $notes = Format-FixRecommendation `
        -Problem "If you're experiencing files that cannot be deleted (stay in Recycle Bin or show errors):" `
        -ManualSteps @(
            "FILES THAT WON'T DELETE - Common Causes:",
            "1. File system corruption (most common with your symptoms)",
            "2. File is in use by a program",
            "3. Insufficient permissions",
            "4. Malware protecting itself",
            "",
            "SOLUTIONS (Try in order):",
            "",
            "METHOD 1: Safe Mode",
            "1. Restart in Safe Mode (hold Shift while clicking Restart)",
            "2. Try deleting the files",
            "3. Run chkdsk /f",
            "",
            "METHOD 2: Command Line Force Delete",
            "1. Open PowerShell as Administrator",
            "2. Run: Remove-Item 'C:\path\to\file' -Force",
            "3. Or: del /f /q 'C:\path\to\file'",
            "",
            "METHOD 3: Unlock Tool",
            "1. Download Unlocker (iobit.com)",
            "2. Right-click file → Unlocker",
            "3. Select 'Delete' and click OK",
            "",
            "METHOD 4: chkdsk (For corrupt files)",
            "1. Open PowerShell as Admin",
            "2. Run: chkdsk C: /f /r",
            "3. Restart computer",
            "",
            "METHOD 5: Format Drive (LAST RESORT)",
            "- If files are on external drive/SD card",
            "- Backup what you can first",
            "- Then format the drive"
        ) `
        -MoreInfo "https://support.microsoft.com/delete-undeletable-files"
    
    Add-AuditFinding `
        -Id "FS_UndeletableFiles" `
        -Title "Undeletable Files Guide" `
        -Value "Informational - manual verification recommended" `
        -Severity 3 `
        -Notes $notes `
        -Category "FileSystem"
}

Export-ModuleMember -Function Invoke-FileSystemAudit