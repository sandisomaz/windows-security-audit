<#
.SYNOPSIS
    Network analysis module (ENHANCED)
.DESCRIPTION
    Audits network configurations, active connections, and for signs of
    DNS hijacking with detailed fix recommendations.
#>

using module .\Core.psm1

function Invoke-NetworkAudit {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )

    Write-AuditHeader "Network Configuration & Connection Analysis"

    Test-ListeningPorts
    Test-HostsFile
}

function Test-ListeningPorts {
    Write-Host "Analyzing listening ports for suspicious services..." -ForegroundColor Cyan

    $listening = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    if (-not $listening) {
        Write-AuditResult "Listening Ports" "Could not query" -Status Info
        return
    }

    # Common malware/RAT ports
    $suspiciousPorts = @(1337, 31337, 4444, 5555, 6666, 8888, 9999, 12345)
    $foundSuspicious = @()

    foreach ($conn in $listening) {
        if ($conn.LocalPort -in $suspiciousPorts) {
            $process = Invoke-SafeCommand { Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue }
            $processName = if ($process) { $process.ProcessName } else { "Unknown" }
            $foundSuspicious += [PSCustomObject]@{
                Port    = $conn.LocalPort
                Process = $processName
                PID     = $conn.OwningProcess
            }
        }
    }

    if ($foundSuspicious) {
        Write-AuditResult "Suspicious Listening Ports" "DETECTED: $($foundSuspicious.Count) port(s)" -Status Fail
        $details = $foundSuspicious | ForEach-Object { "Port $($_.Port) listened on by '$($_.Process)' (PID: $($_.PID))" }

        $notes = Format-FixRecommendation `
            -Problem "The system is listening for connections on ports commonly used by Remote Access Trojans (RATs) and other malware." `
            -ManualSteps @(
                "Investigate the following suspicious listeners:",
                ($details -join "`n"),
                "1. Use Task Manager to find the process by its PID.",
                "2. Right-click the process and select 'Open file location'.",
                "3. If the file is in a temporary or user directory, it is highly suspicious.",
                "4. End the process and delete the associated file.",
                "5. Run a full antivirus scan."
            )
        Add-AuditFinding -Id "Net_SuspiciousListener" -Title "Suspicious Listening Port" -Value "$($foundSuspicious.Count) found" -Severity 0 -Weight 20 -Notes $notes -Category "Network"
    }
    else {
        Write-AuditResult "Suspicious Listening Ports" "None detected" -Status Pass
        Add-AuditFinding -Id "Net_ListenersOK" -Title "Listening Ports" -Value "No common malware ports found" -Severity 1 -Category "Network"
    }
}

function Test-HostsFile {
    Write-Host "Checking HOSTS file for hijacking..." -ForegroundColor Cyan

    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (-not (Test-Path $hostsPath)) {
        Write-AuditResult "HOSTS File" "Not found" -Status Warn
        return
    }

    # Get entries that are not comments or localhost
    $entries = Get-Content $hostsPath | Where-Object { $_ -match '^\s*[^#\s]' -and $_ -notmatch 'localhost' }

    if ($entries) {
        Write-AuditResult "HOSTS File" "Found $($entries.Count) active entries (potential hijacking)" -Status Warn

        $details = ($entries | Select-Object -First 10) -join "`n"

        $notes = Format-FixRecommendation `
            -Problem "The HOSTS file contains active entries. Malware uses this file to redirect legitimate websites (like your bank) to malicious servers." `
            -QuickFix "Set-Content -Path '$hostsPath' -Value '# Default HOSTS file'" `
            -ManualSteps @(
                "The following entries were found:",
                $details,
                "1. Open Notepad as an Administrator.",
                "2. Go to File -> Open and navigate to '$hostsPath'.",
                "3. Change the file type filter from 'Text Documents' to 'All Files'.",
                "4. Open the 'hosts' file.",
                "5. Review each line. If you do not recognize an entry, put a '#' at the beginning of the line to disable it.",
                "6. Save the file."
            ) `
            -MoreInfo "https://www.howtogeek.com/howto/27350/beginner-geek-how-to-edit-your-hosts-file/" `
            -IsSafe $false

        Add-AuditFinding -Id "Net_HostsFileModified" -Title "HOSTS File Hijacking" -Value "$($entries.Count) active entries found" -Severity 2 -Weight 15 -Notes $notes -Category "Network"
    }
    else {
        Write-AuditResult "HOSTS File" "Clean" -Status Pass
        Add-AuditFinding -Id "Net_HostsFileClean" -Title "HOSTS File" -Value "Clean" -Severity 1 -Category "Network"
    }
}

Export-ModuleMember -Function Invoke-NetworkAudit