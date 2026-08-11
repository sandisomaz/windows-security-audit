#Requires -Version 5.1
<#
.SYNOPSIS
    Network configuration and active connection analysis module.
.DESCRIPTION
    Audits listening ports for known RAT/backdoor ports and checks the HOSTS
    file for hijacking indicators. Port lists are driven entirely by Config.psd1.
.NOTES
    Version : 5.5.0
    Requires: PowerShell 5.1+, Administrator
#>

using module .\Core.psm1

function Invoke-NetworkAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )

    Write-AuditHeader 'Network Configuration & Connection Analysis'

    Test-ListeningPorts -Config $Config
    Test-HostsFile
}

function Test-ListeningPorts {
    param([hashtable]$Config)

    Write-Host 'Analyzing listening ports for suspicious services...' -ForegroundColor Cyan

    # Resolve port list from Config; fall back to a conservative default
    $suspiciousPorts = if ($Config.Signatures -and $Config.Signatures.SuspiciousListeningPorts) {
        $Config.Signatures.SuspiciousListeningPorts
    } else {
        @(1337, 31337, 4444, 5555, 6666, 8888, 9999, 12345)
    }

    $listening = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    if (-not $listening) {
        Write-AuditResult 'Listening Ports' 'Could not query' -Status Info
        return
    }

    $foundSuspicious = @()

    foreach ($conn in $listening) {
        if ($conn.LocalPort -in $suspiciousPorts) {
            $process = Invoke-SafeCommand { Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue }
            $processName = if ($process) { $process.ProcessName } else { 'Unknown' }
            $foundSuspicious += [PSCustomObject]@{
                Port    = $conn.LocalPort
                Process = $processName
                PID     = $conn.OwningProcess
            }
        }
    }

    if ($foundSuspicious) {
        Write-AuditResult 'Suspicious Listening Ports' "DETECTED: $($foundSuspicious.Count) port(s)" -Status Fail
        $details = $foundSuspicious | ForEach-Object {
            "Port $($_.Port) listened on by '$($_.Process)' (PID: $($_.PID))"
        }

        $notes = Format-FixRecommendation `
            -Problem 'The system is listening for connections on ports commonly used by Remote Access Trojans (RATs) and other malware.' `
            -ManualSteps @(
                'Investigate the following suspicious listeners:',
                ($details -join "`n"),
                '1. Use Task Manager to find the process by its PID.',
                "2. Right-click the process and select 'Open file location'.",
                '3. If the file is in a temporary or user directory, it is highly suspicious.',
                '4. End the process and delete the associated file.',
                '5. Run a full antivirus scan.'
            )
        Add-AuditFinding -Id 'Net_SuspiciousListener' -Title 'Suspicious Listening Port' `
            -Value "$($foundSuspicious.Count) found" -Severity 0 -Weight 20 -Notes $notes -Category 'Network'
    } else {
        Write-AuditResult 'Suspicious Listening Ports' 'None detected' -Status Pass
        Add-AuditFinding -Id 'Net_ListenersOK' -Title 'Listening Ports' `
            -Value 'No common malware ports found' -Severity 1 -Category 'Network'
    }
}

function Test-HostsFile {
    Write-Host 'Checking HOSTS file for hijacking...' -ForegroundColor Cyan

    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (-not (Test-Path $hostsPath)) {
        Write-AuditResult 'HOSTS File' 'Not found' -Status Warn
        return
    }

    $entries = Get-Content $hostsPath | Where-Object {
        $_ -match '^\s*[^#\s]' -and $_ -notmatch 'localhost'
    }

    if ($entries) {
        Write-AuditResult 'HOSTS File' "Found $($entries.Count) active entries (potential hijacking)" -Status Warn
        $details = ($entries | Select-Object -First 10) -join "`n"

        $notes = Format-FixRecommendation `
            -Problem 'The HOSTS file contains active entries. Malware uses this file to redirect legitimate websites to malicious servers.' `
            -QuickFix "Set-Content -Path '$hostsPath' -Value '# Default HOSTS file'" `
            -ManualSteps @(
                'The following entries were found:',
                $details,
                "1. Open Notepad as an Administrator.",
                "2. Go to File -> Open and navigate to '$hostsPath'.",
                "3. Change the file type filter to 'All Files'.",
                "4. Open the 'hosts' file.",
                "5. Review each line. Prefix suspicious entries with '#' to disable them.",
                '6. Save the file.'
            ) `
            -MoreInfo 'https://support.microsoft.com/en-us/topic/how-to-reset-the-hosts-file-back-to-the-default-c2a43f9d-e176-c6f3-e4ef-3500277a6dae' `
            -IsSafe $false

        Add-AuditFinding -Id 'Net_HostsFileModified' -Title 'HOSTS File Hijacking' `
            -Value "$($entries.Count) active entries found" -Severity 2 -Weight 15 -Notes $notes -Category 'Network'
    } else {
        Write-AuditResult 'HOSTS File' 'Clean' -Status Pass
        Add-AuditFinding -Id 'Net_HostsFileClean' -Title 'HOSTS File' -Value 'Clean' -Severity 1 -Category 'Network'
    }
}

Export-ModuleMember -Function Invoke-NetworkAudit