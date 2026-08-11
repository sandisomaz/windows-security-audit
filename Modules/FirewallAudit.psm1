#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Firewall analysis module.
.DESCRIPTION
    Audits the Windows Firewall configuration for each profile and identifies
    potentially dangerous inbound and outbound rules. Port lists are driven
    entirely by Config.psd1.
.NOTES
    Version : 5.5.0
    Requires: PowerShell 5.1+, Administrator
#>

using module .\Core.psm1

function Invoke-FirewallAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )

    Write-AuditHeader 'Windows Firewall Analysis'

    foreach ($profile in @('Domain', 'Private', 'Public')) {
        Test-FirewallProfile -ProfileName $profile
    }

    Test-FirewallRules -Config $Config
}

function Test-FirewallProfile {
    param([string]$ProfileName)

    Write-Host "Checking Firewall Profile: $ProfileName..." -ForegroundColor Cyan

    $fwProfile = Get-NetFirewallProfile -Name $ProfileName -ErrorAction SilentlyContinue
    if (-not $fwProfile) {
        Write-AuditResult "Profile: $ProfileName" 'Could not query' -Status Info
        return
    }

    if ($fwProfile.Enabled -eq 'True') {
        Write-AuditResult "Profile: $ProfileName" 'Enabled' -Status Pass
        Add-AuditFinding -Id "FW_Profile_${ProfileName}_Enabled" -Title "Firewall Profile ($ProfileName)" `
            -Value 'Enabled' -Severity 1 -Category 'Firewall'
    } else {
        Write-AuditResult "Profile: $ProfileName" 'DISABLED' -Status Fail
        $notes = Format-FixRecommendation `
            -Problem "CRITICAL: The firewall for the '$ProfileName' profile is disabled. This leaves the system exposed to network attacks." `
            -QuickFix "Set-NetFirewallProfile -Name '$ProfileName' -Enabled True" `
            -ManualSteps @(
                "Open 'Windows Defender Firewall' in Control Panel.",
                "Click 'Turn Windows Defender Firewall on or off'.",
                "Under the '$ProfileName' settings, select 'Turn on Windows Defender Firewall'."
            ) `
            -IsSafe $true
        Add-AuditFinding -Id "FW_Profile_${ProfileName}_Disabled" -Title "Firewall Profile ($ProfileName)" `
            -Value 'Disabled' -Severity 0 -Weight 20 -Notes $notes -Category 'Firewall'
    }
}

function Test-FirewallRules {
    param([hashtable]$Config)

    Write-Host 'Analyzing firewall rules for suspicious entries...' -ForegroundColor Cyan

    # Resolve malicious ports from Config
    $maliciousPorts = if ($Config.Signatures -and $Config.Signatures.MaliciousOutboundPorts) {
        $Config.Signatures.MaliciousOutboundPorts
    } else {
        @(6667, 1337, 31337)
    }

    # --- Inbound: broad Allow-All rules (excluding known-good system rules) ---
    $allowAllInbound = Get-NetFirewallRule -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Where-Object {
        $_.Enabled -eq 'True' -and ($_.RemoteAddress -eq 'Any' -or -not $_.RemoteAddress)
    }

    $suspiciousInbound = $allowAllInbound | Where-Object {
        $_.DisplayName -notmatch 'Core Networking|Remote Assistance|Remote Desktop|Windows Remote Management'
    }

    if ($suspiciousInbound) {
        Write-AuditResult 'Suspicious Inbound Rules' "Found $($suspiciousInbound.Count) overly permissive rule(s)" -Status Warn
        $ruleNames = ($suspiciousInbound | Select-Object -First 5 -ExpandProperty DisplayName) -join ', '
        $notes = Format-FixRecommendation `
            -Problem 'Found firewall rules that allow ALL inbound traffic for certain applications. This is risky and could be exploited.' `
            -ManualSteps @(
                "Review these rules in 'Windows Defender Firewall with Advanced Security'.",
                "Rule names to check: $ruleNames",
                'If the rule is not for a trusted application, disable or delete it.',
                "Modify the rule to restrict by remote IP address instead of allowing 'Any'."
            )
        Add-AuditFinding -Id 'FW_SuspiciousInbound' -Title "Suspicious Inbound 'Allow' Rules" `
            -Value "$($suspiciousInbound.Count) found" -Severity 2 -Notes $notes -Category 'Firewall'
    } else {
        Write-AuditResult 'Suspicious Inbound Rules' 'None found' -Status Pass
    }

    # --- Outbound: rules allowing known malicious ports ---
    $suspiciousOutbound = Get-NetFirewallRule -Direction Outbound -Action Allow -ErrorAction SilentlyContinue | Where-Object {
        $_.Enabled -eq 'True' -and $_.RemotePort -in $maliciousPorts
    }

    if ($suspiciousOutbound) {
        Write-AuditResult 'Suspicious Outbound Rules' "Found $($suspiciousOutbound.Count) rule(s) allowing malicious ports" -Status Warn
        $ruleInfo = ($suspiciousOutbound | ForEach-Object { "$($_.DisplayName) (Port: $($_.RemotePort))" } | Select-Object -First 5) -join ', '
        $notes = Format-FixRecommendation `
            -Problem 'Found firewall rules allowing outbound connections on ports commonly used by malware (IRC, RATs).' `
            -ManualSteps @(
                "Review these rules immediately in 'Windows Defender Firewall with Advanced Security'.",
                "Rules to check: $ruleInfo",
                'Unless there is a specific legitimate reason, disable or delete these rules.'
            )
        Add-AuditFinding -Id 'FW_SuspiciousOutbound' -Title 'Suspicious Outbound Port Rules' `
            -Value "$($suspiciousOutbound.Count) found" -Severity 2 -Weight 15 -Notes $notes -Category 'Firewall'
    } else {
        Write-AuditResult 'Suspicious Outbound Rules' 'None found' -Status Pass
    }
}

Export-ModuleMember -Function Invoke-FirewallAudit