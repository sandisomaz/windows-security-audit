<#
.SYNOPSIS
    Windows Firewall analysis module (ENHANCED)
.DESCRIPTION
    Audits the Windows Firewall configuration for each profile and identifies
    potentially dangerous inbound and outbound rules.
#>

using module .\Core.psm1

function Invoke-FirewallAudit {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )

    Write-AuditHeader "Windows Firewall Analysis"

    $profiles = @("Domain", "Private", "Public")

    foreach ($profile in $profiles) {
        Test-FirewallProfile -ProfileName $profile
    }

    Test-FirewallRules
}

function Test-FirewallProfile {
    param([string]$ProfileName)

    Write-Host "Checking Firewall Profile: $ProfileName..." -ForegroundColor Cyan

    $fwProfile = Get-NetFirewallProfile -Name $ProfileName -ErrorAction SilentlyContinue

    if (-not $fwProfile) {
        Write-AuditResult "Profile: $ProfileName" "Could not query" -Status Info
        return
    }

    if ($fwProfile.Enabled -eq 'True') {
        Write-AuditResult "Profile: $ProfileName" "Enabled" -Status Pass
        Add-AuditFinding -Id "FW_Profile_$($ProfileName)_Enabled" -Title "Firewall Profile ($ProfileName)" -Value "Enabled" -Severity 1 -Category "Firewall"
    }
    else {
        Write-AuditResult "Profile: $ProfileName" "DISABLED" -Status Fail
        $notes = Format-FixRecommendation `
            -Problem "CRITICAL: The firewall for the '$ProfileName' profile is disabled. This leaves the system exposed to network attacks on this profile." `
            -QuickFix "Set-NetFirewallProfile -Name '$ProfileName' -Enabled True" `
            -ManualSteps @(
                "Open 'Windows Defender Firewall' in Control Panel.",
                "Click 'Turn Windows Defender Firewall on or off'.",
                "Under the '$ProfileName' settings, select 'Turn on Windows Defender Firewall'."
            ) `
            -IsSafe $true
        Add-AuditFinding -Id "FW_Profile_$($ProfileName)_Disabled" -Title "Firewall Profile ($ProfileName)" -Value "Disabled" -Severity 0 -Weight 20 -Notes $notes -Category "Firewall"
    }
}

function Test-FirewallRules {
    Write-Host "Analyzing firewall rules for suspicious entries..." -ForegroundColor Cyan

    # Check for broad "Allow All" inbound rules
    $allowAllInbound = Get-NetFirewallRule -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Where-Object {
        $_.Enabled -eq 'True' -and
        ($_.RemoteAddress -eq 'Any' -or !$_.RemoteAddress)
    }

    $suspiciousInbound = $allowAllInbound | Where-Object {
        $ruleName = $_.DisplayName.ToLower()
        $ruleName -notmatch 'core networking|remote assistance|remote desktop|windows remote management'
    }

    if ($suspiciousInbound) {
        Write-AuditResult "Suspicious Inbound Rules" "Found $($suspiciousInbound.Count) overly permissive rule(s)" -Status Warn
        $ruleNames = ($suspiciousInbound | Select-Object -First 5 -ExpandProperty DisplayName) -join ", "

        $notes = Format-FixRecommendation `
            -Problem "Found firewall rules that allow ALL inbound traffic for certain applications. This is risky and could be exploited." `
            -ManualSteps @(
                "Review these rules in 'Windows Defender Firewall with Advanced Security'.",
                "Search for the following rule names: $ruleNames",
                "If the rule is not for a trusted application, disable or delete it.",
                "Modify the rule to be more specific (e.g., restrict by remote IP address) instead of allowing 'Any'."
            )
        Add-AuditFinding -Id "FW_SuspiciousInbound" -Title "Suspicious Inbound 'Allow' Rules" -Value "$($suspiciousInbound.Count) found" -Severity 2 -Notes $notes -Category "Firewall"
    }
    else {
        Write-AuditResult "Suspicious Inbound Rules" "None found" -Status Pass
    }

    # Check for rules allowing known malicious ports outbound
    $maliciousPorts = @(6667, 1337, 31337) # IRC, common RAT ports
    $suspiciousOutbound = Get-NetFirewallRule -Direction Outbound -Action Allow -ErrorAction SilentlyContinue | Where-Object {
        $_.Enabled -eq 'True' -and $_.RemotePort -in $maliciousPorts
    }

    if ($suspiciousOutbound) {
        Write-AuditResult "Suspicious Outbound Rules" "Found $($suspiciousOutbound.Count) rule(s) allowing malicious ports" -Status Warn
        $ruleInfo = $suspiciousOutbound | ForEach-Object { "$($_.DisplayName) (Port: $($_.RemotePort))" } | Select-Object -First 5

        $notes = Format-FixRecommendation `
            -Problem "Found firewall rules allowing outbound connections on ports commonly used by malware (e.g., IRC, RATs)." `
            -ManualSteps @(
                "Review these rules immediately in 'Windows Defender Firewall with Advanced Security'.",
                "Rules to check: $($ruleInfo -join ', ')",
                "Unless you have a specific, legitimate reason for these rules, they should be disabled or deleted."
            )
        Add-AuditFinding -Id "FW_SuspiciousOutbound" -Title "Suspicious Outbound Port Rules" -Value "$($suspiciousOutbound.Count) found" -Severity 2 -Weight 15 -Notes $notes -Category "Firewall"
    }
    else {
        Write-AuditResult "Suspicious Outbound Rules" "None found" -Status Pass
    }
}

Export-ModuleMember -Function Invoke-FirewallAudit