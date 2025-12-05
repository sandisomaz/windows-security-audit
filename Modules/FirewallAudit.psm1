<#
.SYNOPSIS
    Windows Firewall configuration and rule analysis
.DESCRIPTION
    Checks:
    - Firewall status for all profiles (Domain, Private, Public)
    - Inbound/Outbound default actions
    - Suspicious firewall rules
    - Open ports
#>

using module .\Core.psm1

function Invoke-FirewallAudit {
    <#
    .SYNOPSIS
        Performs Windows Firewall analysis
    .PARAMETER Config
        Configuration object from Config.psd1
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )
    
    Write-AuditHeader "Windows Firewall Analysis"
    
    # === Firewall Profile Status ===
    Test-FirewallProfiles
    
    # === Suspicious Rules ===
    Test-FirewallRules
}

function Test-FirewallProfiles {
    Write-Host "Checking firewall profiles..." -ForegroundColor Cyan
    
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        
        foreach ($profile in $profiles) {
            $profileName = $profile.Name
            
            # Check if enabled
            if ($profile.Enabled) {
                Write-AuditResult "Firewall: $profileName" "ENABLED" -Status Pass
                
                Add-AuditFinding `
                    -Id "FW_$profileName" `
                    -Title "Firewall Profile: $profileName" `
                    -Value "Enabled" `
                    -Severity 1 `
                    -Category "Firewall"
            }
            else {
                Write-AuditResult "Firewall: $profileName" "DISABLED" -Status Fail
                
                Add-AuditFinding `
                    -Id "FW_$profileName" `
                    -Title "Firewall Profile: $profileName" `
                    -Value "Disabled" `
                    -Severity 0 `
                    -Weight 25 `
                    -Notes "CRITICAL: Firewall is disabled for $profileName profile. System is exposed to network attacks." `
                    -Category "Firewall"
            }
            
            # Check default actions
            Write-Host "  Default Inbound: $($profile.DefaultInboundAction)" -ForegroundColor Gray
            Write-Host "  Default Outbound: $($profile.DefaultOutboundAction)" -ForegroundColor Gray
            
            # Warn if inbound is not blocked by default
            if ($profile.DefaultInboundAction -ne 'Block') {
                Add-AuditFinding `
                    -Id "FW_${profileName}_Inbound" `
                    -Title "Firewall Default Inbound: $profileName" `
                    -Value $profile.DefaultInboundAction `
                    -Severity 2 `
                    -Notes "Default inbound action should be 'Block' for security." `
                    -Category "Firewall"
            }
        }
    }
    catch {
        Write-AuditResult "Firewall Profiles" "Query failed" -Status Fail
        
        Add-AuditFinding `
            -Id "FW_Error" `
            -Title "Firewall Status" `
            -Value "Query failed" `
            -Severity 0 `
            -Weight 25 `
            -Notes "Unable to query firewall status. This may indicate system corruption or malware." `
            -Category "Firewall"
    }
}

function Test-FirewallRules {
    Write-Host "Analyzing firewall rules..." -ForegroundColor Cyan
    Write-Host "  (This may take a moment)" -ForegroundColor Gray
    
    try {
        # Get all enabled rules
        $rules = Get-NetFirewallRule -Enabled True -ErrorAction Stop | 
            Where-Object { $_.Direction -eq 'Inbound' } |
            Select-Object -First 50
        
        Write-AuditResult "Enabled Inbound Rules" "$($rules.Count) rule(s) (showing first 50)" -Status Info
        
        # Look for suspicious rules
        $suspiciousRules = @()
        
        foreach ($rule in $rules) {
            # Check for rules allowing all traffic
            $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
            $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
            
            if ($rule.Action -eq 'Allow') {
                # Rule allows traffic from any address to any port
                if ($addressFilter -and $addressFilter.RemoteAddress -contains 'Any' -and 
                    $portFilter -and $portFilter.LocalPort -contains 'Any') {
                    
                    $suspiciousRules += [PSCustomObject]@{
                        Name = $rule.Name
                        DisplayName = $rule.DisplayName
                        Reason = "Allows ANY remote address to ANY port"
                    }
                }
                
                # Rule is not from Microsoft
                if ($rule.DisplayName -notmatch 'Microsoft|Windows|Core Networking') {
                    Write-Host "  Third-party rule: $($rule.DisplayName)" -ForegroundColor Yellow
                }
            }
        }
        
        if ($suspiciousRules.Count -gt 0) {
            Write-AuditResult "Suspicious Rules" "Found $($suspiciousRules.Count) potentially risky rule(s)" -Status Warn
            
            foreach ($rule in $suspiciousRules) {
                Write-Host "  - $($rule.DisplayName): $($rule.Reason)" -ForegroundColor Yellow
            }
            
            Add-AuditFinding `
                -Id "FW_SuspiciousRules" `
                -Title "Suspicious Firewall Rules" `
                -Value "Found $($suspiciousRules.Count) risky rule(s)" `
                -Severity 2 `
                -Notes "Review these rules in Windows Firewall settings. Overly permissive rules reduce security." `
                -Category "Firewall"
        }
        else {
            Write-AuditResult "Suspicious Rules" "None detected" -Status Pass
            
            Add-AuditFinding `
                -Id "FW_SuspiciousRules" `
                -Title "Suspicious Firewall Rules" `
                -Value "None detected" `
                -Severity 1 `
                -Category "Firewall"
        }
        
        Add-AuditFinding `
            -Id "FW_RuleCount" `
            -Title "Firewall Rules Summary" `
            -Value "$($rules.Count) enabled inbound rules" `
            -Severity 3 `
            -Category "Firewall"
            
    }
    catch {
        Write-AuditResult "Firewall Rules" "Analysis failed" -Status Warn
        
        Add-AuditFinding `
            -Id "FW_RulesError" `
            -Title "Firewall Rules Analysis" `
            -Value "Query failed" `
            -Severity 2 `
            -Category "Firewall"
    }
}

Export-ModuleMember -Function Invoke-FirewallAudit