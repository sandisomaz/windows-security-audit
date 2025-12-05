<#
.SYNOPSIS
    Network connection and configuration analysis
.DESCRIPTION
    Checks:
    - Active external network connections
    - DNS configuration
    - Listening ports
    - Network adapters
#>

using module .\Core.psm1

function Invoke-NetworkAudit {
    <#
    .SYNOPSIS
        Performs network security analysis
    .PARAMETER Config
        Configuration object from Config.psd1
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )
    
    Write-AuditHeader "Network Security Analysis"
    
    # === External Connections ===
    Test-ExternalConnections -Config $Config
    
    # === Listening Ports ===
    Test-ListeningPorts
    
    # === DNS Configuration ===
    Test-DNSConfiguration
    
    # === Network Adapters ===
    Test-NetworkAdapters
}

function Test-ExternalConnections {
    param([hashtable]$Config)
    
    Write-Host "Analyzing external network connections..." -ForegroundColor Cyan
    
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object {
            $_.RemoteAddress -and 
            ($_.RemoteAddress -notmatch "^127\.|^10\.|^172\.1[6-9]|^172\.2[0-9]|^172\.3[0-1]|^192\.168") -and
            $_.RemoteAddress -ne "::1"
        } |
        Select-Object -First $Config.Thresholds.MaxNetworkConnections
    
    if ($connections) {
        Write-AuditResult "External Connections" "Found $($connections.Count) established connection(s)" -Status Info
        
        $connectionDetails = @()
        
        foreach ($conn in $connections) {
            $process = Invoke-SafeCommand {
                (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).Name
            }
            
            $detail = "$($conn.LocalAddress):$($conn.LocalPort) → $($conn.RemoteAddress):$($conn.RemotePort) [$process]"
            Write-Host "  $detail" -ForegroundColor Gray
            
            $connectionDetails += $detail
        }
        
        Add-AuditFinding `
            -Id "Net_ExtConns" `
            -Title "External Network Connections" `
            -Value "Found $($connections.Count) connection(s)" `
            -Severity 3 `
            -Notes "Active connections: $($connectionDetails -join '; ')" `
            -Category "Network"
    }
    else {
        Write-AuditResult "External Connections" "None found" -Status Pass
        
        Add-AuditFinding `
            -Id "Net_ExtConns" `
            -Title "External Network Connections" `
            -Value "None" `
            -Severity 1 `
            -Category "Network"
    }
}

function Test-ListeningPorts {
    Write-Host "Checking listening ports..." -ForegroundColor Cyan
    
    $listening = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object -First 20
    
    if ($listening) {
        Write-AuditResult "Listening Ports" "Found $($listening.Count) listening port(s)" -Status Info
        
        $suspiciousPorts = @()
        
        foreach ($port in $listening) {
            $process = Invoke-SafeCommand {
                (Get-Process -Id $port.OwningProcess -ErrorAction SilentlyContinue).Name
            }
            
            Write-Host "  Port $($port.LocalPort) - $process" -ForegroundColor Gray
            
            # Flag common malware ports or uncommon services
            if ($port.LocalPort -in @(4444, 31337, 12345, 6667, 6666)) {
                $suspiciousPorts += "Port $($port.LocalPort) by $process"
            }
        }
        
        if ($suspiciousPorts.Count -gt 0) {
            Add-AuditFinding `
                -Id "Net_SusPorts" `
                -Title "Suspicious Listening Ports" `
                -Value "Found $($suspiciousPorts.Count) suspicious port(s)" `
                -Severity 2 `
                -Notes "Ports: $($suspiciousPorts -join ', '). Verify these are legitimate services." `
                -Category "Network"
        }
        else {
            Add-AuditFinding `
                -Id "Net_Listening" `
                -Title "Listening Ports" `
                -Value "$($listening.Count) port(s) listening" `
                -Severity 3 `
                -Category "Network"
        }
    }
    else {
        Write-AuditResult "Listening Ports" "None found" -Status Pass
    }
}

function Test-DNSConfiguration {
    Write-Host "Checking DNS configuration..." -ForegroundColor Cyan
    
    $dnsServers = Get-DnsClientServerAddress -ErrorAction SilentlyContinue
    
    if ($dnsServers) {
        $dnsInfo = @()
        
        foreach ($adapter in $dnsServers) {
            if ($adapter.ServerAddresses) {
                $servers = $adapter.ServerAddresses -join ", "
                Write-Host "  $($adapter.InterfaceAlias): $servers" -ForegroundColor Gray
                $dnsInfo += "$($adapter.InterfaceAlias): $servers"
            }
        }
        
        Add-AuditFinding `
            -Id "Net_DNS" `
            -Title "DNS Configuration" `
            -Value "Configured" `
            -Severity 3 `
            -Notes "DNS Servers: $($dnsInfo -join '; ')" `
            -Category "Network"
        
        Write-AuditResult "DNS Servers" "Configured" -Status Pass
    }
    else {
        Write-AuditResult "DNS Servers" "Query failed" -Status Warn
        
        Add-AuditFinding `
            -Id "Net_DNS" `
            -Title "DNS Configuration" `
            -Value "Unknown" `
            -Severity 2 `
            -Category "Network"
    }
}

function Test-NetworkAdapters {
    Write-Host "Checking network adapters..." -ForegroundColor Cyan
    
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Up' }
    
    if ($adapters) {
        Write-AuditResult "Active Adapters" "$($adapters.Count) adapter(s)" -Status Info
        
        foreach ($adapter in $adapters) {
            Write-Host "  - $($adapter.Name) [$($adapter.InterfaceDescription)]" -ForegroundColor Gray
        }
        
        Add-AuditFinding `
            -Id "Net_Adapters" `
            -Title "Network Adapters" `
            -Value "$($adapters.Count) active adapter(s)" `
            -Severity 3 `
            -Category "Network"
    }
    else {
        Write-AuditResult "Active Adapters" "None found" -Status Warn
    }
}

Export-ModuleMember -Function Invoke-NetworkAudit