<#
.SYNOPSIS
    Report generation module for security audit results
.DESCRIPTION
    Generates HTML, JSON, and CSV reports from audit findings
#>

using module .\Core.psm1

# Load required assembly for HTML encoding
Add-Type -AssemblyName System.Web

function New-AuditReport {
    <#
    .SYNOPSIS
        Generates audit reports in multiple formats
    .PARAMETER ReportPath
        Base path for report folder
    .PARAMETER Config
        Configuration hashtable
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ReportPath,
        
        [Parameter(Mandatory)]
        [hashtable]$Config
    )
    
    Write-AuditHeader "Generating Reports"
    
    # Create report folder
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFolder = Join-Path $ReportPath "WinSecAudit_$timestamp"
    New-Item -Path $reportFolder -ItemType Directory -Force | Out-Null
    
    # Get findings and system info
    $findings = Get-AuditFindings
    $systemInfo = Get-SystemInfo
    $riskScore = Get-RiskScore
    
    # Prepare report data
    $reportData = @{
        GeneratedAt = Get-Date -Format "s"
        SystemInfo = $systemInfo
        RiskScore = $riskScore
        Findings = $findings
    }
    
    $reports = @()
    
    # Generate JSON report
    if ($Config.Output.GenerateJSON) {
        $jsonPath = Join-Path $reportFolder "report.json"
        Export-JSONReport -Data $reportData -Path $jsonPath
        $reports += $jsonPath
    }
    
    # Generate HTML report
    if ($Config.Output.GenerateHTML) {
        $htmlPath = Join-Path $reportFolder "report.html"
        Export-HTMLReport -Data $reportData -Path $htmlPath
        $reports += $htmlPath
        
        # Auto-open if configured
        if ($Config.Output.AutoOpenReport) {
            Start-Process $htmlPath
        }
    }
    
    # Generate CSV report
    if ($Config.Output.GenerateCSV) {
        $csvPath = Join-Path $reportFolder "report.csv"
        Export-CSVReport -Data $reportData -Path $csvPath
        $reports += $csvPath
    }
    
    Write-AuditResult "Reports Generated" "$($reports.Count) file(s)" -Status Pass
    Write-Host ""
    Write-Host "Reports saved to:" -ForegroundColor Cyan
    Write-Host "  $reportFolder" -ForegroundColor Gray
    Write-Host ""
    
    foreach ($report in $reports) {
        Write-Host "  - $(Split-Path $report -Leaf)" -ForegroundColor Gray
    }
    
    return $reportFolder
}

function Export-JSONReport {
    param(
        [hashtable]$Data,
        [string]$Path
    )
    
    try {
        $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
        Write-AuditLog "JSON report saved: $Path" -Level Info
    }
    catch {
        Write-AuditLog "Failed to generate JSON report: $($_.Exception.Message)" -Level Error
    }
}

function Export-CSVReport {
    param(
        [hashtable]$Data,
        [string]$Path
    )
    
    try {
        $Data.Findings | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        Write-AuditLog "CSV report saved: $Path" -Level Info
    }
    catch {
        Write-AuditLog "Failed to generate CSV report: $($_.Exception.Message)" -Level Error
    }
}

function Export-HTMLReport {
    param(
        [hashtable]$Data,
        [string]$Path
    )
    
    try {
        $html = Build-HTMLReport -Data $Data
        $html | Out-File -FilePath $Path -Encoding UTF8
        Write-AuditLog "HTML report saved: $Path" -Level Info
    }
    catch {
        Write-AuditLog "Failed to generate HTML report: $($_.Exception.Message)" -Level Error
    }
}

function Build-HTMLReport {
    param([hashtable]$Data)
    
    $sysInfo = $Data.SystemInfo
    $riskScore = $Data.RiskScore
    $findings = $Data.Findings
    
    # Determine severity color
    $severityColor = switch ($riskScore.SeverityLabel) {
        "HIGH"   { "bad" }
        "MEDIUM" { "warn" }
        "LOW"    { "good" }
        default  { "info" }
    }
    
    # Build findings table
    $findingsRows = ""
    foreach ($finding in $findings) {
        $sevText = ConvertTo-SeverityText -Severity $finding.Severity
        $sevClass = $sevText
        
        $safeValue = [System.Web.HttpUtility]::HtmlEncode($finding.Value)
        $safeNotes = [System.Web.HttpUtility]::HtmlEncode($finding.Notes)
        
        $findingsRows += @"
<tr>
    <td>$($finding.Id)</td>
    <td>$($finding.Title)</td>
    <td>$safeValue</td>
    <td><span class='$sevClass'>$sevText</span></td>
    <td>$($finding.Weight)</td>
    <td>$($finding.Category)</td>
    <td>$safeNotes</td>
</tr>

"@
    }
    
    # Build complete HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Security Audit Report</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        
        .header p {
            opacity: 0.9;
            font-size: 1.1em;
        }
        
        .content {
            padding: 40px;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .info-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        
        .info-card h3 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .info-card p {
            color: #333;
            font-size: 1.1em;
            font-weight: 600;
        }
        
        .risk-score {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            margin: 30px 0;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        
        .risk-score.LOW {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }
        
        .risk-score.MEDIUM {
            background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        }
        
        .risk-score.HIGH {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }
        
        .risk-score h2 {
            font-size: 3em;
            margin-bottom: 10px;
        }
        
        .risk-score p {
            opacity: 0.9;
            font-size: 1.2em;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            border-radius: 8px;
            overflow: hidden;
        }
        
        thead {
            background: #667eea;
            color: white;
        }
        
        th, td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }
        
        th {
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }
        
        tbody tr:hover {
            background: #f8f9fa;
        }
        
        .FAIL {
            color: #dc3545;
            font-weight: bold;
            background: #ffe6e6;
            padding: 4px 8px;
            border-radius: 4px;
        }
        
        .WARN {
            color: #ff9800;
            font-weight: bold;
            background: #fff3e0;
            padding: 4px 8px;
            border-radius: 4px;
        }
        
        .PASS {
            color: #28a745;
            font-weight: bold;
            background: #e6ffe6;
            padding: 4px 8px;
            border-radius: 4px;
        }
        
        .INFO {
            color: #6c757d;
            font-weight: bold;
            background: #f0f0f0;
            padding: 4px 8px;
            border-radius: 4px;
        }
        
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            font-size: 0.9em;
            border-top: 1px solid #e0e0e0;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 30px 0;
        }
        
        .stat-box {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 2px solid #e0e0e0;
        }
        
        .stat-box h3 {
            font-size: 2em;
            margin-bottom: 5px;
        }
        
        .stat-box.fail h3 { color: #dc3545; }
        .stat-box.warn h3 { color: #ff9800; }
        .stat-box.pass h3 { color: #28a745; }
        .stat-box.info h3 { color: #6c757d; }
        
        .stat-box p {
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Windows Security Audit Report</h1>
            <p>Forensic Suite v5.1 - Comprehensive Security Assessment</p>
        </div>
        
        <div class="content">
            <div class="info-grid">
                <div class="info-card">
                    <h3>Computer Name</h3>
                    <p>$($sysInfo.ComputerName)</p>
                </div>
                <div class="info-card">
                    <h3>Operating System</h3>
                    <p>$($sysInfo.OSName)</p>
                </div>
                <div class="info-card">
                    <h3>Architecture</h3>
                    <p>$($sysInfo.Architecture)</p>
                </div>
                <div class="info-card">
                    <h3>Generated</h3>
                    <p>$($Data.GeneratedAt)</p>
                </div>
            </div>
            
            <div class="risk-score $($riskScore.SeverityLabel)">
                <h2>$($riskScore.SeverityLabel) RISK</h2>
                <p>$($riskScore.RiskPercent)% Risk Score</p>
                <p style="font-size: 0.9em; margin-top: 10px;">
                    $($riskScore.RawScore) points out of $($riskScore.MaxPossible) possible
                </p>
            </div>
            
            <div class="stats">
                <div class="stat-box fail">
                    <h3>$(($findings | Where-Object {$_.Severity -eq 0}).Count)</h3>
                    <p>Critical Issues</p>
                </div>
                <div class="stat-box warn">
                    <h3>$(($findings | Where-Object {$_.Severity -eq 2}).Count)</h3>
                    <p>Warnings</p>
                </div>
                <div class="stat-box pass">
                    <h3>$(($findings | Where-Object {$_.Severity -eq 1}).Count)</h3>
                    <p>Passed Checks</p>
                </div>
                <div class="stat-box info">
                    <h3>$($findings.Count)</h3>
                    <p>Total Findings</p>
                </div>
            </div>
            
            <h2 style="margin-top: 40px; color: #667eea;">Detailed Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Title</th>
                        <th>Value</th>
                        <th>Severity</th>
                        <th>Weight</th>
                        <th>Category</th>
                        <th>Notes</th>
                    </tr>
                </thead>
                <tbody>
                    $findingsRows
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Windows Security Audit Framework - Built with PowerShell</p>
            <p>Open Source Project - Licensed for Security Research</p>
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}

Export-ModuleMember -Function New-AuditReport