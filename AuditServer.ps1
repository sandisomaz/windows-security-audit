<#
.SYNOPSIS
    Windows Security Audit - Web Server Backend
.DESCRIPTION
    Hosts the web interface and handles API requests from the browser.
#>
param($Port = 8080)

# --- Configuration ---
$RootPath = $PSScriptRoot
$HtmlFile = Join-Path $RootPath "index.html"
$CurrentJob = $null

# Ensure HTML file exists
if (-not (Test-Path $HtmlFile)) {
    Write-Error "index.html not found! Please check your installation."
    exit
}

# --- Helper Functions ---
function Get-JobOutput {
    if ($CurrentJob -and $CurrentJob.HasMoreData) {
        return Receive-Job -Job $CurrentJob
    }
    return @()
}

function Send-Response {
    param($Context, $Content, $ContentType = "text/html", $StatusCode = 200)
    try {
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($Content)
        $Context.Response.ContentType = $ContentType
        $Context.Response.StatusCode = $StatusCode
        $Context.Response.ContentLength64 = $buffer.Length
        $Context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
    } catch {
        Write-Warning "Failed to send response: $_"
    } finally {
        $Context.Response.Close()
    }
}

# --- Start Server ---
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$Port/")
try {
    $listener.Start()
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host " Security Audit Server running on Port $Port" -ForegroundColor Green
    Write-Host " Keep this window open." -ForegroundColor Gray
    Write-Host "============================================="
} catch {
    Write-Error "Could not start server. Port $Port might be in use or admin rights missing."
    exit
}

# --- Main Loop ---
while ($true) {
    if (-not $listener.IsListening) { break }
    
    $context = $listener.GetContext()
    $request = $context.Request
    $url = $request.Url.LocalPath.ToLower()

    switch ($url) {
        "/" {
            # Serve Dashboard
            $htmlContent = Get-Content -Path $HtmlFile -Raw
            Send-Response $context $htmlContent
        }
        
        "/api/start" {
            # Start Scan
            $mode = [System.Web.HttpUtility]::ParseQueryString($request.Url.Query).Get("mode")
            if ([string]::IsNullOrWhiteSpace($mode)) { $mode = "Quick" }

            if ($CurrentJob -and $CurrentJob.State -eq 'Running') {
                Send-Response $context '{"status":"error", "message":"Scan already running"}' "application/json" 409
            } else {
                if ($CurrentJob) { Remove-Job $CurrentJob -Force }
                $scriptPath = Join-Path $RootPath "SecurityAudit.ps1"
                
                # Start job quietly
                $CurrentJob = Start-Job -ScriptBlock {
                    param($p, $m)
                    & $p -Mode $m *>&1 
                } -ArgumentList $scriptPath, $mode
                
                Send-Response $context '{"status":"success"}' "application/json"
            }
        }

        "/api/stop" {
            # Stop Scan
            if ($CurrentJob) {
                Stop-Job $CurrentJob
                Remove-Job $CurrentJob -Force
                $CurrentJob = $null
            }
            Send-Response $context '{"status":"success"}' "application/json"
        }

        "/api/status" {
            # Polling Endpoint
            $status = "Idle"
            if ($CurrentJob) { $status = $CurrentJob.State }

            $newLogs = @()
            if ($CurrentJob) {
                $rawLogs = Get-JobOutput
                foreach ($line in $rawLogs) {
                    $msg = $line.ToString()
                    $type = "INFO"
                    if ($msg -match "FAIL|CRITICAL") { $type = "ERR" }
                    elseif ($msg -match "WARN") { $type = "WARN" }
                    elseif ($msg -match "PASS|OK") { $type = "SYS" }

                    $newLogs += @{
                        time = (Get-Date).ToString("HH:mm:ss")
                        type = $type
                        message = $msg
                    }
                }
            }

            $payload = @{ status = $status; logs = $newLogs } | ConvertTo-Json -Compress
            Send-Response $context $payload "application/json"
        }

        "/api/open-report" {
            # Open Latest Report
            $reportsPath = Join-Path $RootPath "Reports"
            if (Test-Path $reportsPath) {
                $latest = Get-ChildItem -Path $reportsPath | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($latest) {
                    $reportFile = Join-Path $latest.FullName "report.html"
                    if (Test-Path $reportFile) {
                        Invoke-Item $reportFile
                        Send-Response $context '{"status":"success"}' "application/json"
                    } else { Send-Response $context '{"status":"error"}' "application/json" 404 }
                } else { Send-Response $context '{"status":"error"}' "application/json" 404 }
            } else { Send-Response $context '{"status":"error"}' "application/json" 404 }
        }

        default {
            Send-Response $context "404 Not Found" "text/plain" 404
        }
    }
}