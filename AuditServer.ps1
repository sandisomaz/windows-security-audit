<#
.SYNOPSIS
    Windows Security Audit - Web Server Backend (v3.1 - Fixed Path Logic)
#>
param($Port = 8080)

$RootPath = $PSScriptRoot
$HtmlFile = Join-Path $RootPath "index.html"
$CurrentJob = $null

if (-not (Test-Path $HtmlFile)) { Write-Error "index.html not found!"; exit }

function Get-JobOutput {
    if ($CurrentJob -and $CurrentJob.HasMoreData) { return Receive-Job -Job $CurrentJob }
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
    } catch {} finally { $Context.Response.Close() }
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$Port/")
try {
    $listener.Start()
    Write-Host " Security Audit Server running on Port $Port" -ForegroundColor Green
} catch {
    Write-Error "Could not start server. Port $Port might be in use."
    exit
}

while ($true) {
    if (-not $listener.IsListening) { break }
    $context = $listener.GetContext()
    $request = $context.Request
    $url = $request.Url.LocalPath

    # --- Serve Report Files Directly ---
    if ($url.StartsWith("/Reports/")) {
        # Fix URL decoding for spaces/special chars
        $decodedUrl = [System.Web.HttpUtility]::UrlDecode($url)
        $localPath = $decodedUrl -replace "/", "\"
        $fullPath = Join-Path $RootPath $localPath.TrimStart("\")
        
        if (Test-Path $fullPath) {
            $content = Get-Content -Path $fullPath -Raw
            Send-Response $context $content "text/html"
        } else {
            Send-Response $context "File not found: $fullPath" "text/plain" 404
        }
        continue
    }

    # --- API Router ---
    switch ($url.ToLower()) {
        "/" {
            $htmlContent = Get-Content -Path $HtmlFile -Raw
            Send-Response $context $htmlContent
        }
        
        "/api/start" {
            $mode = [System.Web.HttpUtility]::ParseQueryString($request.Url.Query).Get("mode")
            if ([string]::IsNullOrWhiteSpace($mode)) { $mode = "Quick" }

            if ($CurrentJob -and $CurrentJob.State -eq 'Running') {
                Send-Response $context '{"status":"error"}' "application/json" 409
            } else {
                if ($CurrentJob) { Remove-Job $CurrentJob -Force }
                $scriptPath = Join-Path $RootPath "SecurityAudit.ps1"
                $CurrentJob = Start-Job -ScriptBlock { param($p, $m) & $p -Mode $m *>&1 } -ArgumentList $scriptPath, $mode
                Send-Response $context '{"status":"success"}' "application/json"
            }
        }

        "/api/stop" {
            if ($CurrentJob) { Stop-Job $CurrentJob; Remove-Job $CurrentJob -Force; $CurrentJob = $null }
            Send-Response $context '{"status":"success"}' "application/json"
        }

        "/api/status" {
            $status = "Idle"; if ($CurrentJob) { $status = $CurrentJob.State }
            $newLogs = @(); 
            if ($CurrentJob) {
                $rawLogs = Get-JobOutput
                foreach ($line in $rawLogs) {
                    $msg = $line.ToString()
                    $type = "INFO"
                    if ($msg -match "FAIL|CRITICAL") { $type = "ERR" } elseif ($msg -match "WARN") { $type = "WARN" } elseif ($msg -match "PASS|OK") { $type = "SYS" }
                    $newLogs += @{ time = (Get-Date).ToString("HH:mm:ss"); type = $type; message = $msg }
                }
            }
            $payload = @{ status = $status; logs = $newLogs } | ConvertTo-Json -Compress
            Send-Response $context $payload "application/json"
        }

        "/api/open-report" {
            $reportsPath = Join-Path $RootPath "Reports"
            if (Test-Path $reportsPath) {
                # --- FIX IS HERE: Added -Directory switch ---
                # This forces it to ignore log files and only find the Report Folders
                $latest = Get-ChildItem -Path $reportsPath -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                
                if ($latest) {
                    $reportUrl = "/Reports/$($latest.Name)/report.html"
                    $json = @{ status = "success"; url = $reportUrl } | ConvertTo-Json
                    Send-Response $context $json "application/json"
                } else { Send-Response $context '{"status":"error", "message":"No report folders found"}' "application/json" 404 }
            } else { Send-Response $context '{"status":"error"}' "application/json" 404 }
        }

        default { Send-Response $context "404" "text/plain" 404 }
    }
}