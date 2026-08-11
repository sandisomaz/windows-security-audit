#Requires -Version 5.1
<#
.SYNOPSIS
    HTTP API server for the Windows Security Audit Framework web dashboard.
.DESCRIPTION
    Hosts a lightweight REST API on localhost using System.Net.HttpListener.
    The dashboard (index.html) communicates with this server to start/stop
    audit jobs and stream live log output.
.PARAMETER Port
    TCP port to listen on. Default: 8080
.NOTES
    Version : 5.5.0
    Requires: PowerShell 5.1+, Windows
    Run As  : Administrator (recommended)
#>
[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8080
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
$RootPath      = $PSScriptRoot
$IndexHtmlPath = Join-Path $RootPath 'index.html'
$LogPath       = Join-Path $RootPath 'Reports' | Join-Path -ChildPath 'server_access.log'

if (-not (Test-Path (Join-Path $RootPath 'Modules\Core.psm1'))) {
    Write-Error "Cannot locate Modules\Core.psm1. Run AuditServer.ps1 from the project root directory."
    exit 1
}

# ---------------------------------------------------------------------------
# Session security: one-time GUID token, injected into the dashboard HTML
# ---------------------------------------------------------------------------
$SessionToken = [Guid]::NewGuid().ToString('N')   # 32-char hex, no dashes

# ---------------------------------------------------------------------------
# Job tracking state
# ---------------------------------------------------------------------------
$script:CurrentJob       = $null
$script:CurrentJobMode   = $null
$script:JobStartTime     = $null
$script:JobOutputStream  = [System.Collections.Generic.List[string]]::new()

# ---------------------------------------------------------------------------
# Clean up any orphaned jobs from a previous run of this server
# ---------------------------------------------------------------------------
Get-Job | Where-Object { $_.Name -eq 'SecurityAuditJob' } | ForEach-Object {
    Write-Host " [*] Removing orphaned job: $($_.Id)" -ForegroundColor Yellow
    $_ | Stop-Job -ErrorAction SilentlyContinue
    $_ | Remove-Job -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-AccessLog {
    param([string]$Method, [string]$Path, [int]$StatusCode, [string]$RemoteAddr)
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $RemoteAddr $Method $Path $StatusCode"
    try {
        $logDir = Split-Path $LogPath
        if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        Add-Content -Path $LogPath -Value $entry -ErrorAction SilentlyContinue
    } catch {}
    Write-Verbose $entry
}

function Send-Response {
    param(
        [System.Net.HttpListenerContext]$Context,
        [string]$Body,
        [string]$ContentType = 'application/json; charset=utf-8',
        [int]$StatusCode = 200
    )
    $Context.Response.StatusCode = $StatusCode
    $Context.Response.ContentType = $ContentType

    # Restrict CORS to localhost only
    $origin = $Context.Request.Headers['Origin']
    $allowedOrigins = @("http://localhost:$Port", "http://127.0.0.1:$Port")
    if ($origin -and $allowedOrigins -contains $origin) {
        $Context.Response.Headers.Add('Access-Control-Allow-Origin', $origin)
        $Context.Response.Headers.Add('Vary', 'Origin')
    }
    $Context.Response.Headers.Add('X-Content-Type-Options', 'nosniff')
    $Context.Response.Headers.Add('X-Frame-Options', 'SAMEORIGIN')
    $Context.Response.Headers.Add('Cache-Control', 'no-store')

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Context.Response.OutputStream.Close()
}

function Send-JsonResponse {
    param(
        [System.Net.HttpListenerContext]$Context,
        [hashtable]$Data,
        [int]$StatusCode = 200
    )
    $json = $Data | ConvertTo-Json -Depth 5 -Compress
    Send-Response -Context $Context -Body $json -ContentType 'application/json; charset=utf-8' -StatusCode $StatusCode
}

function Test-AuthToken {
    param([System.Net.HttpListenerContext]$Context)
    $token = $Context.Request.Headers['X-Audit-Token']
    return ($token -eq $SessionToken)
}

function Send-Unauthorized {
    param([System.Net.HttpListenerContext]$Context)
    Send-JsonResponse -Context $Context -Data @{ status = 'error'; message = 'Unauthorized' } -StatusCode 401
}

# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------
function Invoke-RouteRoot {
    param([System.Net.HttpListenerContext]$Context)
    if (-not (Test-Path $IndexHtmlPath)) {
        Send-Response -Context $Context -Body '<h1>index.html not found</h1>' -ContentType 'text/html' -StatusCode 404
        return
    }
    $html = Get-Content -Path $IndexHtmlPath -Raw -Encoding UTF8
    # Inject the session token into a <meta> tag for the JS to read
    $html = $html -replace '(?i)<meta\s+name=["\x27]audit-token["\x27][^>]*>', ''
    $html = $html -replace '(<head>)', "<head>`n    <meta name=`"audit-token`" content=`"$SessionToken`" />"
    Send-Response -Context $Context -Body $html -ContentType 'text/html; charset=utf-8'
}

function Invoke-RouteStart {
    param([System.Net.HttpListenerContext]$Context)
    if (-not (Test-AuthToken $Context)) { Send-Unauthorized $Context; return }

    $query = [System.Web.HttpUtility]::ParseQueryString($Context.Request.Url.Query)
    $mode  = $query['mode']

    $validModes = @('Quick', 'Standard', 'Deep', 'Forensic')
    if ($mode -notin $validModes) {
        Send-JsonResponse -Context $Context -Data @{ status = 'error'; message = "Invalid mode. Valid modes: $($validModes -join ', ')" } -StatusCode 400
        return
    }

    if ($script:CurrentJob -and $script:CurrentJob.State -eq 'Running') {
        Send-JsonResponse -Context $Context -Data @{ status = 'error'; message = 'An audit is already running.' } -StatusCode 409
        return
    }

    $auditScript = Join-Path $RootPath 'SecurityAudit.ps1'
    $script:JobOutputStream.Clear()
    $script:CurrentJobMode = $mode
    $script:JobStartTime   = Get-Date

    $script:CurrentJob = Start-Job -Name 'SecurityAuditJob' -ScriptBlock {
        param($ScriptPath, $AuditMode)
        & $ScriptPath -Mode $AuditMode *>&1
    } -ArgumentList $auditScript, $mode

    Send-JsonResponse -Context $Context -Data @{ status = 'success'; mode = $mode }
}

function Invoke-RouteStop {
    param([System.Net.HttpListenerContext]$Context)
    if (-not (Test-AuthToken $Context)) { Send-Unauthorized $Context; return }

    if ($script:CurrentJob) {
        Stop-Job  -Job $script:CurrentJob -ErrorAction SilentlyContinue
        Remove-Job -Job $script:CurrentJob -Force -ErrorAction SilentlyContinue
        $script:CurrentJob = $null
    }
    Send-JsonResponse -Context $Context -Data @{ status = 'success'; message = 'Scan stopped.' }
}

function Invoke-RouteStatus {
    param([System.Net.HttpListenerContext]$Context)
    if (-not (Test-AuthToken $Context)) { Send-Unauthorized $Context; return }

    $state          = 'Idle'
    $elapsedSeconds = 0
    $newLogs        = @()

    if ($script:CurrentJob) {
        $state = switch ($script:CurrentJob.State) {
            'Running'   { 'Running' }
            'Completed' { 'Completed' }
            'Failed'    { 'Failed' }
            'Stopped'   { 'Stopped' }
            default     { 'Idle' }
        }

        if ($script:JobStartTime) {
            $elapsedSeconds = [int]((Get-Date) - $script:JobStartTime).TotalSeconds
        }

        # Drain buffered output from the job
        $rawLines = Receive-Job -Job $script:CurrentJob -ErrorAction SilentlyContinue
        foreach ($line in $rawLines) {
            $lineStr = "$line"
            if (-not $lineStr.Trim()) { continue }
            $script:JobOutputStream.Add($lineStr)

            $type = switch -Regex ($lineStr) {
                '\[FAIL\]|ERROR|CRITICAL' { 'ERR'  }
                '\[WARN\]|WARNING'        { 'WARN' }
                '===|\[OK\]|\[SYS\]'     { 'SYS'  }
                default                  { 'INFO' }
            }
            $newLogs += @{ time = (Get-Date -Format 'HH:mm:ss'); type = $type; message = $lineStr }
        }

        # Clean up completed/failed jobs
        if ($state -in 'Completed', 'Failed', 'Stopped') {
            Remove-Job -Job $script:CurrentJob -Force -ErrorAction SilentlyContinue
            $script:CurrentJob = $null
        }
    }

    Send-JsonResponse -Context $Context -Data @{
        status         = $state
        mode           = $script:CurrentJobMode
        elapsedSeconds = $elapsedSeconds
        logs           = $newLogs
    }
}

function Invoke-RouteOpenReport {
    param([System.Net.HttpListenerContext]$Context)
    if (-not (Test-AuthToken $Context)) { Send-Unauthorized $Context; return }

    $reportsDir = Join-Path $RootPath 'Reports'
    $latest = Get-ChildItem -Path $reportsDir -Directory -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if (-not $latest) {
        Send-JsonResponse -Context $Context -Data @{ status = 'error'; message = 'No reports found.' } -StatusCode 404
        return
    }

    $reportFile = Join-Path $latest.FullName 'report.html'
    if (-not (Test-Path $reportFile)) {
        Send-JsonResponse -Context $Context -Data @{ status = 'error'; message = 'report.html not found.' } -StatusCode 404
        return
    }

    $relativePath = $reportFile.Substring($RootPath.Length).TrimStart('\')
    $url = "http://localhost:$Port/$($relativePath.Replace('\', '/'))"
    Send-JsonResponse -Context $Context -Data @{ status = 'success'; url = $url }
}

function Invoke-RouteStaticFile {
    param([System.Net.HttpListenerContext]$Context, [string]$UrlPath)
    if (-not (Test-AuthToken $Context)) { Send-Unauthorized $Context; return }

    # Path traversal protection: ensure resolved path stays within Reports/
    $reportsFolder  = [IO.Path]::GetFullPath((Join-Path $RootPath 'Reports'))
    $decodedUrl     = [Uri]::UnescapeDataString($UrlPath)
    $requestedPath  = [IO.Path]::GetFullPath((Join-Path $RootPath $decodedUrl.TrimStart('/')))

    if (-not $requestedPath.StartsWith($reportsFolder, [StringComparison]::OrdinalIgnoreCase)) {
        Send-JsonResponse -Context $Context -Data @{ status = 'error'; message = 'Forbidden' } -StatusCode 403
        return
    }

    if (-not (Test-Path $requestedPath -PathType Leaf)) {
        Send-JsonResponse -Context $Context -Data @{ status = 'error'; message = 'Not found' } -StatusCode 404
        return
    }

    $ext = [IO.Path]::GetExtension($requestedPath).ToLower()
    $contentType = switch ($ext) {
        '.html' { 'text/html; charset=utf-8' }
        '.json' { 'application/json; charset=utf-8' }
        '.css'  { 'text/css; charset=utf-8' }
        '.js'   { 'application/javascript; charset=utf-8' }
        default { 'application/octet-stream' }
    }
    $bytes = [IO.File]::ReadAllBytes($requestedPath)
    $Context.Response.StatusCode      = 200
    $Context.Response.ContentType     = $contentType
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Context.Response.OutputStream.Close()
}

# ---------------------------------------------------------------------------
# Server startup
# ---------------------------------------------------------------------------
try {
    Add-Type -AssemblyName System.Web
} catch {
    Write-Warning 'System.Web assembly not found. Query string parsing may fail.'
}

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://localhost:$Port/")

try {
    $listener.Start()
}
catch {
    Write-Error "Failed to start HTTP listener on port $Port. Is another process already using it? Error: $_"
    exit 1
}

Write-Host ''
Write-Host '  Windows Security Audit Framework' -ForegroundColor Cyan
Write-Host "  Version $(& { if (Test-Path (Join-Path $PSScriptRoot 'Modules\Core.psm1')) { Import-Module (Join-Path $PSScriptRoot 'Modules\Core.psm1') -Force -ErrorAction SilentlyContinue; Get-FrameworkVersion } else { '5.5.0' } })" -ForegroundColor Gray
Write-Host ''
Write-Host "  [+] Server listening on http://localhost:$Port" -ForegroundColor Green
Write-Host '  [+] Session token active. Open the dashboard URL above.' -ForegroundColor Green
Write-Host '  [-] Press Ctrl+C to stop the server.' -ForegroundColor Gray
Write-Host ''

# ---------------------------------------------------------------------------
# Request dispatch loop
# ---------------------------------------------------------------------------
try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $urlPath = $request.Url.AbsolutePath
        $method  = $request.HttpMethod
        $remoteAddr = $context.Request.RemoteEndPoint.Address

        try {
            switch -Wildcard ($urlPath) {
                '/'                  { Invoke-RouteRoot       -Context $context; break }
                '/api/start'         { Invoke-RouteStart      -Context $context; break }
                '/api/stop'          { Invoke-RouteStop       -Context $context; break }
                '/api/status'        { Invoke-RouteStatus     -Context $context; break }
                '/api/open-report'   { Invoke-RouteOpenReport -Context $context; break }
                '/Reports/*'         { Invoke-RouteStaticFile -Context $context -UrlPath $urlPath; break }
                default {
                    Send-JsonResponse -Context $context -Data @{ status = 'error'; message = 'Not found' } -StatusCode 404
                }
            }
            Write-AccessLog -Method $method -Path $urlPath -StatusCode $context.Response.StatusCode -RemoteAddr $remoteAddr
        }
        catch {
            Write-Warning "Request handler error for $urlPath : $_"
            try { Send-JsonResponse -Context $context -Data @{ status = 'error'; message = 'Internal server error' } -StatusCode 500 } catch {}
            Write-AccessLog -Method $method -Path $urlPath -StatusCode 500 -RemoteAddr $remoteAddr
        }
    }
}
finally {
    $listener.Stop()
    $listener.Close()
    Write-Host '  [*] Server stopped.' -ForegroundColor Yellow
}