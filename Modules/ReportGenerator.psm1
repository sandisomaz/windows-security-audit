#Requires -Version 5.1
<#
.SYNOPSIS
    Advanced Report Generator - v5.5 (Encoding & Print Fix)
.DESCRIPTION
    Generates a professional, Tailwind CSS-based security report.
    Includes fixes for UTF-8 encoding and PDF printing.
.NOTES
    Version : 5.5.0
#>

function New-AuditReport {
    param(
        [Parameter(Mandatory)]
        [string]$ReportPath,
        [Parameter(Mandatory)]
        [hashtable]$Config
    )
    
    Write-Host "Generating Modern HTML Report..." -ForegroundColor Cyan
    
    # 1. Gather Data
    $findings = Get-AuditFindings
    $sysInfo = Get-SystemInfo
    $riskData = Get-RiskScore
    
    # Calculate Counts
    $critCount = ($findings | Where-Object { $_.Severity -eq 0 }).Count
    $warnCount = ($findings | Where-Object { $_.Severity -eq 2 }).Count
    $infoCount = ($findings | Where-Object { $_.Severity -eq 3 }).Count
    $passCount = ($findings | Where-Object { $_.Severity -eq 1 }).Count
    $totalCount = $findings.Count
    
    # Calculate Security Score
    $securityScore = [math]::Round(100 - $riskData.RiskPercent)
    
    # Calculate SVG Circle Stroke
    $strokeOffset = 502.6 - (502.6 * $securityScore / 100)
    $scoreColor = if ($securityScore -ge 80) { "text-emerald-500" } elseif ($securityScore -ge 50) { "text-amber-500" } else { "text-red-500" }
    $scoreLabel = if ($securityScore -ge 80) { "Good Standing" } elseif ($securityScore -ge 50) { "Needs Improvement" } else { "Critical Risk" }
    $scoreBg = if ($securityScore -ge 80) { "bg-emerald-50 text-emerald-600 border-emerald-100" } elseif ($securityScore -ge 50) { "bg-amber-50 text-amber-600 border-amber-100" } else { "bg-red-50 text-red-600 border-red-100" }
    $scoreIcon = if ($securityScore -ge 80) { "check_circle" } elseif ($securityScore -ge 50) { "warning" } else { "gpp_bad" }

    # 2. Build HTML Content
    
    $htmlHead = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>System Security Report</title>
<script src="https://cdn.tailwindcss.com?plugins=forms,typography"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet"/>
<script>
    tailwind.config = {
        theme: {
            extend: {
                colors: {
                    primary: "#10b981", "primary-dark": "#059669", danger: "#ef4444", warning: "#f59e0b",
                    "bg-body": "#f3f4f6", "bg-surface": "#ffffff", "border-subtle": "#e5e7eb",
                    "text-main": "#111827", "text-secondary": "#6b7280"
                },
                fontFamily: { display: ["Inter", "sans-serif"], mono: ["JetBrains Mono", "monospace"] },
                boxShadow: { 'floating': '0 20px 25px -5px rgba(0, 0, 0, 0.05), 0 10px 10px -5px rgba(0, 0, 0, 0.02)' }
            }
        }
    };
</script>
<style>
    .score-ring-gradient { transition: stroke-dashoffset 1s ease-in-out; filter: drop-shadow(0px 2px 4px rgba(0,0,0, 0.1)); }
    .custom-scrollbar::-webkit-scrollbar { width: 6px; }
    .custom-scrollbar::-webkit-scrollbar-thumb { background-color: #d1d5db; border-radius: 3px; }
    
    /* PRINT STYLES */
    @media print {
        body { -webkit-print-color-adjust: exact; print-color-adjust: exact; background: white; }
        .no-print, button { display: none !important; }
        .shadow-floating, .shadow-sm { box-shadow: none !important; border: 1px solid #eee; }
        .h-screen { height: auto; }
        .overflow-y-auto { overflow: visible; }
    }
</style>
</head>
<body class="bg-bg-body h-screen flex items-center justify-center p-6 font-display text-text-main antialiased">
<div class="w-full max-w-[1400px] h-[92vh] bg-bg-surface shadow-floating rounded-2xl flex flex-col overflow-hidden ring-1 ring-black/5 relative">
    
    <!-- TOP BAR -->
    <div class="h-12 border-b border-border-subtle flex items-center justify-between px-6 shrink-0 bg-white z-20 no-print">
        <div class="flex items-center gap-3">
            <span class="w-3 h-3 rounded-full bg-red-400"></span><span class="w-3 h-3 rounded-full bg-amber-400"></span><span class="w-3 h-3 rounded-full bg-green-400"></span>
        </div>
        <div class="flex items-center gap-2 px-3 py-1 bg-gray-50 rounded-md border border-gray-100">
            <span class="material-symbols-outlined text-sm text-gray-400">lock</span>
            <span class="font-medium text-text-secondary text-xs">Security Audit Framework v5.5.0</span>
        </div>
        <div class="flex gap-4 text-gray-400"><span class="material-symbols-outlined text-[20px]">settings</span></div>
    </div>

    <!-- HEADER -->
    <header class="px-8 py-8 bg-white border-b border-border-subtle flex items-center justify-between shrink-0">
        <div class="flex items-center gap-6">
            <div class="w-16 h-16 rounded-2xl bg-gradient-to-br from-emerald-400 to-teal-500 flex items-center justify-center text-white shadow-lg shadow-emerald-100">
                <span class="material-symbols-outlined text-[32px]">shield_lock</span>
            </div>
            <div>
                <h1 class="text-3xl font-bold text-gray-900 tracking-tight">System Security Report</h1>
                <div class="flex items-center gap-4 mt-2 text-sm text-gray-500 font-medium">
                    <span class="flex items-center gap-1.5"><span class="material-symbols-outlined text-[18px]">calendar_today</span> $(Get-Date -Format "MMM dd, yyyy")</span>
                    <span class="text-gray-300">&bull;</span>
                    <span class="flex items-center gap-1.5"><span class="material-symbols-outlined text-[18px]">schedule</span> $(Get-Date -Format "HH:mm tt")</span>
                    <span class="text-gray-300">&bull;</span>
                    <span class="bg-emerald-50 text-emerald-600 px-2.5 py-0.5 rounded-md text-xs font-semibold ring-1 ring-emerald-100">Finalized</span>
                </div>
            </div>
        </div>
        <div class="flex items-center gap-3 no-print">
            <button onclick="window.print()" class="flex items-center gap-2 px-5 py-2.5 bg-white border border-gray-200 rounded-xl text-gray-600 hover:bg-gray-50 transition-all text-sm font-semibold shadow-sm">
                <span class="material-symbols-outlined text-[20px]">print</span> Print
            </button>
        </div>
    </header>

    <!-- MAIN CONTENT -->
    <main class="flex-1 overflow-y-auto bg-gray-50/50 p-8 custom-scrollbar">
        <div class="grid grid-cols-12 gap-6 mb-8">
            
            <!-- SCORE CARD -->
            <div class="col-span-12 lg:col-span-3 bg-white rounded-2xl border border-gray-100 p-6 flex flex-col items-center justify-center shadow-sm relative">
                <h3 class="text-xs font-bold text-gray-400 uppercase tracking-wider mb-6 self-start">Security Score</h3>
                <div class="relative w-48 h-48 flex items-center justify-center mb-4">
                    <svg class="w-full h-full transform -rotate-90">
                        <circle class="text-gray-100" cx="96" cy="96" fill="transparent" r="80" stroke="currentColor" stroke-width="12"></circle>
                        <circle class="$scoreColor score-ring-gradient" cx="96" cy="96" fill="transparent" r="80" stroke="currentColor" stroke-dasharray="502.6" stroke-dashoffset="$strokeOffset" stroke-linecap="round" stroke-width="12"></circle>
                    </svg>
                    <div class="absolute inset-0 flex flex-col items-center justify-center">
                        <span class="text-5xl font-bold text-gray-900 tracking-tighter">$securityScore</span>
                        <span class="text-sm text-gray-400 font-medium mt-1">/ 100</span>
                    </div>
                </div>
                <div class="inline-flex items-center gap-2 px-4 py-1.5 rounded-full $scoreBg text-xs font-bold border">
                    <span class="material-symbols-outlined text-[16px] filled">$scoreIcon</span> $scoreLabel
                </div>
            </div>

            <!-- STATS CARDS -->
            <div class="col-span-12 lg:col-span-5 grid grid-cols-2 gap-4">
                <!-- Critical -->
                <div class="bg-white p-6 rounded-2xl border border-gray-100 shadow-sm flex flex-col justify-between hover:border-red-100 transition-all group relative overflow-hidden">
                    <div class="absolute top-0 right-0 w-24 h-24 bg-red-50 rounded-bl-full -mr-10 -mt-10 opacity-50"></div>
                    <div class="flex justify-between items-start z-10">
                        <div class="w-10 h-10 rounded-lg bg-red-50 text-red-500 flex items-center justify-center border border-red-100"><span class="material-symbols-outlined text-xl">gpp_bad</span></div>
                        <span class="text-4xl font-bold text-gray-900">$critCount</span>
                    </div>
                    <div class="mt-6 z-10"><p class="text-base font-bold text-gray-800">Critical Threats</p></div>
                </div>
                <!-- Warnings -->
                <div class="bg-white p-6 rounded-2xl border border-gray-100 shadow-sm flex flex-col justify-between hover:border-amber-100 transition-all group relative overflow-hidden">
                    <div class="absolute top-0 right-0 w-24 h-24 bg-amber-50 rounded-bl-full -mr-10 -mt-10 opacity-50"></div>
                    <div class="flex justify-between items-start z-10">
                        <div class="w-10 h-10 rounded-lg bg-amber-50 text-amber-500 flex items-center justify-center border border-amber-100"><span class="material-symbols-outlined text-xl">warning</span></div>
                        <span class="text-4xl font-bold text-gray-900">$warnCount</span>
                    </div>
                    <div class="mt-6 z-10"><p class="text-base font-bold text-gray-800">Warnings</p></div>
                </div>
                <!-- Info -->
                <div class="bg-white p-6 rounded-2xl border border-gray-100 shadow-sm flex flex-col justify-between hover:border-blue-100 transition-all group relative overflow-hidden">
                    <div class="absolute top-0 right-0 w-24 h-24 bg-blue-50 rounded-bl-full -mr-10 -mt-10 opacity-50"></div>
                    <div class="flex justify-between items-start z-10">
                        <div class="w-10 h-10 rounded-lg bg-blue-50 text-blue-500 flex items-center justify-center border border-blue-100"><span class="material-symbols-outlined text-xl">info</span></div>
                        <span class="text-4xl font-bold text-gray-900">$infoCount</span>
                    </div>
                    <div class="mt-6 z-10"><p class="text-base font-bold text-gray-800">Info / Notices</p></div>
                </div>
                <!-- Passed -->
                <div class="bg-white p-6 rounded-2xl border border-gray-100 shadow-sm flex flex-col justify-between hover:border-emerald-100 transition-all group relative overflow-hidden">
                    <div class="absolute top-0 right-0 w-24 h-24 bg-emerald-50 rounded-bl-full -mr-10 -mt-10 opacity-50"></div>
                    <div class="flex justify-between items-start z-10">
                        <div class="w-10 h-10 rounded-lg bg-gray-50 text-emerald-500 flex items-center justify-center border border-gray-100"><span class="material-symbols-outlined text-xl">checklist</span></div>
                        <span class="text-4xl font-bold text-gray-900">$passCount</span>
                    </div>
                    <div class="mt-6 z-10"><p class="text-base font-bold text-gray-800">Checks Passed</p></div>
                </div>
            </div>

            <!-- SYSTEM INFO -->
            <div class="col-span-12 lg:col-span-4 bg-white rounded-2xl border border-gray-100 p-6 shadow-sm">
                <div class="flex items-center justify-between mb-8">
                    <h3 class="text-xs font-bold text-gray-400 uppercase tracking-wider">Target System</h3>
                    <span class="px-2.5 py-1 bg-emerald-50 text-emerald-600 rounded-md text-[10px] tracking-wide font-bold border border-emerald-100">ONLINE</span>
                </div>
                <div class="space-y-6">
                    <div class="grid grid-cols-2 gap-x-4 gap-y-6">
                        <div>
                            <p class="text-[10px] text-gray-400 uppercase font-bold tracking-wider mb-2">Hostname</p>
                            <div class="flex items-center gap-2.5"><span class="material-symbols-outlined text-[20px] text-gray-300">desktop_windows</span><span class="text-sm font-bold text-gray-800 font-mono">$($sysInfo.ComputerName)</span></div>
                        </div>
                        <div>
                            <p class="text-[10px] text-gray-400 uppercase font-bold tracking-wider mb-2">OS</p>
                            <div class="flex items-center gap-2.5"><span class="material-symbols-outlined text-[20px] text-gray-300">grid_view</span><span class="text-sm font-bold text-gray-800 text-xs">$($sysInfo.OSName)</span></div>
                        </div>
                        <div>
                            <p class="text-[10px] text-gray-400 uppercase font-bold tracking-wider mb-2">Memory</p>
                            <div class="flex items-center gap-2.5"><span class="material-symbols-outlined text-[20px] text-gray-300">memory</span><span class="text-sm font-bold text-gray-800 font-mono">$($sysInfo.TotalRAM_GB) GB</span></div>
                        </div>
                        <div>
                            <p class="text-[10px] text-gray-400 uppercase font-bold tracking-wider mb-2">User</p>
                            <div class="flex items-center gap-2.5"><span class="material-symbols-outlined text-[20px] text-gray-300">person</span><span class="text-sm font-bold text-gray-800">$env:USERNAME</span></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- FINDINGS TABLE -->
        <div class="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden flex flex-col">
            <div class="px-8 py-5 border-b border-gray-100 flex items-center justify-between bg-white">
                <div class="flex items-center gap-4">
                    <h3 class="text-lg font-bold text-gray-900">Detailed Findings</h3>
                    <span class="px-3 py-1 rounded-full bg-gray-100 text-xs font-semibold text-gray-600 border border-gray-200">$totalCount Issues Found</span>
                </div>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="bg-gray-50/50 border-b border-gray-100 text-[11px] uppercase tracking-wider text-gray-400 font-bold">
                            <th class="px-8 py-5 w-32">Severity</th>
                            <th class="px-8 py-5">Finding</th>
                            <th class="px-8 py-5">Category / ID</th>
                            <th class="px-8 py-5 w-48 text-right">Action</th>
                        </tr>
                    </thead>
                    <tbody class="text-sm divide-y divide-gray-50">
"@

    # --- GENERATE ROWS ---
    $rows = ""
    
    foreach ($f in $findings) {
        # Determine Severity Styles
        if ($f.Severity -eq 0) { # FAIL (Critical)
            $badge = "<span class='inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-red-50 text-red-600 border border-red-100 text-xs font-bold'><span class='material-symbols-outlined text-[14px] filled'>error</span> Critical</span>"
        } elseif ($f.Severity -eq 2) { # WARN
            $badge = "<span class='inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-amber-50 text-amber-600 border border-amber-100 text-xs font-bold'><span class='material-symbols-outlined text-[14px] filled'>warning</span> Warning</span>"
        } elseif ($f.Severity -eq 1) { # PASS
            $badge = "<span class='inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-50 text-emerald-600 border border-emerald-100 text-xs font-bold'><span class='material-symbols-outlined text-[14px] filled'>check_circle</span> Pass</span>"
        } else { # INFO
            $badge = "<span class='inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-blue-50 text-blue-600 border border-blue-100 text-xs font-bold'><span class='material-symbols-outlined text-[14px] filled'>info</span> Info</span>"
        }

        # Safe String with HTML Encoding
        $title = [System.Net.WebUtility]::HtmlEncode([string]$f.Title)
        $value = [System.Net.WebUtility]::HtmlEncode([string]$f.Value)
        $cat = [System.Net.WebUtility]::HtmlEncode([string]$f.Category)
        
        # Action Button (Copy Fix)
        $actionBtn = ""
        if ($f.Notes -match "Run:\s*(.+?)(\r|\n|$)") {
            $cmd = $matches[1].Trim()
            $escapedCmd = $cmd -replace '"', '&quot;'
            $actionBtn = "<button class='copy-fix-btn inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-gray-600 hover:text-gray-900 hover:bg-gray-100 bg-transparent rounded-lg border border-transparent transition-all' data-cmd=`"$escapedCmd`"><span class='material-symbols-outlined text-[16px]'>content_copy</span> Copy Fix</button>"
        }

        $rows += @"
<tr class="group hover:bg-gray-50/50 transition-colors">
    <td class="px-8 py-5 align-top">$badge</td>
    <td class="px-8 py-5 align-top">
        <p class="text-sm font-bold text-gray-900">$title</p>
        <p class="text-xs text-gray-500 mt-1.5 leading-relaxed">$value</p>
    </td>
    <td class="px-8 py-5 align-top">
        <code class="px-2.5 py-1.5 bg-gray-100 rounded-md text-[11px] font-mono text-gray-600 border border-gray-200">$cat</code>
    </td>
    <td class="px-8 py-5 align-top text-right">$actionBtn</td>
</tr>
"@
    }

    $htmlFoot = @"
                    </tbody>
                </table>
            </div>
        </div>
    </main>
</div>
<script>
document.addEventListener('click', function(e) {
    const btn = e.target.closest('.copy-fix-btn');
    if (!btn) return;
    const cmd = btn.getAttribute('data-cmd');
    if (cmd && navigator.clipboard) {
        navigator.clipboard.writeText(cmd).then(() => {
            const orig = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(() => { btn.textContent = orig; }, 1500);
        });
    }
});
</script>
</body>
</html>
"@

    # 3. Save Report - FORCE UTF8 ENCODING
    $finalHTML = $htmlHead + $rows + $htmlFoot
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFolder = Join-Path $ReportPath "WinSecAudit_$timestamp"
    New-Item -Path $reportFolder -ItemType Directory -Force | Out-Null
    
    $finalPath = Join-Path $reportFolder "report.html"
    
    # Use .NET method to ensure BOM is written correctly for browsers to detect
    [System.IO.File]::WriteAllText($finalPath, $finalHTML, [System.Text.Encoding]::UTF8)
    
    Write-Host "Report Saved: $finalPath" -ForegroundColor Green
    
    # Generate JSON
    $jsonData = @{ System=$sysInfo; Score=$riskData; Findings=$findings } | ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText((Join-Path $reportFolder "report.json"), $jsonData, [System.Text.Encoding]::UTF8)
    
    return $reportFolder
}

Export-ModuleMember -Function New-AuditReport