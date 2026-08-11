#Requires -Version 5.1
<#
.SYNOPSIS
    Browser security audit module.
.DESCRIPTION
    Audits installed browsers for suspicious extensions and insecure configurations.
    Currently supports Google Chrome and Mozilla Firefox.
.NOTES
    Version : 5.5.0
    Requires: PowerShell 5.1+
#>

using module .\Core.psm1

function Invoke-BrowserAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )

    Write-AuditHeader 'Browser Security Audit'

    Invoke-ChromeExtensionAudit -Config $Config
    Invoke-FirefoxExtensionAudit -Config $Config
}

function Invoke-ChromeExtensionAudit {
    param([hashtable]$Config)

    Write-AuditResult 'Chrome Extensions' 'Checking...' -Status Info

    $basePath = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    if (-not (Test-Path $basePath)) {
        Add-AuditFinding -Id 'BROWSER-CHROME-01' -Title 'Google Chrome' -Value 'Not installed' `
            -Severity 1 -Category 'Browser' -Notes 'Google Chrome does not appear to be installed.'
        return
    }

    $profilePaths  = @(Join-Path $basePath 'Default')
    $profilePaths += Get-ChildItem -Path $basePath -Directory -Filter 'Profile*' -ErrorAction SilentlyContinue |
                         Select-Object -ExpandProperty FullName

    $allExtensions = @()
    foreach ($profilePath in $profilePaths) {
        $extensionsPath = Join-Path $profilePath 'Extensions'
        if (Test-Path $extensionsPath) {
            $allExtensions += Get-ChildItem -Path $extensionsPath -Directory -ErrorAction SilentlyContinue
        }
    }

    if ($allExtensions.Count -eq 0) {
        Add-AuditFinding -Id 'BROWSER-CHROME-02' -Title 'Chrome Extensions' -Value 'No extensions found' `
            -Severity 1 -Category 'Browser'
        return
    }

    $notes = Format-FixRecommendation `
        -Problem "$($allExtensions.Count) Chrome extension(s) found. Review for malicious or unnecessary extensions." `
        -ManualSteps @(
            "Open Chrome and navigate to 'chrome://extensions'.",
            "Review each extension. Ask: 'Do I know what this does and do I use it?'",
            'Remove any extensions you do not recognise.',
            "Be wary of extensions requesting 'Read and change all your data on the websites you visit'."
        ) `
        -MoreInfo 'https://support.google.com/chrome_webstore/answer/2664769'

    Add-AuditFinding -Id 'BROWSER-CHROME-02' -Title 'Chrome Extensions Review' `
        -Value "$($allExtensions.Count) extension(s) found" -Severity 3 -Category 'Browser' -Notes $notes
}

function Invoke-FirefoxExtensionAudit {
    param([hashtable]$Config)

    Write-AuditResult 'Firefox Extensions' 'Checking...' -Status Info

    $basePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (-not (Test-Path $basePath)) {
        Add-AuditFinding -Id 'BROWSER-FIREFOX-01' -Title 'Mozilla Firefox' -Value 'Not installed' `
            -Severity 1 -Category 'Browser' -Notes 'Mozilla Firefox does not appear to be installed.'
        return
    }

    $profileDir = Get-ChildItem -Path $basePath -Directory -Filter '*.default-release' -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $profileDir) {
        Add-AuditFinding -Id 'BROWSER-FIREFOX-01' -Title 'Firefox Profile' -Value 'Default profile not found' `
            -Severity 2 -Category 'Browser' -Notes 'Could not locate the default Firefox profile directory.'
        return
    }

    $extensionsFile = Join-Path $profileDir.FullName 'extensions.json'
    if (-not (Test-Path $extensionsFile)) {
        Add-AuditFinding -Id 'BROWSER-FIREFOX-02' -Title 'Firefox Extensions' -Value 'No extensions found' `
            -Severity 1 -Category 'Browser'
        return
    }

    try {
        $json = Get-Content -Path $extensionsFile -Raw | ConvertFrom-Json
        $installedExtensions = $json.addons | Where-Object { $_.type -eq 'extension' }
    } catch {
        Write-AuditLog "Failed to parse Firefox extensions.json: $_" -Level Warning
        return
    }

    if (-not $installedExtensions -or $installedExtensions.Count -eq 0) {
        Add-AuditFinding -Id 'BROWSER-FIREFOX-02' -Title 'Firefox Extensions' -Value 'No extensions found' `
            -Severity 1 -Category 'Browser'
        return
    }

    $notes = Format-FixRecommendation `
        -Problem "$($installedExtensions.Count) Firefox extension(s) found. Review for malicious or unnecessary add-ons." `
        -ManualSteps @(
            "Open Firefox and navigate to 'about:addons'.",
            "Click on the 'Extensions' tab.",
            "Review each extension. Disable or remove any you don't recognise.",
            'Pay attention to the permissions each extension requests.'
        ) `
        -MoreInfo 'https://support.mozilla.org/en-US/kb/disable-or-remove-add-ons'

    Add-AuditFinding -Id 'BROWSER-FIREFOX-02' -Title 'Firefox Extensions Review' `
        -Value "$($installedExtensions.Count) extension(s) found" -Severity 3 -Category 'Browser' -Notes $notes
}

Export-ModuleMember -Function Invoke-BrowserAudit