<#
.SYNOPSIS
    Browser Security Audit Module
.DESCRIPTION
    Audits installed browsers for security vulnerabilities, suspicious extensions,
    and insecure configurations.
.NOTES
    Author: Sandiso Mazibuko
    Version: 1.0
    Requires: PowerShell 5.1+, Administrator privileges
#>

using module .\Core.psm1

function Invoke-BrowserAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )

    Write-AuditHeader "Browser Security Audit"

    # Run checks for each supported browser
    Invoke-ChromeExtensionAudit -Config $Config
    Invoke-FirefoxExtensionAudit -Config $Config
    # Add more browser checks here

    Write-AuditResult "Browser Audit" "Completed" -Status Info
}

function Invoke-ChromeExtensionAudit {
    param([hashtable]$Config)

    Write-AuditResult "Chrome Extensions" "Checking..." -Status Info

    $basePath = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    if (-not (Test-Path $basePath)) {
        Add-AuditFinding -Id "BROWSER-CHROME-01" -Title "Google Chrome Installation" -Value "Not Found" -Severity 3 -Category "Browser" -Notes "Google Chrome does not appear to be installed."
        return
    }

    # Find all profile paths (Default, Profile 1, Profile 2, etc.)
    $profilePaths = Get-ChildItem -Path $basePath -Directory -Filter "Profile*" | Select-Object -ExpandProperty FullName
    $profilePaths += Join-Path $basePath "Default"

    $allExtensions = @()

    foreach ($profilePath in $profilePaths) {
        $extensionsPath = Join-Path $profilePath "Extensions"
        if (Test-Path $extensionsPath) {
            $extensions = Get-ChildItem -Path $extensionsPath -Directory
            $allExtensions += $extensions
        }
    }

    if ($allExtensions.Count -eq 0) {
        Add-AuditFinding -Id "BROWSER-CHROME-02" -Title "Chrome Extensions" -Value "No extensions found" -Severity 1 -Category "Browser"
        return
    }

    $extensionNames = $allExtensions | ForEach-Object { $_.Name }
    $value = "$($allExtensions.Count) extensions found: $($extensionNames -join ', ')"

    $notes = Format-FixRecommendation `
        -Problem "A review of installed browser extensions is recommended. Malicious extensions can steal passwords, inject ads, and monitor your activity." `
        -ManualSteps @(
            "Open Chrome and navigate to 'chrome://extensions'.",
            "Review each extension. Ask yourself: 'Do I know what this is and do I use it?'.",
            "If the answer is no, remove it.",
            "Be wary of extensions that require 'Read and change all your data on the websites you visit' permissions."
        ) `
        -MoreInfo "https://support.google.com/chrome_webstore/answer/2664769"

    Add-AuditFinding -Id "BROWSER-CHROME-02" -Title "Chrome Extensions Review" -Value "$($allExtensions.Count) extensions found" -Severity 3 -Category "Browser" -Notes $notes
}

function Invoke-FirefoxExtensionAudit {
    param([hashtable]$Config)

    Write-AuditResult "Firefox Extensions" "Checking..." -Status Info

    $basePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (-not (Test-Path $basePath)) {
        Add-AuditFinding -Id "BROWSER-FIREFOX-01" -Title "Mozilla Firefox Installation" -Value "Not Found" -Severity 3 -Category "Browser" -Notes "Mozilla Firefox does not appear to be installed."
        return
    }

    $profileDir = Get-ChildItem -Path $basePath -Directory -Filter "*.default-release" | Select-Object -First 1
    if (-not $profileDir) {
        Add-AuditFinding -Id "BROWSER-FIREFOX-01" -Title "Mozilla Firefox Profile" -Value "Not Found" -Severity 2 -Category "Browser" -Notes "Could not locate the default Firefox profile."
        return
    }

    $extensionsFile = Join-Path $profileDir.FullName "extensions.json"
    if (-not (Test-Path $extensionsFile)) {
        Add-AuditFinding -Id "BROWSER-FIREFOX-02" -Title "Firefox Extensions" -Value "No extensions found" -Severity 1 -Category "Browser"
        return
    }

    $json = Get-Content -Path $extensionsFile | ConvertFrom-Json
    $installedExtensions = $json.addons | Where-Object { $_.type -eq "extension" }

    if ($installedExtensions.Count -eq 0) {
        Add-AuditFinding -Id "BROWSER-FIREFOX-02" -Title "Firefox Extensions" -Value "No extensions found" -Severity 1 -Category "Browser"
        return
    }

    $extensionNames = $installedExtensions | ForEach-Object { $_.defaultLocale.name }
    $value = "$($installedExtensions.Count) extensions found: $($extensionNames -join ', ')"

    $notes = Format-FixRecommendation `
        -Problem "A review of installed browser extensions is recommended. Malicious extensions can steal passwords, inject ads, and monitor your activity." `
        -ManualSteps @(
            "Open Firefox and navigate to 'about:addons'.",
            "Click on the 'Extensions' tab.",
            "Review each extension. If you don't recognize it, disable or remove it.",
            "Pay attention to the permissions each extension requests."
        ) `
        -MoreInfo "https://support.mozilla.org/en-US/kb/disable-or-remove-add-ons"

    Add-AuditFinding -Id "BROWSER-FIREFOX-02" -Title "Firefox Extensions Review" -Value "$($installedExtensions.Count) extensions found" -Severity 3 -Category "Browser" -Notes $notes
}

Export-ModuleMember -Function Invoke-BrowserAudit