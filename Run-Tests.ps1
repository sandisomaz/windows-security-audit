<#
.SYNOPSIS
    Test Suite Runner for the Windows Security Audit Framework
.DESCRIPTION
    This script automatically installs the Pester testing framework if needed
    and then runs all Pester tests located in the 'Tests' sub-directory.
.NOTES
    Run this script from the project root to validate all modules.
#>

$PesterModule = Get-Module -Name Pester -ListAvailable

if (-not $PesterModule) {
    Write-Host "Pester test framework not found." -ForegroundColor Yellow
    Write-Host "Attempting to install Pester from the PowerShell Gallery..." -ForegroundColor Cyan
    
    try {
        Install-Module -Name Pester -Force -SkipPublisherCheck -Scope CurrentUser -ErrorAction Stop
        Write-Host "Pester installed successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to install Pester. Please run 'Install-Module Pester -Force -Scope CurrentUser' in an Administrator PowerShell session and try again."
        exit 1
    }
}

Write-Host "Starting Pester test suite..." -ForegroundColor Cyan
Write-Host "================================================================="
Write-Host ""

# Get the installed Pester version to handle syntax differences
$pester = Get-Module -Name Pester -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1

if ($pester.Version.Major -ge 5) {
    # Pester v5+ uses a configuration object
    Write-Host "Detected Pester v5+. Using modern configuration." -ForegroundColor Gray
    $pesterConfig = [PesterConfiguration]@{
        Run = @{ Path = "$PSScriptRoot\Tests" }
        Output = @{ Verbosity = 'Detailed' }
    }
    # Execute all tests in the 'Tests' folder
    Invoke-Pester -Configuration $pesterConfig
}
else {
    # Pester v4 and older use direct parameters
    Write-Host "Detected Pester v4 or older. Using legacy syntax." -ForegroundColor Gray
    Invoke-Pester -Path "$PSScriptRoot\Tests"
}