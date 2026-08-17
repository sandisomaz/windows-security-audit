# Modules.tests.ps1
$ModulesDir = Join-Path $PSScriptRoot "..\Modules"

Describe "All Audit Modules Integrity" {
    $modules = Get-ChildItem -Path $ModulesDir -Filter *.psm1

    It "Should find all 13 audit modules" {
        $modules.Count | Should Be 13
    }

    foreach ($module in $modules) {
        Context "Module: $($module.Name)" {
            It "Should exist on disk" {
                $module.FullName | Should Exist
            }

            It "Should parse without AST syntax errors" {
                $parseErrors = $null
                $tokens = $null
                [System.Management.Automation.Language.Parser]::ParseFile($module.FullName, [ref]$tokens, [ref]$parseErrors) | Out-Null
                $parseErrors.Count | Should Be 0
            }

            It "Should import into PowerShell session without throwing" {
                { Import-Module $module.FullName -Force -ErrorAction Stop } | Should Not Throw
            }
        }
    }
}
