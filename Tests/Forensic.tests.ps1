# Forensic.tests.ps1
$CorePath = "$PSScriptRoot\..\Modules\Core.psm1"
$ForensicPath = "$PSScriptRoot\..\Modules\ForensicChecks.psm1"

Describe "Forensic Capabilities" {
    
    BeforeAll {
        Import-Module $CorePath -Force
        Import-Module $ForensicPath -Force
    }

    Context "HOSTS File Detection" {

        It "Should detect a suspicious HOSTS entry using mocking" {
            InModuleScope ForensicChecks {
                Mock -CommandName Get-Content -MockWith {
                    return @(
                        '127.0.0.1       localhost',
                        '127.0.0.1       malicious-site.com  # Suspicious'
                    )
                }

                Mock -CommandName Test-BrowserExtensions -MockWith {}
                Mock -CommandName Test-BackdoorPaths -MockWith {}
                Mock -CommandName Test-PUPs -MockWith {}
                Mock -CommandName Test-RecentExecutables -MockWith {}

                Clear-AuditFindings
                Invoke-ForensicChecks -Config @{ Detection = @{}; Thresholds = @{ RecentExecutablesAge = 7 } }
                
                $findings = Get-AuditFindings
                $hostFinding = $findings | Where-Object { $_.Id -eq "Forensic_HOSTS" }
                
                $hostFinding.Severity | Should Be 2 # Warn
            }
        }

        It "Should correctly identify a clean HOSTS file" {
            InModuleScope ForensicChecks {
                Mock -CommandName Get-Content -MockWith { return '# Clean' }

                Mock -CommandName Test-BrowserExtensions -MockWith {}
                Mock -CommandName Test-BackdoorPaths -MockWith {}
                Mock -CommandName Test-PUPs -MockWith {}
                Mock -CommandName Test-RecentExecutables -MockWith {}

                Clear-AuditFindings
                Invoke-ForensicChecks -Config @{ Detection = @{}; Thresholds = @{ RecentExecutablesAge = 7 } }

                $findings = Get-AuditFindings
                $hostFinding = $findings | Where-Object { $_.Id -eq "Forensic_HOSTS" }
                $hostFinding.Severity | Should Be 1 # Pass
            }
        }
    }
}