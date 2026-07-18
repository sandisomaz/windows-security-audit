# Forensic.tests.ps1
$CorePath = "$PSScriptRoot\..\Modules\Core.psm1"
$ForensicPath = "$PSScriptRoot\..\Modules\ForensicChecks.psm1"

Describe "Forensic Capabilities" {
    
    BeforeAll {
        # Global imports moved back to internal for Pester 3 compatibility
    }

    Context "HOSTS File Detection" {
        $HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $BackupPath = "$env:SystemRoot\System32\drivers\etc\hosts.bak"

        It "Should detect a suspicious HOSTS entry using mocking" {
            Import-Module $CorePath -Force
            Import-Module $ForensicPath -Force

            # Mock Get-Content specifically for the ForensicChecks module
            Mock -ModuleName ForensicChecks -CommandName Get-Content -MockWith {
                return @(
                    '127.0.0.1       localhost',
                    '127.0.0.1       malicious-site.com  # Suspicious'
                )
            }

            # Mock other heavy functions
            Mock -ModuleName ForensicChecks -CommandName Test-BrowserExtensions -MockWith {}
            Mock -ModuleName ForensicChecks -CommandName Test-BackdoorPaths -MockWith {}
            Mock -ModuleName ForensicChecks -CommandName Test-PUPs -MockWith {}
            Mock -ModuleName ForensicChecks -CommandName Test-RecentExecutables -MockWith {}

            Clear-AuditFindings
            Invoke-ForensicChecks -Config @{ Detection = @{}; Thresholds = @{ RecentExecutablesAge = 7 } }
            
            $findings = Get-AuditFindings
            $hostFinding = $findings | Where-Object { $_.Id -eq "Forensic_HOSTS" }
            
            $hostFinding.Severity | Should Be 2 # Warn
        }

        It "Should correctly identify a clean HOSTS file" {
            Import-Module $CorePath -Force
            Import-Module $ForensicPath -Force

            Mock -ModuleName ForensicChecks -CommandName Get-Content -MockWith { return '# Clean' }

            # Mock other heavy functions
            Mock -ModuleName ForensicChecks -CommandName Test-BrowserExtensions -MockWith {}
            Mock -ModuleName ForensicChecks -CommandName Test-BackdoorPaths -MockWith {}
            Mock -ModuleName ForensicChecks -CommandName Test-PUPs -MockWith {}
            Mock -ModuleName ForensicChecks -CommandName Test-RecentExecutables -MockWith {}

            Clear-AuditFindings
            Invoke-ForensicChecks -Config @{ Detection = @{}; Thresholds = @{ RecentExecutablesAge = 7 } }

            $findings = Get-AuditFindings
            $hostFinding = $findings | Where-Object { $_.Id -eq "Forensic_HOSTS" }
            $hostFinding.Severity | Should Be 1 # Pass
        }
    }
}