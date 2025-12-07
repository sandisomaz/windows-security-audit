# Forensic.tests.ps1
$CorePath = "$PSScriptRoot\..\Modules\Core.psm1"
$ForensicPath = "$PSScriptRoot\..\Modules\ForensicChecks.psm1"

Describe "Forensic Capabilities" {
    
    BeforeAll {
        # Module import will be handled inside each 'It' block to ensure mock scope
        # Mock Config
        $Global:Config = @{ Detection = @{ PUPKeywords = @('TestMalware') } }
    }

    Context "HOSTS File Detection" {
        $HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $BackupPath = "$env:SystemRoot\System32\drivers\etc\hosts.bak"

        It "Should detect a suspicious HOSTS entry using mocking" {
            # Mock the base Get-Content cmdlet to return a fake malicious file content
            Mock -CommandName Get-Content -MockWith {
                return @(
                    '# Default content',
                    '127.0.0.1       localhost',
                    '127.0.0.1       malicious-site.com  #<-- malware entry'
                )
            }
            
            # Import the module *after* the mock is defined to ensure it's used
            Import-Module $CorePath -Force
            Import-Module $ForensicPath -Force
            Clear-AuditFindings
            Invoke-ForensicChecks -Config $Global:Config
            
            $findings = Get-AuditFindings
            $hostFinding = $findings | Where-Object { $_.Id -eq "Forensic_HOSTS" }
            
            $hostFinding.Severity | Should Be 2 # Warn
            $hostFinding.Value | Should Match "1 custom entry"
        }

        It "Should correctly identify a clean HOSTS file" {
            # Mock Get-Content to return a clean file
            Mock -CommandName Get-Content -MockWith { return '# Clean file' }

            # Import the module *after* the mock is defined
            Import-Module $CorePath -Force
            Import-Module $ForensicPath -Force
            Clear-AuditFindings
            Invoke-ForensicChecks -Config $Global:Config

            $findings = Get-AuditFindings
            $hostFinding = $findings | Where-Object { $_.Id -eq "Forensic_HOSTS" }
            $hostFinding.Severity | Should Be 1 # Pass
        }
    }
}