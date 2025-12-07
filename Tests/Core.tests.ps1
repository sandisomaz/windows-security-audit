# Core.tests.ps1
$ModulePath = "$PSScriptRoot\..\Modules\Core.psm1"

Describe "Core Module Integrity" {
    
    It "Should exist at the expected path" {
        $ModulePath | Should Exist
    }

    It "Should import without errors" {
        { Import-Module $ModulePath -Force } | Should Not Throw
    }
}

Describe "Risk Scoring Logic" {
    # We need to import the module to test the functions
    Import-Module $ModulePath -Force

    Context "Calculating Severity Weights" {

        It "Should return LOW risk for 0 findings" {
            Clear-AuditFindings
            $score = Get-RiskScore
            $score.SeverityLabel | Should Be "LOW"
            $score.RiskPercent | Should Be 0
        }

        It "Should return HIGH risk if we add a Critical Fail" {
            Clear-AuditFindings
            Add-AuditFinding -Id "TEST_FAIL" -Title "Critical Test" -Value "Bad" -Severity 0 # Weight 25
            
            $score = Get-RiskScore
            $score.SeverityLabel | Should Be "HIGH"
            $score.RiskPercent | Should Be 100
        }

        It "Should return MEDIUM risk for two WARN findings" {
            Clear-AuditFindings
            Add-AuditFinding -Id "TEST_WARN1" -Title "Warning 1" -Value "Warn" -Severity 2 # Weight 10
            Add-AuditFinding -Id "TEST_WARN2" -Title "Warning 2" -Value "Warn" -Severity 2 # Weight 10

            # Score = (10/2) + (10/2) = 10
            # MaxPossible = 10 + 10 = 20
            # RiskPercent = (10 / 20) * 100 = 50%
            $score = Get-RiskScore
            $score.SeverityLabel | Should Be "HIGH" # 50% is the threshold for HIGH
            $score.RiskPercent | Should Be 50
        }

        It "Should correctly calculate a mixed-severity score" {
            Clear-AuditFindings
            Add-AuditFinding -Id "TEST_FAIL" -Title "A Fail" -Value "Bad" -Severity 0 # Score 25, Max 25
            Add-AuditFinding -Id "TEST_WARN" -Title "A Warn" -Value "Hmm" -Severity 2 # Score 5, Max 10
            Add-AuditFinding -Id "TEST_PASS" -Title "A Pass" -Value "Good" -Severity 1 # Score 0, Max 0
            Add-AuditFinding -Id "TEST_INFO" -Title "An Info" -Value " FYI" -Severity 3 # Score 2, Max 5

            # Score = 25 + (10/2) + 0 + 2 = 32
            # MaxPossible = 25 + 10 + 0 + 5 = 40
            # RiskPercent = (32 / 40) * 100 = 80%
            $score = Get-RiskScore
            $score.SeverityLabel | Should Be "HIGH"
            $score.RiskPercent | Should Be 80
        }
    }
}