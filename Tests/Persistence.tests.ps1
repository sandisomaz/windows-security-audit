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
            InModuleScope PersistenceHunting {
                # Create fake WMI objects to be returned by the mock
                $fakeFilter = [pscustomobject]@{
                    Name = 'EvilFilter';
                    Query = 'SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA "Win32_Process"';
                    __CLASS = '__EventFilter'
                }
                $fakeConsumer = [pscustomobject]@{
                    Name = 'EvilConsumer';
                    CommandLineTemplate = 'evil.exe';
                    __CLASS = 'CommandLineEventConsumer'
                }
                $fakeBinding = [pscustomobject]@{
                    Filter = '__EventFilter.Name="EvilFilter"';
                    Consumer = 'CommandLineEventConsumer.Name="EvilConsumer"'
                }

                # Define mocks within the module scope
                Mock -CommandName Get-WmiObject -MockWith {
                    param($Namespace, $Class)
                    if ($Class -eq '__EventFilter') { return $fakeFilter }
                    if ($Class -eq '__EventConsumer') { return $fakeConsumer }
                    if ($Class -eq '__FilterToConsumerBinding') { return $fakeBinding }
                    return $null
                }

                # Mock other persistence checks to isolate WMI
                Mock -CommandName Test-RegistryAutoruns -MockWith {}
                Mock -CommandName Test-ScheduledTasks -MockWith {}
                Mock -CommandName Test-ThirdPartyServices -MockWith {}
                Mock -CommandName Test-StartupFolder -MockWith {}

                Clear-AuditFindings
                Invoke-PersistenceHunting -Config @{} 

                $findings = Get-AuditFindings
                $wmiFinding = $findings | Where-Object { $_.Id -eq 'Persist_WMI' }

                # Assert that a critical finding was created
                $wmiFinding.Severity | Should Be 0 # FAIL
                $wmiFinding.Value | Should Match "1 subscription"
            }
        }
    }
}