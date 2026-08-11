#Requires -Version 5.1
<#
.SYNOPSIS
    Malware persistence mechanism detection module
.DESCRIPTION
    Hunts for:
    - WMI Event Subscriptions (fileless persistence)
    - Registry Run keys (autoruns)
    - Scheduled Tasks
    - Services (non-Microsoft)
    - Startup folder items
.NOTES
    Version : 5.5.0
#>

using module .\Core.psm1

function Invoke-PersistenceHunting {
    <#
    .SYNOPSIS
        Hunts for malware persistence mechanisms
    .PARAMETER Config
        Configuration object from Config.psd1
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )
    
    Write-AuditHeader "Persistence Mechanism Hunting"
    
    # === WMI Persistence ===
    Test-WMIPersistence
    
    # === Registry Autoruns ===
    Test-RegistryAutoruns
    
    # === Scheduled Tasks ===
    Test-ScheduledTasks -Config $Config
    
    # === Non-Microsoft Services ===
    Test-ThirdPartyServices
    
    # === Startup Folder ===
    Test-StartupFolder
}

function Test-WMIPersistence {
    Write-Host "Scanning for WMI Event Subscriptions (advanced persistence)..." -ForegroundColor Cyan
    
    try {
        # Get Event Filters
        $filters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction Stop |
            Where-Object { $_.Name -notmatch "SecurityHealthService|OneDrive|SCM Event Log" }
        
        # Get Event Consumers
        $consumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction Stop |
            Where-Object { $_.Name -notmatch "SecurityHealthService|OneDrive|SCM Event Log" }
        
        # Get Bindings
        $bindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction Stop
        
        $suspiciousWMI = @()
        
        foreach ($binding in $bindings) {
            # Robust extraction of filter and consumer names from WMI binding string
            # Format usually: \\.\root\subscription:__EventFilter.Name="Name"
            $filterName = if ($binding.Filter -match 'Name="([^"]+)"') { $Matches[1] } else { ($binding.Filter -split '"')[1] }
            $consumerName = if ($binding.Consumer -match 'Name="([^"]+)"') { $Matches[1] } else { ($binding.Consumer -split '"')[1] }
            
            $filter = $filters | Where-Object { $_.Name -eq $filterName }
            $consumer = $consumers | Where-Object { $_.Name -eq $consumerName }
            
            if ($filter -and $consumer) {
                $suspiciousWMI += [PSCustomObject]@{
                    FilterName = $filter.Name
                    Query = $filter.Query
                    ConsumerName = $consumer.Name
                    ConsumerType = $consumer.__CLASS
                    Action = if ($consumer.CommandLineTemplate) { $consumer.CommandLineTemplate } else { "N/A" }
                }
            }
        }
        
        if ($suspiciousWMI.Count -gt 0) {
            Write-AuditResult "WMI Persistence" "Found $($suspiciousWMI.Count) suspicious subscription(s)" -Status Fail
            
            foreach ($wmi in $suspiciousWMI) {
                Write-Host "  - Filter: $($wmi.FilterName)" -ForegroundColor Red
                Write-Host "    Consumer: $($wmi.ConsumerName) ($($wmi.ConsumerType))" -ForegroundColor Red
                Write-Host "    Action: $($wmi.Action)" -ForegroundColor Red
            }
            
            $wmiJson = $suspiciousWMI | ConvertTo-Json -Compress
            
            $manualSteps = @(
                "This requires advanced tools to remove safely.",
                "Use Sysinternals Autoruns: Launch Autoruns64.exe as Admin and go to the 'WMI' tab.",
                "Uncheck the suspicious entries found by this audit, which are: $($suspiciousWMI.FilterName -join ', ').",
                "Alternatively, use PowerShell to manually remove the Filter, Consumer, and Binding (ADVANCED USERS ONLY).",
                "Example removal commands:",
                "Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -Filter ""Filter = '__EventFilter.Name=''FILTER_NAME'''"" | Remove-WmiObject",
                "Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter ""Name='FILTER_NAME'"" | Remove-WmiObject",
                "Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter ""Name='CONSUMER_NAME'"" | Remove-WmiObject"
            )
            
            $notes = Format-FixRecommendation `
                -Problem "CRITICAL: WMI Event Subscription persistence detected." `
                -ManualSteps $manualSteps `
                -MoreInfo "https://www.fireeye.com/blog/threat-research/2016/09/wmi_persistence.html"

            Add-AuditFinding `
                -Id "Persist_WMI" `
                -Title "WMI Persistence Detected" `
                -Value "Found $($suspiciousWMI.Count) subscription(s)" `
                -Severity 0 `
                -Weight 25 `
                -Notes $notes `
                -Category "Persistence"
        }
        else {
            Write-AuditResult "WMI Persistence" "None detected" -Status Pass
            
            Add-AuditFinding `
                -Id "Persist_WMI" `
                -Title "WMI Persistence" `
                -Value "None detected" `
                -Severity 1 `
                -Category "Persistence"
        }
    }
    catch {
        Write-AuditResult "WMI Persistence" "Query failed" -Status Warn
        
        Add-AuditFinding `
            -Id "Persist_WMI" `
            -Title "WMI Persistence Check" `
            -Value "Query failed" `
            -Severity 2 `
            -Category "Persistence"
    }
}

function Test-RegistryAutoruns {
    Write-Host "Checking registry autorun locations..." -ForegroundColor Cyan
    
    $autorunKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    $foundEntries = @()
    
    foreach ($keyPath in $autorunKeys) {
        try {
            $items = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
            
            if ($items) {
                $properties = $items.PSObject.Properties | 
                    Where-Object { $_.Name -notmatch 'PS.*|^$' }
                
                foreach ($prop in $properties) {
                    $foundEntries += [PSCustomObject]@{
                        Location = $keyPath
                        Name = $prop.Name
                        Value = $prop.Value
                    }
                    
                    Write-Host "  $($keyPath): $($prop.Name) → $($prop.Value)" -ForegroundColor Gray
                }
            }
        }
        catch {
            # Key doesn't exist or can't be read - that's okay
        }
    }
    
    if ($foundEntries.Count -gt 0) {
        Write-AuditResult "Registry Autoruns" "Found $($foundEntries.Count) entry(ies)" -Status Info
        
        $notes = Format-FixRecommendation `
            -Problem "A review of registry autorun entries is recommended. Malware and unwanted programs often add themselves here to start automatically with Windows." `
            -ManualSteps @(
                "Use Sysinternals Autoruns: Launch Autoruns64.exe and go to the 'Logon' tab.",
                "Review the entries listed in the 'HKLM\...\Run', 'HKCU\...\Run' sections.",
                "Uncheck any entries you do not recognize or that are from unverified publishers.",
                "You can also use Registry Editor (regedit.exe) to navigate to the keys and delete the values, but Autoruns is safer."
            ) `
            -MoreInfo "https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns"

        Add-AuditFinding `
            -Id "Persist_RegRun" `
            -Title "Registry Autorun Entries" `
            -Value "Found $($foundEntries.Count) entry(ies)" `
            -Severity 3 `
            -Notes $notes `
            -Category "Persistence"
    }
    else {
        Write-AuditResult "Registry Autoruns" "None found" -Status Pass
        
        Add-AuditFinding `
            -Id "Persist_RegRun" `
            -Title "Registry Autorun Entries" `
            -Value "None" `
            -Severity 1 `
            -Category "Persistence"
    }
}

function Test-ScheduledTasks {
    param([hashtable]$Config)
    
    Write-Host "Analyzing scheduled tasks..." -ForegroundColor Cyan
    
    try {
        # Get non-Microsoft tasks
        $tasks = Get-ScheduledTask -ErrorAction Stop |
            Where-Object { $_.TaskPath -notmatch "Microsoft" } |
            Select-Object TaskName, TaskPath, State, Author -First $Config.Thresholds.MaxScheduledTasks
        
        if ($tasks) {
            Write-AuditResult "Scheduled Tasks" "Found $($tasks.Count) non-Microsoft task(s)" -Status Info
            
            $suspiciousTasks = @()
            
            foreach ($task in $tasks) {
                # Check if task is enabled and has suspicious characteristics
                if ($task.State -eq 'Ready' -and $task.Author -notmatch 'Microsoft|Administrator') {
                    $suspiciousTasks += $task
                    Write-Host "  - $($task.TaskName) [$($task.State)] by $($task.Author)" -ForegroundColor Yellow
                }
                else {
                    Write-Host "  - $($task.TaskName) [$($task.State)]" -ForegroundColor Gray
                }
            }
            
            if ($suspiciousTasks.Count -gt 0) {
                $taskNames = ($suspiciousTasks | Select-Object -ExpandProperty TaskName) -join ", "
                $notes = Format-FixRecommendation `
                    -Problem "Found scheduled tasks that are not from Microsoft and may be suspicious. Malware frequently uses scheduled tasks to achieve persistence or run malicious code periodically." `
                    -ManualSteps @(
                        "Open Task Scheduler.",
                        "In the 'Task Scheduler Library', look for the following tasks: $taskNames",
                        "Review the 'Actions' tab for each task. Does it run a script or executable from a strange location (e.g., AppData, Temp)?",
                        "Review the 'Triggers' tab. Does it run frequently or at unusual times?",
                        "If a task is suspicious, right-click and 'Disable' it first. If the system remains stable, you can later 'Delete' it."
                    )

                Add-AuditFinding `
                    -Id "Persist_Tasks" `
                    -Title "Scheduled Tasks" `
                    -Value "Found $($suspiciousTasks.Count) potentially suspicious task(s)" `
                    -Severity 2 `
                    -Notes $notes `
                    -Category "Persistence"
            }
            else {
                Add-AuditFinding `
                    -Id "Persist_Tasks" `
                    -Title "Scheduled Tasks" `
                    -Value "$($tasks.Count) non-Microsoft tasks found" `
                    -Severity 3 `
                    -Category "Persistence"
            }
        }
        else {
            Write-AuditResult "Scheduled Tasks" "No non-Microsoft tasks found" -Status Pass
            
            Add-AuditFinding `
                -Id "Persist_Tasks" `
                -Title "Scheduled Tasks" `
                -Value "None found" `
                -Severity 1 `
                -Category "Persistence"
        }
    }
    catch {
        Write-AuditResult "Scheduled Tasks" "Query failed" -Status Warn
        
        Add-AuditFinding `
            -Id "Persist_Tasks" `
            -Title "Scheduled Tasks" `
            -Value "Query failed" `
            -Severity 2 `
            -Category "Persistence"
    }
}

function Test-ThirdPartyServices {
    Write-Host "Checking for non-Microsoft and forged system services..." -ForegroundColor Cyan
    
    $services = Get-CimInstance Win32_Service | 
                Where-Object { $_.State -eq 'Running' }
    
    $suspiciousServices = @()
    $thirdPartyServices = @()

    foreach ($svc in $services) {
        $path = $svc.PathName
        $isMicrosoft = $svc.DisplayName -match "Microsoft|Windows" -or $path -match "C:\\Windows\\System32"
        
        # FORGED SERVICE DETECTION
        # Check if service name looks like Windows/Microsoft but path is NOT in Windows/System32
        if ($svc.DisplayName -match "Windows|System|Update|Service" -and $path -notmatch "C:\\Windows") {
            if ($path -match "AppData|Temp|Users") {
                $suspiciousServices += $svc
                Write-Host "  [!] FORGED SERVICE DETECTED: $($svc.DisplayName) -> $path" -ForegroundColor Red
            }
        }
        
        # 3rd Party Service categorization
        if (-not $isMicrosoft) {
            $thirdPartyServices += $svc
        }
    }
    
    if ($suspiciousServices.Count -gt 0) {
        $notes = "CRITICAL: Detected forged 'Windows' services running from user directories.`n`n"
        foreach ($s in $suspiciousServices) {
            $notes += " - Service: $($s.DisplayName)`n   Path: $($s.PathName)`n"
        }
        
        Add-AuditFinding `
            -Id "Persist_ForgedService" `
            -Title "Forged Windows Services Detected" `
            -Value "Found $($suspiciousServices.Count) forged service(s)" `
            -Severity 0 `
            -Weight 25 `
            -Notes $notes `
            -Category "Persistence"
        
        Write-AuditResult "Forged Services" "DETECTED" -Status Fail
    }

    if ($thirdPartyServices.Count -gt 0) {
        Write-AuditResult "3rd-Party Services" "Found $($thirdPartyServices.Count) running service(s)" -Status Info
        
        foreach ($svc in $thirdPartyServices | Select-Object -First 10) {
            Write-Host "  - $($svc.DisplayName) [$($svc.Name)]" -ForegroundColor Gray
        }
        
        $notes = "A review of running third-party services is recommended. While most are legitimate, malware can install itself as a service to gain persistence.`n`n"
        $notes += "Review these paths for legitimacy:`n"
        foreach ($svc in $thirdPartyServices | Select-Object -First 10) {
            $notes += " - $($svc.DisplayName): $($svc.PathName)`n"
        }

        Add-AuditFinding `
            -Id "Persist_Services" `
            -Title "Third-Party Services" `
            -Value "Found $($thirdPartyServices.Count) running service(s)" `
            -Severity 3 `
            -Notes $notes `
            -Category "Persistence"
    } else {
        Write-AuditResult "3rd-Party Services" "None found" -Status Pass
    }
}

function Test-StartupFolder {
    Write-Host "Checking Startup folder..." -ForegroundColor Cyan
    
    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    $foundItems = @()
    
    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            $items = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
            
            foreach ($item in $items) {
                $foundItems += $item
                Write-Host "  - $($item.Name) in $path" -ForegroundColor Gray
            }
        }
    }
    
    if ($foundItems.Count -gt 0) {
        Write-AuditResult "Startup Folder" "Found $($foundItems.Count) item(s)" -Status Info
        
        $notes = Format-FixRecommendation `
            -Problem "Items were found in the Startup folders. These programs will launch automatically when the user logs in." `
            -ManualSteps @(
                "Open File Explorer and navigate to the following two locations:",
                "1. For the current user: shell:startup",
                "2. For all users: shell:common startup",
                "Review the shortcuts and files in these folders. If you find anything you did not intentionally place there, delete it."
            )

        Add-AuditFinding `
            -Id "Persist_Startup" `
            -Title "Startup Folder Items" `
            -Value "Found $($foundItems.Count) item(s)" `
            -Severity 3 `
            -Notes $notes `
            -Category "Persistence"
    }
    else {
        Write-AuditResult "Startup Folder" "Empty" -Status Pass
        
        Add-AuditFinding `
            -Id "Persist_Startup" `
            -Title "Startup Folder Items" `
            -Value "None" `
            -Severity 1 `
            -Category "Persistence"
    }
}

Export-ModuleMember -Function Invoke-PersistenceHunting