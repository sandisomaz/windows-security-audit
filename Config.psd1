@{
    # ===== SCAN CONFIGURATION =====
    ScanProfile = @{
        # Scan modes: Quick, Standard, Deep, Forensic
        Mode = "Deep"
        
        # Enable/disable specific checks
        EnableSystemHardening = $true
        EnableDefenderAudit = $true
        EnableFirewallAudit = $true
        EnableProcessTriage = $true
        EnablePersistenceHunting = $true
        EnableNetworkAudit = $true
        EnableForensicChecks = $true
        EnableFileSystemAudit = $true  # NEW: Detects corruption
    }
    
    # ===== OUTPUT CONFIGURATION =====
    Output = @{
        # Where to save reports
        ReportPath = [Environment]::GetFolderPath("Desktop")
        
        # Report formats to generate
        GenerateHTML = $true
        GenerateJSON = $true
        GenerateCSV = $false
        
        # Open HTML report automatically when done
        AutoOpenReport = $true
        
        # Logging
        EnableTranscript = $true
        VerboseLogging = $false
    }
    
    # ===== THRESHOLDS & LIMITS =====
    Thresholds = @{
        # Windows Update age threshold (days)
        MaxUpdateAge = 30
        
        # Process signature scan limit
        MaxProcessesToScan = 100
        
        # Recent executables age (days)
        RecentExecutablesAge = 7
        
        # Network connections to show
        MaxNetworkConnections = 20
        
        # Scheduled tasks to show
        MaxScheduledTasks = 40
    }
    
    # ===== DETECTION RULES =====
    Detection = @{
        # Suspicious process paths (malware often hides here)
        SuspiciousPaths = @(
            'AppData',
            'Local\Temp',
            'Users\Public',
            'Windows\Temp',
            'ProgramData'
        )
        
        # Suspicious command line keywords (fileless malware)
        SuspiciousCmdKeywords = @(
            '-EncodedCommand',
            'iex ',
            'invoke-expression',
            'invoke-command',
            'downloadstring',
            'webclient',
            'bitstransfer'
        )
        
        # Whitelisted processes (won't flag as suspicious even without path)
        PathlessWhitelist = @(
            'System',
            'Registry',
            'smss.exe',
            'csrss.exe',
            'lsass.exe',
            'services.exe',
            'svchost.exe'
        )
        
        # PUP (Potentially Unwanted Program) keywords
        PUPKeywords = @(
            'Toolbar',
            'Conduit',
            'Ask.com',
            'Babylon',
            'MyWebSearch',
            'Coupon',
            'Optimizer',
            'PC Cleaner',
            'Registry Cleaner',
            'Driver Updater',
            'SearchProtect',
            'Adware',
            'PCProtect',
            'TotalAV'
        )
        
        # Known malicious WMI event filters (can expand this list)
        MaliciousWMIFilters = @(
            '__EventFilter'
        )
    }
    
    # ===== FILE SYSTEM AUDIT =====
    FileSystem = @{
        # Check for file system corruption
        EnableCorruptionCheck = $true
        
        # Scan these drives
        DrivesToScan = @('C:', 'D:')
        
        # Look for suspicious file patterns
        CheckGibberishFilenames = $true
        CheckUndeletableFiles = $true
        CheckHiddenSystemFiles = $true
    }
    
    # ===== BASELINE COMPARISON =====
    Baseline = @{
        # Compare against previous scan
        EnableBaselineComparison = $true
        
        # Where to store baseline
        BaselinePath = "$env:APPDATA\SecurityAudit\baseline.json"
        
        # Alert on new items
        AlertOnNewProcesses = $true
        AlertOnNewAutoruns = $true
        AlertOnNewServices = $true
        AlertOnNewExtensions = $true
    }
    
    # ===== ADVANCED OPTIONS =====
    Advanced = @{
        # Performance tuning
        ParallelProcessing = $false  # Future feature
        MaxThreads = 4
        
        # Integration
        VirusTotalAPIKey = ""  # Add your API key for hash checking
        
        # Exclusions (skip these processes/paths)
        ExcludedProcesses = @()
        ExcludedPaths = @()
    }
}