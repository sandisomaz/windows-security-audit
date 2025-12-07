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
        EnableFileSystemAudit = $true
        EnableCryptoMinerDetection = $true
    }
    
    # ===== OUTPUT CONFIGURATION =====
    Output = @{
        ReportPath = "Reports"
        GenerateHTML = $true
        GenerateJSON = $true
        GenerateCSV = $false
        AutoOpenReport = $true
        EnableTranscript = $true
        VerboseLogging = $false
    }
    
    # ===== THRESHOLDS & LIMITS =====
    Thresholds = @{
        MaxUpdateAge = 30
        MaxProcessesToScan = 100
        RecentExecutablesAge = 7
        MaxNetworkConnections = 20
        MaxScheduledTasks = 40
    }
    
    # ===== DETECTION RULES =====
    Detection = @{
        # FIXED: Escaped backslashes for Regex compatibility
        SuspiciousPaths = @(
            'AppData',
            'Local\\Temp',
            'Users\\Public',
            'Windows\\Temp',
            'ProgramData'
        )
        
        SuspiciousCmdKeywords = @(
            '-EncodedCommand',
            'iex ',
            'invoke-expression',
            'invoke-command',
            'downloadstring',
            'webclient',
            'bitstransfer'
        )
        
        PathlessWhitelist = @(
            'System',
            'Registry',
            'smss.exe',
            'csrss.exe',
            'lsass.exe',
            'services.exe',
            'svchost.exe'
        )
        
        PUPKeywords = @(
            'Toolbar', 'Conduit', 'Ask.com', 'Babylon', 'MyWebSearch', 'Coupon',
            'Optimizer', 'PC Cleaner', 'Registry Cleaner', 'Driver Updater', 
            'SearchProtect', 'Adware', 'PCProtect', 'TotalAV'
        )
        
        MaliciousWMIFilters = @(
            '__EventFilter'
        )
    }
    
    # ===== FILE SYSTEM AUDIT =====
    FileSystem = @{
        EnableCorruptionCheck = $true
        DrivesToScan = @('C:')
        CheckGibberishFilenames = $true
        CheckUndeletableFiles = $true
        CheckHiddenSystemFiles = $true
    }
    
    # ===== ADVANCED OPTIONS =====
    Advanced = @{
        VirusTotalAPIKey = "" # Optional: Add your free public API key
        ExcludedProcesses = @()
        ExcludedPaths = @()
    }
}