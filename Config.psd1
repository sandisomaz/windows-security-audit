@{
    # =====================================================================
    # Windows Security Audit Framework — Configuration Manifest
    # Version: 5.5.0
    #
    # Edit this file to customise scan behaviour, detection thresholds,
    # and threat signatures without modifying any module source code.
    # =====================================================================

    # ===== SCAN CONFIGURATION =====
    ScanProfile = @{
        # Scan modes: Quick | Standard | Deep | Forensic
        Mode = 'Deep'

        # Fine-grained module enable/disable toggles
        EnableSystemHardening      = $true
        EnableDefenderAudit        = $true
        EnableFirewallAudit        = $true
        EnableProcessTriage        = $true
        EnablePersistenceHunting   = $true
        EnableNetworkAudit         = $true
        EnableForensicChecks       = $true
        EnableFileSystemAudit      = $true
        EnableCryptoMinerDetection = $true
    }

    # ===== OUTPUT CONFIGURATION =====
    Output = @{
        ReportPath      = 'Reports'
        GenerateHTML    = $true
        GenerateJSON    = $true
        GenerateCSV     = $false
        AutoOpenReport  = $true
        EnableTranscript = $true
        VerboseLogging  = $false
    }

    # ===== THRESHOLDS & LIMITS =====
    Thresholds = @{
        # Days since last Windows Update before flagging as outdated
        MaxUpdateAge            = 30
        # Maximum number of processes to deep-scan for signatures
        MaxProcessesToScan      = 100
        # Files modified within this many days are flagged as recent
        RecentExecutablesAge    = 7
        # Maximum TCP connections to report in the network audit
        MaxNetworkConnections   = 20
        # Maximum non-Microsoft scheduled tasks to inspect
        MaxScheduledTasks       = 40
        # Sustained CPU usage percentage (per-core normalised) that flags a process
        SuspiciousCPUPercent    = 40
        # Minimum number of changed documents (in 30 min) to trigger ransomware flag
        RansomwareFileChangeThreshold = 100
        # Minimum credential files accessed (in 24 h) to flag info-stealer activity
        InfoStealerFileAccessThreshold = 5
        # Minimum outbound TCP connections from one process to flag botnet activity
        BotnetConnectionThreshold = 20
    }

    # ===== GENERIC DETECTION RULES =====
    Detection = @{
        # Regex-escaped path fragments treated as suspicious execution locations
        SuspiciousPaths = @(
            'AppData',
            'Local\\Temp',
            'Users\\Public',
            'Windows\\Temp',
            'ProgramData'
        )

        # Command-line keywords that flag obfuscated/download activity
        SuspiciousCmdKeywords = @(
            '-EncodedCommand',
            'iex ',
            'invoke-expression',
            'invoke-command',
            'downloadstring',
            'webclient',
            'bitstransfer'
        )

        # Process names that are legitimately pathless (kernel-mode or pseudo-processes)
        PathlessWhitelist = @(
            'System',
            'Registry',
            'smss.exe',
            'csrss.exe',
            'lsass.exe',
            'services.exe',
            'svchost.exe'
        )

        # Installer display-name keywords that identify Potentially Unwanted Programs
        PUPKeywords = @(
            'Toolbar', 'Conduit', 'Ask.com', 'Babylon', 'MyWebSearch', 'Coupon',
            'Optimizer', 'PC Cleaner', 'Registry Cleaner', 'Driver Updater',
            'SearchProtect', 'Adware', 'PCProtect', 'TotalAV'
        )
    }

    # ===== THREAT SIGNATURES =====
    # All signature lists live here so users can extend them without touching module code.
    Signatures = @{

        # ---- Crypto-Miner Detection ----------------------------------------
        # Known miner executable names (without path)
        MinerExecutables = @(
            'xmrig.exe', 'cgminer.exe', 'claymore.exe', 'ethminer.exe',
            'nicehash.exe', 'minergate.exe', 'cpuminer.exe', 'bfgminer.exe',
            'phoenixminer.exe', 'teamredminer.exe', 'lolminer.exe',
            'trex.exe', 'nbminer.exe', 'gminer.exe'
        )

        # Mining pool hostname fragments used for DNS/connection checks
        MiningPools = @(
            'xmr-pool', 'nanopool', 'ethermine', 'f2pool', 'antpool',
            'nicehash', 'minergate', 'monero', 'pool.supportxmr',
            'monerohash', 'hashvault', 'minexmr'
        )

        # Command-line argument patterns that identify miner processes
        MinerCommandPatterns = @(
            '--algo=', '--algo ', '--pool=', '--pool ', '-o stratum',
            'stratum+tcp://', 'stratum+ssl://', '--donate-level=',
            '--cpu-priority', 'cryptonight', 'randomx', 'kawpow', 'ethash'
        )

        # TCP ports commonly used by stratum mining pools
        MiningPorts = @(3333, 4444, 5555, 7777, 8888, 9999, 14433, 14444)

        # ---- Network Threat Ports ------------------------------------------
        # TCP ports used by common RAT/backdoor frameworks
        RatPorts = @(1337, 31337, 4444, 5555, 6666, 7777, 8888, 9999, 12345, 54321)

        # Ports flagged specifically when listening locally (subset of RatPorts)
        SuspiciousListeningPorts = @(1337, 31337, 4444, 5555, 6666, 8888, 9999, 12345)

        # IRC ports (old-school botnet command-and-control)
        IrcPorts = @(6667, 6668, 6669, 7000)

        # Outbound firewall ports that should never have explicit "Allow" rules
        MaliciousOutboundPorts = @(6667, 1337, 31337)

        # ---- Ransomware Indicators -----------------------------------------
        # File extensions appended by known ransomware families
        RansomwareExtensions = @(
            '.encrypted', '.locked', '.crypto', '.crypt', '.cerber',
            '.locky', '.zepto', '.odin', '.vault', '.xtbl'
        )

        # Filename glob patterns for ransom-note drop files
        RansomNotePatterns = @(
            'README*.txt', 'DECRYPT*.txt', 'HOW_TO_DECRYPT*',
            'YOUR_FILES_ARE_ENCRYPTED*', 'RECOVERY*'
        )

        # ---- Remote Access Trojans -----------------------------------------
        # Executable name fragments for legitimate remote-access tools;
        # flagged when found running from AppData/Temp (not their default location)
        RemoteAccessTools = @(
            'anydesk', 'teamviewer', 'remotepc', 'vnc',
            'ammyy', 'ultravnc', 'tightvnc'
        )

        # Reverse-shell command-line patterns
        ReverseShellPatterns = @(
            'powershell.*IEX',
            'cmd.exe.*net.*user',
            'mshta.*http'
        )

        # ---- Keylogger Indicators ------------------------------------------
        # Filename glob patterns in AppData that suggest keystroke-capture logs
        KeyloggerFilePatterns = @('keylog*.txt', '*passwords*.txt', 'log*.dat')

        # ---- Backdoor Directory Patterns -----------------------------------
        # Folders whose existence (with files inside) suggests a backdoor.
        # Use $env: variables — they are expanded at runtime by ForensicChecks.
        BackdoorDirectories = @(
            '$env:LOCALAPPDATA\Updates',
            '$env:LOCALAPPDATA\Windows',
            '$env:APPDATA\Updates',
            'C:\Users\Public\Updates'
        )

        # ---- Forged-Service Detection Pattern Fragments --------------------
        # Service display-name keywords that masquerade as Windows services
        ForgedServiceNameFragments = @('Windows', 'System', 'Update', 'Service')
    }

    # ===== FILE SYSTEM AUDIT =====
    FileSystem = @{
        EnableCorruptionCheck    = $true
        DrivesToScan             = @('C:')
        CheckGibberishFilenames  = $true
        CheckUndeletableFiles    = $true
        CheckHiddenSystemFiles   = $true
    }

    # ===== ADVANCED OPTIONS =====
    Advanced = @{
        # VirusTotal public API key (free tier: 4 requests/minute).
        # Leave empty to skip cloud hash lookups.
        VirusTotalAPIKey = ''

        # Full path to nvidia-smi.exe for GPU usage checks.
        # Set to '' to auto-detect, or provide the explicit path.
        NvidiaSmiPath = 'C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe'

        # Process names to exclude from all process-level checks
        ExcludedProcesses = @()

        # Path fragments to skip during file-system scans
        ExcludedPaths = @(
            '\\.venv\\',
            '\\node_modules\\',
            '\\target\\',
            '\\bin\\',
            '\\obj\\',
            '\\.git\\'
        )
    }
}