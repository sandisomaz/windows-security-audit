# 🛡️ Windows Security Audit Framework

> **Version 5.1** - Enterprise-grade security auditing tool for Windows systems

A comprehensive PowerShell-based security audit framework with GUI that performs deep forensic analysis, threat hunting, and system integrity checks.

---

## 🎯 Features

### Core Capabilities
- ✅ **Deep Process Triage** - Detects process injection, fileless malware, unsigned binaries
- ✅ **File System Integrity** - Identifies corruption, missing system folders, disk health issues
- ✅ **System Hardening Checks** - UAC, Secure Boot, TPM verification
- ✅ **Windows Defender Analysis** - Real-time protection, signature updates, tamper protection
- ✅ **Firewall Configuration** - Multi-profile firewall status
- ✅ **Persistence Hunting** - WMI subscriptions, autoruns, scheduled tasks
- ✅ **Network Analysis** - External connections, DNS configuration
- ✅ **Forensic Checks** - Browser extensions, HOSTS file, PUPs, recent executables
- ✅ **Risk Scoring** - Weighted severity scoring with detailed recommendations

### 🎨 GUI Application
- Modern, user-friendly interface
- One-click scanning
- Real-time progress updates
- Automatic HTML report generation
- Multiple scan modes (Quick, Standard, Deep, Forensic)

---

## 🚀 Quick Start

### Prerequisites
- Windows 10/11
- PowerShell 5.1 or higher
- Administrator privileges (recommended)

### Installation

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/sandisomaz/WindowsSecurityAudit.git
   cd WindowsSecurityAudit
   ```

2. **Launch the GUI:**
   - Double-click `START_HERE.bat`
   - Or right-click → "Run as Administrator"

3. **Choose your scan mode and click Start!**

---

## 📖 Usage

### GUI Mode (Recommended)
```batch
START_HERE.bat
```

### Command Line
```powershell
# Default scan (Deep mode)
.\SecurityAudit.ps1

# Quick scan (essential checks only)
.\SecurityAudit.ps1 -Mode Quick

# Full forensic analysis
.\SecurityAudit.ps1 -Mode Forensic
```

---

## 📊 Scan Modes

| Mode | Duration | Description |
|------|----------|-------------|
| **⚡ Quick** | 2-3 min | Essential security checks, file system integrity |
| **📋 Standard** | 5-7 min | Core checks + persistence hunting |
| **🔍 Deep** | 10-15 min | Comprehensive audit (recommended) |
| **🔬 Forensic** | 20+ min | Full investigation with verbose logging |

---

## 📁 Project Structure

```
WindowsSecurityAudit/
│
├── SecurityAudit.ps1              # Main orchestrator script
├── Config.psd1                    # Configuration file
├── README.md                      # This file
│
├── Modules/
│   ├── Core.psm1                  # Foundation utilities
│   ├── ProcessTriage.psm1         # Deep process analysis
│   ├── FileSystemAudit.psm1       # File system integrity
│   ├── PersistenceHunting.psm1    # WMI, Autoruns, Tasks
│   ├── ForensicChecks.psm1        # HOSTS, PUPs, Extensions
│   ├── SystemHardening.psm1       # UAC, SecureBoot, RDP
│   ├── DefenderAudit.psm1         # Defender status checks
│   ├── FirewallAudit.psm1         # Firewall profile checks
│   ├── NetworkAudit.psm1          # Network connection analysis
│   ├── ReportGenerator.psm1       # HTML/JSON/CSV reports
│
└── Reports/                       # Auto-generated reports
    └── WinSecAudit_YYYYMMDD_HHMMSS/
        ├── report.html
        ├── report.json
        └── report.csv
```

## 🚀 Quick Start

### Prerequisites
- Windows 10/11
- PowerShell 5.1 or higher
- Administrator privileges (recommended)

### Installation

1. **Download/Clone the project**
   ```powershell
   git clone https://github.com/yourusername/WindowsSecurityAudit.git
   cd WindowsSecurityAudit
   ```

2. **Set execution policy** (if needed)
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

3. **Run the audit**
   ```powershell
   .\SecurityAudit.ps1
   ```

## 📖 Usage

### Basic Usage

```powershell
# Default scan (Deep mode)
.\SecurityAudit.ps1

# Quick scan (essential checks only)
.\SecurityAudit.ps1 -Mode Quick

# Standard scan (balanced)
.\SecurityAudit.ps1 -Mode Standard

# Full forensic analysis
.\SecurityAudit.ps1 -Mode Forensic

# Custom report location
.\SecurityAudit.ps1 -ReportPath "C:\SecurityAudits"

# Use custom configuration
.\SecurityAudit.ps1 -ConfigPath ".\MyConfig.psd1"
```

### Scan Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Quick** | Essential security checks, file system integrity | Quick health check |
| **Standard** | Core + persistence hunting | Regular audits |
| **Deep** | All checks enabled | Comprehensive audit |
| **Forensic** | Everything + verbose logging | Incident investigation |

## ⚙️ Configuration

Edit `Config.psd1` to customize the audit:

```powershell
@{
    ScanProfile = @{
        Mode = "Deep"
        EnableProcessTriage = $true
        EnableFileSystemAudit = $true
        # ... more options
    }
    
    Output = @{
        ReportPath = [Environment]::GetFolderPath("Desktop")
        GenerateHTML = $true
        GenerateJSON = $true
        AutoOpenReport = $true
    }
    
    Thresholds = @{
        MaxUpdateAge = 30           # Days
        RecentExecutablesAge = 7    # Days
        # ... more thresholds
    }
    
    Detection = @{
        SuspiciousPaths = @('AppData', 'Temp', ...)
        PUPKeywords = @('Toolbar', 'Adware', ...)
        # ... customize detection rules
    }
}
```

## 📊 Understanding Reports

### Risk Levels

- **LOW** (0-24%): System is in good health
- **MEDIUM** (25-49%): Some concerns, action recommended
- **HIGH** (50-100%): Critical issues, immediate action required

### Severity Ratings

- **FAIL** (Red): Critical security issue
- **WARN** (Yellow): Potential problem
- **PASS** (Green): Check passed
- **INFO** (Gray): Informational only

### Report Formats

1. **HTML Report** - Beautiful, interactive web report
2. **JSON Report** - Machine-readable for automation
3. **CSV Report** - Spreadsheet-compatible

## 🔧 Development

### Adding New Modules

1. Create module in `Modules/` directory:
   ```powershell
   # Modules/MyModule.psm1
   using module .\Core.psm1
   
   function Invoke-MyCheck {
       param([hashtable]$Config)
       Write-AuditHeader "My Custom Check"
       # Your logic here
       Add-AuditFinding -Id "MyCheck_1" -Title "..." -Value "..." -Severity 1
   }
   
   Export-ModuleMember -Function Invoke-MyCheck
   ```

2. Import and call in `SecurityAudit.ps1`:
   ```powershell
   Import-Module (Join-Path $ScriptRoot "Modules\MyModule.psm1") -Force
   Invoke-MyCheck -Config $Config
   ```

### Module Development Guidelines

- Use `Write-AuditHeader` for section headers
- Use `Write-AuditResult` for console output
- Use `Add-AuditFinding` to record findings
- Use `Invoke-SafeCommand` for error-safe execution
- Follow severity guidelines:
  - 0 = FAIL (critical issue)
  - 1 = PASS (check passed)
  - 2 = WARN (potential issue)
  - 3 = INFO (informational)

## 🐛 Troubleshooting

### Common Issues

**"Execution policy" error**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**"Not running as Administrator"**
- Right-click PowerShell → Run as Administrator
- Or the script will prompt to re-launch

**Reports not generating**
- Check write permissions to report path
- Verify `Config.psd1` output settings

**Modules not loading**
- Ensure all `.psm1` files are in `Modules/` folder
- Check file paths are correct

## 📝 License

This project is open source and available under the MIT License.

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 📧 Support

- **Issues**: Submit via GitHub Issues
- **Discussions**: Use GitHub Discussions
- **Security Issues**: Report privately

## 🙏 Acknowledgments

Built with PowerShell and inspired by enterprise security tools like:
- CIS Benchmarks
- Microsoft Security Compliance Toolkit
- NIST Cybersecurity Framework

## 📚 Further Reading

- [PowerShell Security Best Practices](https://docs.microsoft.com/powershell/scripting/security/)
- [Windows Security Baseline](https://docs.microsoft.com/windows/security/threat-protection/windows-security-baselines)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

**Version**: 5.1  
**Last Updated**: 2025  
**Author**: Sandiso Mazibuko  
**Status**: Active Development