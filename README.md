# 🛡️ Windows Security Audit Framework

> **Version 5.4 (Web Edition)** - Enterprise-grade security auditing tool for Windows systems

A comprehensive PowerShell-based security audit framework with a modern **Web Dashboard**. It performs deep forensic analysis, threat hunting, and system integrity checks.

---

## 🎯 Features

### 🖥️ Modern Web Dashboard
- **Live Monitoring:** Real-time log streaming via WebSocket-like polling.
- **One-Click Scanning:** Launch Quick, Standard, Deep, or Forensic scans instantly.
- **Responsive UI:** Built with Tailwind CSS, works in any modern browser.
- **Dark Mode:** Automatically adapts to your system theme.

### 🔍 Core Capabilities
- **Deep Process Triage:** Detects process injection, fileless malware, unsigned binaries.
- **Crypto Miner Detection:** Identifies abnormal CPU usage and mining signatures.
- **Persistence Hunting:** Scans WMI subscriptions, Registry Autoruns, and Scheduled Tasks.
- **Forensic Analysis:** Checks browser extensions, HOSTS files, and recent executables.
- **System Hardening:** Verifies UAC, Secure Boot, TPM, and Windows Defender status.

---

## 🚀 Quick Start

### Prerequisites
- **OS:** Windows 10 or Windows 11
- **PowerShell:** Version 5.1 or higher
- **Rights:** Administrator privileges are required for deep scans.

### Installation

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/sandisomaz/windows-security-audit.git
   cd windows-security-audit
   ```

2. **Launch the Dashboard:**
   - Double-click `START_HERE.bat`
   - (Accept the Admin prompt if asked)

3. **Run a Scan:**
   - The dashboard will open in your default browser (http://localhost:8080).
   - Click a scan mode (e.g., Quick Scan).
   - Wait for the "Open Report" button to appear.

## 📊 Scan Modes

| Mode | Duration | Description |
|------|----------|-------------|
| **⚡ Quick** | 2-3 min | Essential checks: Memory, Disk Health, Critical System Files |
| **📋 Standard** | 5-7 min | Core checks + Persistence Hunting (Autoruns, WMI) |
| **🔍 Deep** | 10-15 min | Comprehensive audit: Network, Firewall, Defender, Hardening |
| **🔬 Forensic** | 20+ min | Full investigation: Timeline analysis, Verbose logging |

## 📁 Project Structure

```text
WindowsSecurityAudit/
│
├── START_HERE.bat         # Launcher (Starts Backend + Browser)
├── AuditServer.ps1        # Web Server Backend (API)
├── index.html             # Web Dashboard Frontend
├── SecurityAudit.ps1      # Main Scan Engine
├── Config.psd1            # Configuration Settings
├── LICENSE                # MIT License
├── README.md              # Documentation
│
├── Modules/               # Security Logic Modules
│   ├── Core.psm1
│   ├── ProcessTriage.psm1
│   ├── CryptoMinerDetection.psm1
│   ├── ... (other modules)
│
└── Reports/                       # Auto-generated reports
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