# ðŸ›¡ï¸ Windows Security Audit Framework

[![Pester Security Suite CI](https://github.com/sandisomaz/windows-security-audit/actions/workflows/test.yml/badge.svg)](https://github.com/sandisomaz/windows-security-audit/actions/workflows/test.yml)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Version 5.5](https://img.shields.io/badge/Version-5.5--Web--Edition-emerald.svg)](#-project-architecture)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Version 5.5 (Production & Web Edition)** â€” Enterprise-grade, zero-binary security auditing framework, threat-hunting engine, and real-time live web dashboard for Windows operating systems.

The **Windows Security Audit Framework** is a modular PowerShell-based forensic and security audit engine paired with a modern real-time **Web Dashboard**. It performs deep system inspection, persistence hunting, process triage, crypto-miner detection, browser extension auditing, network analysis, and system hardening verification without relying on third-party compiled binaries.

---

## ðŸ—ºï¸ System Map & Architecture Quick Link

For a complete architectural breakdown, data flow diagrams, REST API route specifications, and component dependency graphs, please refer to the dedicated **[System Map](SYSTEM_MAP.md)** (`SYSTEM_MAP.md`).

---

## ðŸŽ¯ Key Features

### ðŸ–¥ï¸ Modern Web Dashboard & Hardened API Server
- **Token-Based CSRF Protection:** Enforces dynamic single-session token verification (`X-Audit-Token` header / URL parameter) generated via 128-bit GUID cryptographically secure tokens.
- **Live Streamed Auditing:** Real-time log streaming using asynchronous PowerShell background jobs (`*>&1`) and HTTP polling.
- **Terminal Log Controls:** Live terminal log view with line counting, elapsed scan timer, and log category tab filters (**All**, **Errors**, **Warnings**, **System**).
- **Directory Traversal Protection:** Hardened static report file server under `/Reports/` preventing path escape.
- **One-Click HTML & Data Reports:** Automatically generates interactive Tailwind CSS HTML reports, machine-readable JSON, and CSV datasets.

### ðŸ” Core Audit & Threat Hunting Engines
- **Process Triage:** Detects process injection, hidden parentless processes, high CPU/RAM spikes, execution from temporary/AppData directories, and unsigned binaries.
- **Persistence Mechanism Hunting:** Audits WMI Event Subscriptions (`__EventFilter`, `__EventConsumer`), Registry Autoruns (`Run`, `RunOnce`, `Winlogon`, `IFEO`), Scheduled Tasks, and Startup Folders.
- **Crypto-Miner Detection:** Scans for active mining process signatures (`xmrig`, `ethminer`, `cgminer`), stratum protocol network connections, mining wallet keywords, and high CPU utilization.
- **Forensic Artifact Analysis:** Scans HOSTS file modifications, browser extensions (Chrome, Edge, Brave, Firefox), backdoor path indicators, and Potentially Unwanted Programs (PUPs).
- **System Hardening Verification:** Audits UAC configuration & slider levels, Secure Boot state, TPM 2.0 readiness, BitLocker encryption status, LSA Protection, Credential Guard, and SMBv1 protocol state.
- **Network & Firewall Audit:** Evaluates Domain, Private, and Public firewall profiles, listening ports, adapter promiscuity, DNS integrity, and active TCP/UDP connections.
- **Threat Intelligence & IOC Matching:** SHA256 file hashing, path indicator matching, embedded threat feeds, and optional VirusTotal API integration.

---

## âš¡ Quick Start

### Prerequisites
- **OS:** Windows 10, Windows 11, or Windows Server 2016+
- **PowerShell:** Version 5.1 or higher
- **Privileges:** Administrator privileges recommended for complete CIM/WMI access.

---

### Option 1: Web Dashboard (Recommended)

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/sandisomaz/windows-security-audit.git
   cd windows-security-audit
   ```

2. **Launch via Windows Batch Script:**
   - Double-click **`START_HERE.bat`** (or right-click â†’ *Run as Administrator*).
   
   *Or launch manually via PowerShell:*
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\AuditServer.ps1 -Port 8080
   ```

3. **Access the Dashboard:**
   - Open your web browser to **`http://localhost:8080`**.
   - Select your desired scan profile and click to initiate streaming audit logs.

---

### Option 2: PowerShell Command Line Interface (CLI)

Run directly inside PowerShell (as Administrator):

```powershell
# Default scan (Deep mode)
.\SecurityAudit.ps1

# Quick health check (2-3 mins)
.\SecurityAudit.ps1 -Mode Quick

# Standard audit (5-7 mins)
.\SecurityAudit.ps1 -Mode Standard

# Full incident investigation (20+ mins)
.\SecurityAudit.ps1 -Mode Forensic -ReportPath "C:\SecurityAudits"
```

---

## ðŸ“Š Scan Execution Modes

| Mode | Est. Duration | Description | Active Engine Modules |
|:---|:---:|:---|:---|
| **âš¡ Quick** | 2-3 min | Essential checks: Memory, File System integrity, Active Processes | `FileSystemAudit`, `ProcessTriage` |
| **ðŸ“‹ Standard** | 5-7 min | Core checks + Persistence vector hunting | Quick + `PersistenceHunting` |
| **ðŸ” Deep** *(Recommended)* | 10-15 min | Full security audit: Firewall, Defender, Hardening, Miners | Standard + `DefenderAudit`, `FirewallAudit`, `NetworkAudit`, `SystemHardening`, `CryptoMinerDetection` |
| **ðŸ”¬ Forensic** | 20+ min | Comprehensive incident investigation: Browser artifacts, IOC matching, Hash calculation | Deep + `BrowserAudit`, `ThreatIntelligence` |

---

## ðŸ“ Project Architecture & File Directory Map

```text
WindowsSecurityAudit/
â”‚
â”œâ”€â”€ .github/workflows/
â”‚   â””â”€â”€ test.yml           # GitHub Actions CI/CD Automated Pester Testing
â”œâ”€â”€ START_HERE.bat         # One-Click Windows Launcher (Starts Server + Browser)
â”œâ”€â”€ AuditServer.ps1        # Hardened HTTP Listener API Backend Engine (Port 8080)
â”œâ”€â”€ index.html             # Web Dashboard Single Page Application (Tailwind CSS)
â”œâ”€â”€ SecurityAudit.ps1      # Main Orchestration Engine
â”œâ”€â”€ Config.psd1            # Thresholds, Whitelists & Profile Configuration
â”œâ”€â”€ Run-Tests.ps1          # Automated Pester Test Runner Script
â”œâ”€â”€ SYSTEM_MAP.md          # Comprehensive System Architecture & API Documentation
â”œâ”€â”€ LICENSE                # MIT License
â”œâ”€â”€ README.md              # Project Documentation
â”‚
â”œâ”€â”€ Modules/               # Modular Security & Forensic Engines (.psm1)
â”‚   â”œâ”€â”€ Core.psm1                  # State Engine, Logging & Weighted Risk Calculator
â”‚   â”œâ”€â”€ ProcessTriage.psm1         # Process Injection, RAM Spikes & Unsigned Binaries
â”‚   â”œâ”€â”€ PersistenceHunting.psm1    # WMI Subscriptions, Autoruns & Task Scanner
â”‚   â”œâ”€â”€ CryptoMinerDetection.psm1  # Mining Signatures, Stratum Ports & CPU Utilization
â”‚   â”œâ”€â”€ FileSystemAudit.psm1       # Disk Health & System File Integrity
â”‚   â”œâ”€â”€ ForensicChecks.psm1        # HOSTS File, PUP Keywords & Backdoor Paths
â”‚   â”œâ”€â”€ DefenderAudit.psm1         # Antivirus Definition Age & Real-Time Protection
â”‚   â”œâ”€â”€ FirewallAudit.psm1         # Inbound/Outbound Rules & Open Port Auditing
â”‚   â”œâ”€â”€ NetworkAudit.psm1          # TCP/UDP Connections & DNS Integrity
â”‚   â”œâ”€â”€ SystemHardening.psm1       # UAC, Secure Boot, TPM 2.0, BitLocker & Credential Guard
â”‚   â”œâ”€â”€ BrowserAudit.psm1          # Chrome/Edge/Firefox Extension Manifest Scanner
â”‚   â”œâ”€â”€ ThreatIntelligence.psm1    # SHA256 Hashing, IOC Feeds & VirusTotal Integration
â”‚   â””â”€â”€ ReportGenerator.psm1       # Multi-Format Report Engine (HTML/JSON/CSV)
â”‚
â”œâ”€â”€ Tests/                 # Pester Automated Test Suites (.tests.ps1)
â”‚   â”œâ”€â”€ Core.tests.ps1             # Tests state management & risk calculations
â”‚   â”œâ”€â”€ Forensic.tests.ps1         # Tests HOSTS parser & PUP detection
â”‚   â””â”€â”€ Persistence.tests.ps1      # Tests registry autoruns & scheduled task logic
â”‚
â””â”€â”€ tools/                 # Utility Scripts
    â””â”€â”€ MergeFiles.ps1             # Context Aggregator Script
```

---

## âš™ï¸ Configuration (`Config.psd1`)

Tailor audit parameters, paths, and thresholds by editing `Config.psd1`:

```powershell
@{
    ScanProfile = @{
        Mode = "Deep"
        EnableSystemHardening     = $true
        EnableDefenderAudit        = $true
        EnableFirewallAudit        = $true
        EnableProcessTriage        = $true
        EnablePersistenceHunting   = $true
        EnableNetworkAudit         = $true
        EnableForensicChecks       = $true
        EnableFileSystemAudit      = $true
        EnableCryptoMinerDetection = $true
    }
    
    Output = @{
        ReportPath       = "Reports"
        GenerateHTML     = $true
        GenerateJSON     = $true
        GenerateCSV      = $false
        AutoOpenReport   = $true
        EnableTranscript = $true
    }
    
    Thresholds = @{
        MaxUpdateAge          = 30 # Days
        RecentExecutablesAge = 7  # Days
        MaxProcessesToScan   = 100
    }
    
    Detection = @{
        SuspiciousPaths = @('AppData', 'Local\\Temp', 'Users\\Public', 'ProgramData')
        PUPKeywords     = @('Toolbar', 'Adware', 'SearchProtect', 'Registry Cleaner')
        # ... additional detection rules
    }
}
```

---

## ðŸ“ˆ Understanding Security Reports & Risk Scores

### Risk Scoring Formula
The framework calculates a weighted risk percentage ($R$) based on identified findings:
- **FAIL (Critical)**: Full weight penalty (`Weight = 25`)
- **WARN (Warning)**: Half weight penalty (`Weight = 10 / 2 = 5`)
- **INFO (Informational)**: Flat 2-point penalty (`Weight = 5`)
- **PASS (Passed)**: Zero penalty (`Weight = 0`)

$$\text{Security Score } = 100 - \text{Risk Percentage}$$

### Risk Status Categories
- ðŸŸ¢ **LOW RISK (0% - 24%)**: System in good standing.
- ðŸŸ¡ **MEDIUM RISK (25% - 49%)**: Minor misconfigurations, remediation recommended.
- ðŸ”´ **HIGH RISK (50% - 100%)**: Critical vulnerabilities found, immediate action required.

---

## ðŸŒ API Route Catalog

The native HTTP backend (`AuditServer.ps1`) exposes the following endpoints:

| Endpoint | Method | Security Header Required | Description |
|:---|:---:|:---:|:---|
| `/` | `GET` | None | Renders Web Dashboard with injected `X-Audit-Token` |
| `/api/start?mode=<Mode>` | `GET` | `X-Audit-Token` | Starts background audit job |
| `/api/stop` | `GET` | `X-Audit-Token` | Cancels running audit job |
| `/api/status` | `GET` | `X-Audit-Token` | Fetches status, elapsed time & log stream |
| `/api/open-report` | `GET` | `X-Audit-Token` | Obtains latest HTML report URL |
| `/Reports/*` | `GET` | `X-Audit-Token` | Serves report files safely |

---

## ðŸ§ª Automated Testing

To run the unit test suite across all modules:

```powershell
powershell -ExecutionPolicy Bypass -File .\Run-Tests.ps1
```

The test runner automatically detects **Pester v5+** or **Pester v4** and executes tests in the `Tests/` directory.

---

## ðŸ› Troubleshooting

| Problem | Cause | Solution |
|:---|:---|:---|
| **Script execution blocked** | PowerShell execution policy restricted | Run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| **Server port conflict** | Port 8080 already in use | Launch server on a different port: `.\AuditServer.ps1 -Port 9090` |
| **Incomplete CIM/WMI results** | Non-administrator privileges | Right-click PowerShell or `START_HERE.bat` â†’ **Run as Administrator** |
| **401 Unauthorized API error** | Missing `X-Audit-Token` | Reload the dashboard (`http://localhost:8080`) to fetch a new session token |

---

## ðŸ¤ Contributing & License

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

This project is licensed under the **[MIT License](LICENSE)**.

---

**Version**: 5.5 Enterprise Edition  
**Author**: Sandiso Mazibuko  
**Status**: Active Development
