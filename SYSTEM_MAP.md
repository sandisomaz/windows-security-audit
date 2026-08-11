# Windows Security Audit Framework - System Architecture Map

> **Version 5.5 (Production & Web Edition)**  
> **Target OS:** Windows 10 / Windows 11 / Windows Server 2016+  
> **Execution Engine:** PowerShell 5.1+ & Native System.Net.HttpListener  
> **Last Updated:** August 2026  

---

## High-Level Architecture Overview

The **Windows Security Audit Framework (v5.5)** is an enterprise-grade, zero-binary security auditing and threat-hunting platform. It operates without external compiled binaries, leveraging native Windows Management Instrumentation (WMI), Common Information Model (CIM), Component Object Model (COM), and PowerShell 5.1+ cmdlets.

The framework consists of four primary tiers:
1. **User Interface Tier**: Single Page Application (`index.html`) using Tailwind CSS and Material Symbols.
2. **Backend API & Service Tier**: REST API Server (`AuditServer.ps1`) backed by `System.Net.HttpListener` with session token security.
3. **Orchestration & Audit Core Tier**: Execution Engine (`SecurityAudit.ps1`), Configuration (`Config.psd1`), and Core Utilities (`Modules/Core.psm1`).
4. **Analysis & Threat Hunting Tier**: 12 Specialized PowerShell Modules (`Modules/*.psm1`) executing deep system inspection.

```
+-----------------------------------------------------------------------------------+
|                             PRESENTATION TIER                                     |
|                                                                                   |
|   +---------------------------------------------------------------------------+   |
|   |                 Web UI Dashboard (index.html)                             |   |
|   |   - Real-Time Console Streamer   - Live Elapsed Timer                     |   |
|   |   - Categorized Log Filters      - Interactive Scan Controls                  |   |
|   +---------------------------------------------------------------------------+   |
+----------------------------------------+------------------------------------------+
                                         | HTTP Requests (X-Audit-Token)
                                         v
+-----------------------------------------------------------------------------------+
|                              API SERVICE TIER                                     |
|                                                                                   |
|   +---------------------------------------------------------------------------+   |
|   |                 AuditServer.ps1 (Port 8080)                               |   |
|   |   - System.Net.HttpListener      - GUID CSRF Session Token Auth               |   |
|   |   - Async PowerShell Job Runner  - Path Traversal Protected File Server       |   |
|   +---------------------------------------------------------------------------+   |
+----------------------------------------+------------------------------------------+
                                         | Spawns Async PS Job (*>&1 Stream)
                                         v
+-----------------------------------------------------------------------------------+
|                            ORCHESTRATION & CORE TIER                              |
|                                                                                   |
|   +-----------------------+  +-----------------------+  +---------------------+   |
|   | SecurityAudit.ps1     |  | Config.psd1           |  | Core.psm1           |   |
|   | Orchestration Engine  |<-| Scan Profiles & Rules |->| Risk & State Engine |   |
|   +-----------+-----------+  +-----------------------+  +----------+----------+   |
+---------------+----------------------------------------------------+--------------+
                | Loads & Executes Selected Modules                  | Collects Findings
                v                                                    v
+-----------------------------------------------------------------------------------+
|                             AUDIT MODULE TIER                                     |
|                                                                                   |
| +-----------------------+ +-----------------------+ +---------------------------+ |
| | ProcessTriage.psm1   | | PersistenceHunting   | | CryptoMinerDetection     | |
| +-----------------------+ +-----------------------+ +---------------------------+ |
| | FileSystemAudit      | | DefenderAudit        | | FirewallAudit            | |
| +-----------------------+ +-----------------------+ +---------------------------+ |
| | NetworkAudit         | | SystemHardening      | | ForensicChecks           | |
| +-----------------------+ +-----------------------+ +---------------------------+ |
| | BrowserAudit         | | ThreatIntelligence   | | ReportGenerator          | |
| +-----------------------+ +-----------------------+ +---------------------------+ |
+----------------------------------------+------------------------------------------+
                                         | System Inspection (CIM / WMI / Registry)
                                         v
+-----------------------------------------------------------------------------------+
|                          TARGET SYSTEM ENVIRONMENT                                |
|  Win32/CIM Provider  - Registry Autoruns  - Network Sockets  - Event Logs         |
+-----------------------------------------------------------------------------------+
```

---

## Data Flow & Job Orchestration Pipeline

```
[User Clicks "Run Scan"]
       |
       v
1. Web Dashboard (index.html)
       | HTTP GET /api/start?mode=Deep (Header: X-Audit-Token)
       v
2. API Backend (AuditServer.ps1)
       | Validates X-Audit-Token -> Spawns PowerShell Background Job
       | Start-Job -ScriptBlock { SecurityAudit.ps1 -Mode Deep *>&1 }
       v
3. Orchestration Engine (SecurityAudit.ps1)
       | Reads Config.psd1 & Loads Modules/Core.psm1
       | Initializes Global Findings Store
       | Iterates over configured modules for requested mode
       v
4. Module Execution Phase (Modules/*.psm1)
       | Executes audit functions sequentially
       | Performs CIM/WMI/Registry queries and heuristic analysis
       | Emits log messages to stdout (*>&1)
       | Registers structured findings via Add-AuditFinding
       v
5. Real-Time Log Streaming Loop (index.html <-> AuditServer.ps1)
       | Dashboard polls GET /api/status every 1000ms
       | Server collects Receive-Job output -> categorizes (ERR, WARN, SYS, INFO)
       | Dashboard renders logs into live terminal view
       v
6. Finalization & Report Generation (ReportGenerator.psm1)
       | Calculates overall Risk Score & Security Percentage via Core.psm1
       | Generates modern HTML report (report.html) with inline print CSS
       | Generates programmatic JSON report (report.json)
       | Writes files to ./Reports/WinSecAudit_<timestamp>/
       v
7. Audit Completion
       | Job transitions state to 'Completed'
       | Dashboard displays "Open Full Audit Report" action button
```

---

## Security & Authentication Model

### 1. CSRF & Local Session Security Token (`X-Audit-Token`)
- Upon launching `AuditServer.ps1`, a 128-bit cryptographically secure session token is generated:
  ```powershell
  $SessionToken = [Guid]::NewGuid().ToString("N")
  ```
- When serving `index.html`, the backend dynamically injects the session token into the page metadata:
  ```html
  <meta name="audit-token" content="<32-character-hex-guid>"/>
  ```
- All administrative API requests (`/api/start`, `/api/stop`, `/api/status`, `/api/open-report`, `/Reports/*`) require verification via the `X-Audit-Token` HTTP header or `?token=` query parameter.
- Unauthorized requests receive an HTTP `401 Unauthorized` response with a JSON payload.

### 2. Path Traversal Protection
- Static report files served under `/Reports/` are strictly scoped using absolute path resolution:
  ```powershell
  $requestedPath = [System.IO.Path]::GetFullPath((Join-Path $RootPath $decodedUrl.TrimStart("/")))
  $reportsFolder = [System.IO.Path]::GetFullPath((Join-Path $RootPath "Reports"))
  if ($requestedPath.StartsWith($reportsFolder) -and (Test-Path $requestedPath -PathType Leaf)) { ... }
  ```
- Attempts to access files outside the `Reports/` folder return HTTP `403 Forbidden`.

---

## Risk Calculation & Severity Scoring Engine

The framework evaluates security findings using a weighted risk scoring algorithm defined in [`Modules/Core.psm1`](./Modules/Core.psm1).

### Severity Levels & Weights

| Severity Code | Label | Description | Default Weight | Score Contribution |
|:---:|:---:|:---|:---:|:---|
| `0` | **FAIL** | Critical security vulnerability or compromise indicator | `25` | 100% of Weight |
| `2` | **WARN** | Potential misconfiguration or suspicious artifact | `10` | 50% of Weight |
| `3` | **INFO** | Informational system metric or observation | `5` | Flat 2 points |
| `1` | **PASS** | Audit check completed with secure outcome | `0` | 0 points |

### Mathematical Formula

$$\text{Raw Score } (S) = \sum_{i \in \text{Fail}} W_i + \sum_{j \in \text{Warn}} \frac{W_j}{2} + 2 \times N_{\text{Info}}$$

$$\text{Max Possible Score } (M) = \sum_{k \in \text{All Findings}} W_k$$

$$\text{Risk Percentage } (R) = \text{Round}\left( \frac{S}{M} \times 100, 2 \right)$$

$$\text{Security Score } = 100 - R$$

### Risk Rating Scale

- **LOW RISK (0% - 24%)**: Excellent security posture ("Good Standing").
- **MEDIUM RISK (25% - 49%)**: Misconfigurations detected ("Needs Improvement").
- **HIGH RISK (50% - 100%)**: Severe vulnerabilities or active threats ("Critical Risk").

---

## Detailed Component Catalog

### 1. Orchestrator Engine (`SecurityAudit.ps1`)
- **Role**: Command-line entry point & execution manager.
- **Parameters**: `-Mode` (`Quick`, `Standard`, `Deep`, `Forensic`), `-ConfigPath`, `-ReportPath`.
- **Functionality**:
  - Validates environment and execution policy.
  - Loads core configuration from `Config.psd1`.
  - Executes audit modules dynamically based on selected mode.
  - Controls transcript logging (`Start-Transcript`).
  - Triggers final report generation.

### 2. REST API & Web Server (`AuditServer.ps1`)
- **Role**: Lightweight HTTP server providing a GUI backend.
- **Port**: Default `8080` (configurable).
- **Core Technology**: Native `.NET System.Net.HttpListener`.
- **Job Management**: Runs `SecurityAudit.ps1` in an isolated background job (`Start-Job`), receiving terminal output asynchronously.

### 3. Web Dashboard SPA (`index.html`)
- **Role**: User-facing web dashboard.
- **Stack**: HTML5, Vanilla JavaScript, Tailwind CSS (CDN), Material Symbols.
- **Features**:
  - Live log terminal with color coding and category filters (`All`, `Errors`, `Warnings`, `System`).
  - Execution mode launcher with duration estimates.
  - Real-time status indicator & elapsed scan timer.
  - One-click action to view generated HTML reports.

### 4. Configuration Manifest (`Config.psd1`)
- **Role**: Data structure governing threshold parameters, scan profiles, path whitelist, and detection keywords.
- **Key Sections**:
  - `ScanProfile`: Global module toggle switches.
  - `Output`: Report pathing, formats (HTML/JSON/CSV), transcript options.
  - `Thresholds`: Max update age, recent executable age limit, max processes scanned.
  - `Detection`: Regex-escaped path patterns, PUP keywords, suspicious command keywords, pathless whitelist.

---

## Audit Modules Breakdown

| Module | Core Functions | Inspection Scope & Techniques |
|:---|:---|:---|
| **[`Core.psm1`](./Modules/Core.psm1)** | `Add-AuditFinding`, `Get-RiskScore`, `Get-SystemInfo`, `Invoke-SafeCommand` | Centralized state management, weighted scoring, system metadata retrieval, safe execution wrappers. |
| **[`ProcessTriage.psm1`](./Modules/ProcessTriage.psm1)** | `Invoke-ProcessTriage` | Audits active processes for process injection, pathless executables, suspicious execution from `Temp`/`AppData`, high CPU/RAM usage spikes, and unsigned binaries. |
| **[`PersistenceHunting.psm1`](./Modules/PersistenceHunting.psm1)** | `Invoke-PersistenceHunting` | Inspects WMI Event Subscriptions (`__EventFilter`, `__EventConsumer`), Registry Autoruns (`Run`, `RunOnce`, `Winlogon`, `IFEO`), Scheduled Tasks, and Startup folder shortcuts. |
| **[`CryptoMinerDetection.psm1`](./Modules/CryptoMinerDetection.psm1)** | `Invoke-CryptoMinerDetection` | Scans for known miner process names (`xmrig`, `ethminer`), stratum protocol network connections (ports 3333, 4444, 5555, etc.), miner wallet keywords in command arguments, and abnormal CPU usage. |
| **[`FileSystemAudit.psm1`](./Modules/FileSystemAudit.psm1)** | `Invoke-FileSystemAudit` | Checks system drive health, NTFS integrity flags, undeletable file handles, hidden system files, and randomized/gibberish file name patterns in system locations. |
| **[`DefenderAudit.psm1`](./Modules/DefenderAudit.psm1)** | `Invoke-DefenderAudit` | Audits Windows Defender operational status, Real-Time Protection status, antivirus signature definition age, Controlled Folder Access, and NIS rules via CIM. |
| **[`FirewallAudit.psm1`](./Modules/FirewallAudit.psm1)** | `Invoke-FirewallAudit` | Inspects Domain, Private, and Public Windows Firewall profile states, checking for disabled profiles, open listening ports, and insecure inbound rules. |
| **[`NetworkAudit.psm1`](./Modules/NetworkAudit.psm1)** | `Invoke-NetworkAudit` | Evaluates active network connections, listening ports, adapter promiscuous mode, DNS server configurations, and suspicious outbound remote IP addresses. |
| **[`SystemHardening.psm1`](./Modules/SystemHardening.psm1)** | `Invoke-SystemHardeningAudit` | Audits core security features: UAC slider level, Secure Boot state, TPM 2.0 availability, BitLocker encryption status, LSA Protection, Credential Guard, and SMBv1 protocol activation. |
| **[`ForensicChecks.psm1`](./Modules/ForensicChecks.psm1)** | `Invoke-ForensicChecks` | Detects HOSTS file modifications/redirects, Potentially Unwanted Programs (PUPs), backdoor directory paths, guest account status, and event log clearing artifacts. |
| **[`BrowserAudit.psm1`](./Modules/BrowserAudit.psm1)** | `Invoke-BrowserAudit` | Scans Chrome, Edge, Brave, and Firefox extension manifest files for high-risk permissions (`<all_urls>`, `webRequest`, `cookies`, `management`) and side-loaded extensions. |
| **[`ThreatIntelligence.psm1`](./Modules/ThreatIntelligence.psm1)** | `Invoke-ThreatIntelligence` | Calculates SHA256 file hashes for suspicious binaries, matches IOC indicators against embedded threat feeds, and optionally queries VirusTotal API. |
| **[`ReportGenerator.psm1`](./Modules/ReportGenerator.psm1)** | `New-AuditReport` | Compiles audit findings into an interactive Tailwind CSS HTML report with print styling and SVG risk gauge, alongside a machine-readable JSON data export. |

---

## Execution Profile Matrix

| Scan Profile | Est. Time | Included Modules | Target Use Case |
|:---|:---:|:---|:---|
| **Quick** | 2-3 min | `FileSystemAudit`, `ProcessTriage` | Daily rapid health check of critical memory and file integrity. |
| **Standard** | 5-7 min | Quick + `PersistenceHunting` | Regular security audit covering persistence mechanisms. |
| **Deep** *(Default)* | 10-15 min | Standard + `DefenderAudit`, `FirewallAudit`, `NetworkAudit`, `SystemHardening`, `CryptoMinerDetection` | Comprehensive system audit across network, hardening, defender, and miner vectors. |
| **Forensic** | 20+ min | Deep + `BrowserAudit`, `ThreatIntelligence` + Verbose Logging | Full incident response investigation and forensic timeline audit. |

---

## API Route Specifications

| Method | Endpoint | Authorization | Description | Response Format |
|:---:|:---|:---:|:---|:---|
| `GET` | `/` | None | Serves `index.html` with injected `X-Audit-Token` meta tag | `text/html` |
| `GET` | `/api/start?mode=<Mode>` | `X-Audit-Token` | Initiates background audit job in specified mode | `application/json` |
| `GET` | `/api/stop` | `X-Audit-Token` | Terminates active audit background job | `application/json` |
| `GET` | `/api/status` | `X-Audit-Token` | Returns job status, elapsed time, and buffered logs | `application/json` |
| `GET` | `/api/open-report` | `X-Audit-Token` | Returns URL to latest generated HTML report | `application/json` |
| `GET` | `/Reports/<Folder>/<File>` | `X-Audit-Token` | Serves report assets safely (path contained) | `text/html`, `application/json`, etc. |

---

## Testing & Quality Assurance Architecture

The framework incorporates an automated unit testing suite powered by **Pester** (v4/v5 compatible), invoked via [`Run-Tests.ps1`](./Run-Tests.ps1).

```
Tests/
|-- Core.tests.ps1         # Validates state, finding creation, & risk formula
|-- Forensic.tests.ps1     # Validates HOSTS parser & PUP keyword matcher
`-- Persistence.tests.ps1  # Validates registry autoruns & task scanners
```

Continuous integration is enforced via **GitHub Actions** ([`.github/workflows/test.yml`](./.github/workflows/test.yml)) on every push and pull request.
