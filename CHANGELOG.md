# Changelog

All notable changes to the Windows Security Audit Framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.5.0] - 2026-08-11

### Added
- **Signatures Section in `Config.psd1`**: Centralized all threat signatures (miner names, pool URLs, RAT ports, ransomware extensions, keylogger patterns) so users can update signatures without editing source code.
- **VirusTotal Integration**: Hash-checks suspicious files against the VirusTotal v3 API when `VirusTotalAPIKey` is provided in `Config.psd1`.
- **Structured Access Logging**: Added access log output in `AuditServer.ps1` to track incoming HTTP requests.
- **Orphaned Job Cleanup**: `AuditServer.ps1` automatically cleans up background jobs from previous sessions on startup.
- **PSScriptAnalyzer Configuration**: Added linter settings and integrated static analysis into GitHub Actions CI workflow.
- **Open Source Documentation**: Added `CONTRIBUTING.md`, `SECURITY.md`, `AUTHORS.md`, `CHANGELOG.md`, and `.editorconfig`.

### Security
- **CORS Scope Restriction**: Restricted `Access-Control-Allow-Origin` headers in `AuditServer.ps1` from wildcard (`*`) to explicit `localhost` origins only.
- **Token Masking**: Removed plaintext logging of session security tokens to the console.
- **Safe JSON Construction**: Replaced string-interpolated JSON in `AuditServer.ps1` with `ConvertTo-Json`.
- **Report XSS Hardening**: Replaced inline `onclick` handlers in generated HTML reports with secure `data-cmd` attributes and delegated event handling.

### Fixed
- Fixed missing `using module .\Core.psm1` in `ProcessTriage.psm1`.
- Fixed duplicate finding ID (`Miner_CPU_Clean`) in `CryptoMinerDetection.psm1`.
- Standardized version strings across all files to `v5.5.0`.
- Switched `$script:Findings` array accumulation in `Core.psm1` to `System.Collections.Generic.List` for O(1) appending.
