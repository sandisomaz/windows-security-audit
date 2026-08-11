# Contributing to Windows Security Audit Framework

Thank you for considering contributing to the Windows Security Audit Framework! We welcome bug reports, feature requests, module additions, and documentation improvements.

## Code of Conduct

Please help maintain a respectful, inclusive, and professional environment for all contributors.

## How Can I Contribute?

### 1. Adding New Audit Modules
Audit modules live in the `Modules/` directory as `.psm1` PowerShell module files.
- Each module must use `#Requires -Version 5.1`.
- Include standard module headers (`.SYNOPSIS`, `.DESCRIPTION`, `.NOTES`).
- Import `Core.psm1` using `using module .\Core.psm1` or `Import-Module $PSScriptRoot\Core.psm1`.
- Export your main entry point function using `Export-ModuleMember`.
- Always wrap external system calls in `Invoke-SafeCommand`.
- Register findings using `Add-AuditFinding`.
- Move any configurable signatures or threshold values into `Config.psd1` under the `Signatures` section.

### 2. Reporting Bugs & Requesting Features
- Open an Issue on GitHub.
- Describe the expected vs actual behavior clearly.
- Include OS version, PowerShell version (`$PSVersionTable.PSVersion`), and relevant log excerpts.

### 3. Pull Request Process
1. Fork the repository and create a feature branch (`git checkout -b feature/my-new-check`).
2. Make your changes and write unit tests in `Tests/`.
3. Run the test suite locally:
   ```powershell
   .\Run-Tests.ps1
   ```
4. Ensure all tests pass cleanly.
5. Submit a Pull Request targeting the `main` branch.

## Coding Style & Guidelines
- **Indentation**: 4 spaces (no tabs).
- **Encoding**: UTF-8 with BOM for `.ps1`/`.psm1` files.
- **Naming**: Use standard PowerShell `Verb-Noun` naming for all functions.
- **Zero Binary Dependency**: The framework must remain 100% native PowerShell and .NET. Do not introduce compiled binaries or third-party executable dependencies.
