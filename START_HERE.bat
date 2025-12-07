@echo off
title Windows Security Audit Framework - Launcher
color 0B

echo.
echo ====================================================================
echo   Windows Security Audit Framework v5.1
echo   Easy Launcher
echo ====================================================================
echo.
echo Starting GUI Application...
echo.

REM Check if PowerShell exists
where powershell >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: PowerShell not found!
    echo Please ensure PowerShell is installed.
    pause
    exit /b 1
)

REM Launch the GUI
powershell.exe -ExecutionPolicy Bypass -File "%~dp0SecurityAuditGUI.ps1"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Failed to launch the GUI application.
    echo.
    echo Troubleshooting:
    echo   1. Make sure all files are in the same folder
    echo   2. Right-click this file and "Run as Administrator"
    echo   3. Check that SecurityAuditGUI.ps1 exists
    echo.
    pause
)

exit /b 0
pause