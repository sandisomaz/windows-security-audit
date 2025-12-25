@echo off
title Windows Security Audit Framework - Server
color 0B

echo.
echo ====================================================================
echo   Windows Security Audit Framework v5.4 (Web Edition)
echo   Initializing Backend Engine...
echo ====================================================================
echo.

REM Check if PowerShell exists
where powershell >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: PowerShell not found!
    pause
    exit /b 1
)

echo Starting Audit Server on Port 8080...
echo.
echo NOTE: Do not close this window while using the dashboard.
echo.

REM Launch the backend server
start "Audit Backend" powershell.exe -ExecutionPolicy Bypass -File "%~dp0AuditServer.ps1"

REM Wait a moment for server to spin up
timeout /t 3 >nul

REM Open the UI in default browser
start http://localhost:8080

exit /b 0