@echo off
title Windows Security Audit Framework - Server
color 0B

set PORT=8080
if not "%~1"=="" set PORT=%~1

echo.
echo ====================================================================
echo   Windows Security Audit Framework v5.5.0 (Web Edition)
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

echo Starting Audit Server on Port %PORT%...
echo.
echo NOTE: Do not close this window while using the dashboard.
echo.

REM Launch the backend server with RemoteSigned policy
start "Audit Backend" powershell.exe -ExecutionPolicy RemoteSigned -Command "Unblock-File '%~dp0AuditServer.ps1'; & '%~dp0AuditServer.ps1' -Port %PORT%"

REM Wait a moment for server to spin up
timeout /t 3 >nul

REM Open the UI in default browser
start http://localhost:%PORT%

exit /b 0