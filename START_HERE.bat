@echo off
title Windows Security Audit Framework - Server
color 0B

set PORT=8765
if not "%~1"=="" set PORT=%~1

echo.
echo ====================================================================
echo   Windows Security Audit Framework
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
echo NOTE: Keep the background server window open while using the dashboard.
echo.

REM Launch the backend server with RemoteSigned policy
start "Audit Backend" powershell.exe -ExecutionPolicy RemoteSigned -Command "Unblock-File '%~dp0AuditServer.ps1'; & '%~dp0AuditServer.ps1' -Port %PORT%"

REM Wait a moment for server to spin up
timeout /t 2 >nul

REM Open the UI in Chrome if available, otherwise default browser
if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" (
    start "" "%ProgramFiles%\Google\Chrome\Application\chrome.exe" "http://localhost:%PORT%"
) else if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" (
    start "" "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" "http://localhost:%PORT%"
) else if exist "%LocalAppData%\Google\Chrome\Application\chrome.exe" (
    start "" "%LocalAppData%\Google\Chrome\Application\chrome.exe" "http://localhost:%PORT%"
) else (
    start http://localhost:%PORT%
)

exit /b 0