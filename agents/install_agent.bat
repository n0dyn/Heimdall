@echo off
setlocal

:: Double-click launcher for the Heimdall Windows installer.
:: Forwards arguments, for example:
::   install_agent.bat -ApiUrl http://HUB:8010 -ApiKey YOUR_KEY

NET SESSION >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Administrator privileges required. Requesting elevation...
    powershell -NoProfile -Command "Start-Process '%~f0' -ArgumentList '%*' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-HeimdallAgent.ps1" %*
echo.
pause
