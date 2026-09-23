@echo off
setlocal EnableExtensions

set "SCRIPT=%~dp0requirements.ps1"
set "APP_SCRIPT=%~dp0firewall_monitor.py"
set "ICON=%~dp0PyFirewall.ico"

if not exist "%SCRIPT%" (
    echo.
    echo [ERROR] requirements.ps1 was not found beside this installer.
    echo Expected: "%SCRIPT%"
    echo.
    pause
    exit /b 2
)

if not exist "%APP_SCRIPT%" (
    echo.
    echo [ERROR] firewall_monitor.py was not found beside this installer.
    echo Expected: "%APP_SCRIPT%"
    echo.
    pause
    exit /b 2
)

if not exist "%ICON%" (
    echo.
    echo [ERROR] PyFirewall.ico was not found beside this installer.
    echo Expected: "%ICON%"
    echo.
    pause
    exit /b 2
)

for /f "delims=" %%A in ('powershell.exe -NoProfile -Command "$p=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent(); $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)" 2^>nul') do set "ISADMIN=%%A"

if /I not "%ISADMIN%"=="True" (
    echo.
    echo ================================================================
    echo Administrator privileges are required for the PyFirewall installer.
    echo.
    echo Please run the Install-PyFirewall.cmd as admin by right clicking
    echo and selecting Run as Administrator.
    echo ================================================================
    echo.
    pause
    exit /b 740
)

echo.
echo Starting PyFirewall installer...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
set "EXITCODE=%ERRORLEVEL%"

if not "%EXITCODE%"=="0" (
    echo.
    echo Installer exited with code %EXITCODE%.
    echo.
    pause
    exit /b %EXITCODE%
)

echo.
echo ================================================================
echo PyFirewall installation completed successfully.
echo.
echo Desktop shortcut created:
echo PyFirewall
echo ================================================================
echo.
exit /b 0
