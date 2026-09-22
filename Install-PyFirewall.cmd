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
echo Starting PyFirewall prerequisite installer...
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
echo Creating PyFirewall desktop shortcut...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $appScript='%APP_SCRIPT%'; $icon='%ICON%'; $scriptDir=Split-Path -Parent $appScript; $desktop=[Environment]::GetFolderPath('Desktop'); $shortcutPath=Join-Path $desktop 'PyFirewall - Firewall & Network Monitor.lnk'; $python=$null; try { $python=(& py -3 -c 'import sys; print(sys.executable)' 2>$null | Select-Object -First 1).Trim() } catch {}; if (-not $python -or -not (Test-Path $python)) { $cmd=Get-Command python.exe -ErrorAction SilentlyContinue; if ($cmd) { $python=$cmd.Source } }; if (-not $python -or -not (Test-Path $python)) { throw 'Python 3 could not be located after prerequisite installation.' }; $pythonw=Join-Path (Split-Path -Parent $python) 'pythonw.exe'; if (-not (Test-Path $pythonw)) { throw ('pythonw.exe was not found beside ' + $python) }; $ws=New-Object -ComObject WScript.Shell; $sc=$ws.CreateShortcut($shortcutPath); $sc.TargetPath=$pythonw; $sc.Arguments='"' + $appScript + '"'; $sc.WorkingDirectory=$scriptDir; $sc.IconLocation=$icon + ',0'; $sc.Description='Python Personal Firewall & Network Monitor'; $sc.Save(); Write-Host ('Desktop shortcut created: ' + $shortcutPath)"
set "SHORTCUT_EXIT=%ERRORLEVEL%"

if not "%SHORTCUT_EXIT%"=="0" (
    echo.
    echo [WARNING] Prerequisites installed, but the desktop shortcut could not be created.
    echo You can run firewall_monitor.py manually from the install folder.
    echo.
    pause
    exit /b %SHORTCUT_EXIT%
)

echo.
echo ================================================================
echo PyFirewall installation completed successfully.
echo.
echo Desktop shortcut created:
echo PyFirewall - Firewall ^& Network Monitor
echo ================================================================
echo.
exit /b 0
