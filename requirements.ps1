#requires -version 5.1
[CmdletBinding()]
param(
    [switch]$SkipNpcap
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Requirements = Join-Path $ScriptDir 'requirements.txt'
$AppScript = Join-Path $ScriptDir 'firewall_monitor.py'
$TempDir = Join-Path $env:TEMP 'PyFirewallPrerequisites'
$PythonVersion = [Version]'3.14.7'
$NpcapUrl = 'https://npcap.com/dist/npcap-1.89.exe'

function Write-Step([string]$Message) {
    Write-Host "`n== $Message ==" -ForegroundColor Cyan
}

function Write-OK([string]$Message) {
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-WarnMsg([string]$Message) {
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Read-YesNo([string]$Prompt, [bool]$DefaultYes = $true) {
    $suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $answer = (Read-Host "$Prompt $suffix").Trim()
        if ([string]::IsNullOrWhiteSpace($answer)) { return $DefaultYes }
        switch ($answer.ToLowerInvariant()) {
            'y' { return $true }
            'yes' { return $true }
            'n' { return $false }
            'no' { return $false }
        }
        Write-Host 'Please type y then press Enter, or n then press Enter.' -ForegroundColor Yellow
    }
}

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    $admin = [Security.Principal.WindowsBuiltInRole]::Administrator
    if ($principal.IsInRole($admin)) { return }

    Write-Host 'Requesting Administrator privileges...' -ForegroundColor Yellow
    $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    if ($SkipNpcap) { $args += '-SkipNpcap' }
    $elevated = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $args -Wait -PassThru
    exit $elevated.ExitCode
}

function Get-NativeArchitecture {
    if ($env:PROCESSOR_ARCHITEW6432) { return $env:PROCESSOR_ARCHITEW6432.ToUpperInvariant() }
    return $env:PROCESSOR_ARCHITECTURE.ToUpperInvariant()
}

function Get-UsablePython {
    $paths = [System.Collections.Generic.List[string]]::new()
    $roots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:LocalAppData
    ) | Where-Object { $_ }

    foreach ($root in $roots) {
        foreach ($name in 'Python314','Python313','Python312','Python311','Python310','Python39','Python38') {
            $paths.Add((Join-Path (Join-Path $root $name) 'python.exe'))
            $paths.Add((Join-Path (Join-Path (Join-Path $root 'Programs\Python') $name) 'python.exe'))
        }
    }

    foreach ($cmdName in 'python.exe','py.exe') {
        $cmd = Get-Command $cmdName -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source) { $paths.Add($cmd.Source) }
    }

    foreach ($python in ($paths | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $python)) { continue }
        try {
            $probe = & $python -c "import sys, tkinter; print(sys.executable); print('.'.join(map(str, sys.version_info[:3])))" 2>$null
            if ($LASTEXITCODE -ne 0 -or $probe.Count -lt 2) { continue }
            $version = [Version]$probe[1]
            if ($version -lt [Version]'3.8') { continue }
            & $python -m pip --version *> $null
            if ($LASTEXITCODE -eq 0) {
                return [PSCustomObject]@{ Path = $python; Version = $version }
            }
        } catch { }
    }
    return $null
}

function Install-Python {
    $arch = Get-NativeArchitecture
    $info = switch ($arch) {
        'AMD64' {
            @{ Url='https://www.python.org/ftp/python/3.14.7/python-3.14.7-amd64.exe'; Hash='9D9EB2709EF81BF5CD30DB3C2096BDBC4EA10087C22E62F27D356B36F6AE9649' }
            break
        }
        'ARM64' {
            @{ Url='https://www.python.org/ftp/python/3.14.7/python-3.14.7-arm64.exe'; Hash='9A3FE120CC81BC2CB099550F794D8356811F96A86C7F438519243C3485DB928D' }
            break
        }
        'X86' {
            @{ Url='https://www.python.org/ftp/python/3.14.7/python-3.14.7.exe'; Hash='097FC03D4AC2DE66EE1D73A0C5D2D323B5C0F14923F7207686CE93149A80F0A6' }
            break
        }
        default { throw "Unsupported CPU architecture: $arch" }
    }

    $installer = Join-Path $TempDir ([IO.Path]::GetFileName($info.Url))
    Invoke-WebRequest -Uri $info.Url -OutFile $installer -UseBasicParsing

    $actualHash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash
    if ($actualHash -ne $info.Hash) {
        Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
        throw "Python installer SHA-256 validation failed. Expected $($info.Hash), got $actualHash."
    }

    $signature = Get-AuthenticodeSignature -FilePath $installer
    if ($signature.Status -ne 'Valid') {
        throw "Python installer signature validation failed: $($signature.Status)."
    }

    Write-Host "Installing Python $PythonVersion for all users..." -ForegroundColor Gray
    $args = @(
        '/quiet',
        'InstallAllUsers=1',
        'PrependPath=1',
        'Include_pip=1',
        'Include_tcltk=1',
        'Include_launcher=1',
        'InstallLauncherAllUsers=1',
        'Include_test=0',
        'Include_doc=0',
        'AssociateFiles=1'
    )
    $process = Start-Process -FilePath $installer -ArgumentList $args -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Python installer returned exit code $($process.ExitCode)."
    }

    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
}

function Get-PythonPackageStatus([string]$PythonExe, [string]$ModuleName, [Version]$MinimumVersion, [Version]$MaximumExclusive) {
    try {
        $result = @(& $PythonExe -c "import importlib.metadata as m; print(m.version('$ModuleName'))" 2>$null)
        if ($LASTEXITCODE -ne 0 -or $result.Count -lt 1) {
            return [PSCustomObject]@{ Installed=$false; Version=$null }
        }

        $versionText = [string]$result[0]
        if ([string]::IsNullOrWhiteSpace($versionText)) {
            return [PSCustomObject]@{ Installed=$false; Version=$null }
        }

        $version = [Version]$versionText.Trim()
        $valid = ($version -ge $MinimumVersion) -and ($version -lt $MaximumExclusive)
        return [PSCustomObject]@{ Installed=$valid; Version=$version }
    } catch {
        return [PSCustomObject]@{ Installed=$false; Version=$null }
    }
}

function Install-PythonPackage([string]$PythonExe, [string]$PackageSpec, [string]$DisplayName) {
    Write-Host "Installing $DisplayName..." -ForegroundColor Gray
    & $PythonExe -m pip install --disable-pip-version-check --upgrade $PackageSpec
    if ($LASTEXITCODE -ne 0) {
        throw "pip failed while installing $DisplayName (exit code $LASTEXITCODE)."
    }
    Write-OK "$DisplayName installed."
}

function Get-NpcapInstall {
    $candidate = Join-Path ${env:ProgramFiles} 'Npcap\NPFInstall.exe'
    if (Test-Path -LiteralPath $candidate) {
        $version = (Get-Item -LiteralPath $candidate).VersionInfo.FileVersion
        return [PSCustomObject]@{ Path=$candidate; Version=$version }
    }
    return $null
}

function Install-Npcap {
    if ($SkipNpcap) {
        Write-WarnMsg 'Npcap installation was skipped by -SkipNpcap.'
        return $false
    }

    $installer = Join-Path $TempDir 'npcap-1.89.exe'
    Write-Host 'Downloading Npcap 1.89 from the official Npcap site...' -ForegroundColor Gray
    Invoke-WebRequest -Uri $NpcapUrl -OutFile $installer -UseBasicParsing

    $signature = Get-AuthenticodeSignature -FilePath $installer
    if ($signature.Status -ne 'Valid') {
        throw "Npcap installer signature validation failed: $($signature.Status)."
    }

    Write-Host 'Launching Npcap installer with Scapy-compatible settings.' -ForegroundColor Gray
    Write-WarnMsg 'The free Npcap installer is not silently installable; complete its normal installer window when it appears.'
    $args = @('/winpcap_mode=no', '/loopback_support=no', '/admin_only=no', '/require_features')
    $process = Start-Process -FilePath $installer -ArgumentList $args -Wait -PassThru
    if ($process.ExitCode -notin @(0,3010)) {
        throw "Npcap installer returned exit code $($process.ExitCode)."
    }

    Start-Sleep -Seconds 2
    $existing = Get-NpcapInstall
    if (-not $existing) {
        throw 'Npcap installation could not be verified after the installer completed.'
    }
    return $true
}

function Ensure-Service([string]$Name, [string]$FriendlyName) {
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service) { throw "$FriendlyName service ($Name) was not found." }
    if ($service.StartType -eq 'Disabled') {
        Set-Service -Name $Name -StartupType Automatic
    }
    if ($service.Status -ne 'Running') {
        Start-Service -Name $Name
    }
    (Get-Service -Name $Name).WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
    Write-OK "$FriendlyName service is running."
}

function Register-PyFirewallScheduledTask([string]$PythonExe, [string]$ScriptPath, [string]$WorkingDirectory) {
    $taskName = 'PyFirewall - At Login'
    if (-not (Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue)) {
        throw 'Windows Scheduled Tasks management is unavailable on this system.'
    }
    if (-not (Test-Path -LiteralPath $PythonExe)) {
        throw "Python executable for Scheduled Task was not found: $PythonExe"
    }

    $userId = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $action = New-ScheduledTaskAction -Execute $PythonExe -Argument ('"{0}"' -f $ScriptPath) -WorkingDirectory $WorkingDirectory
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
    $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -Compatibility Win8 `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew

    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description 'Starts PyFirewall automatically when the installing Windows user logs on.' `
        -Force | Out-Null

    $registered = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (-not $registered) {
        throw 'The PyFirewall scheduled task could not be verified after registration.'
    }
    Write-OK "Scheduled Task configured: $taskName (At Login, Highest privileges)."
}

function Remove-PyFirewallScheduledTask {
    $taskName = 'PyFirewall - At Login'
    $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-OK 'PyFirewall will not start automatically at login.'
    } else {
        Write-OK 'PyFirewall startup-at-login was not configured.'
    }
}

try {
    Assert-Admin
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

    Write-Step 'Checking Windows'
    $os = Get-CimInstance Win32_OperatingSystem
    if ($os.Caption -notmatch '^Microsoft Windows (10|11)') {
        throw "This installer supports Windows 10 and Windows 11 only. Detected: $($os.Caption)."
    }
    $isWin10 = $os.Caption -match 'Windows 10'
    if ($isWin10) {
        Write-WarnMsg 'Windows 10 reached Microsoft general end of support on October 14, 2025. Verify your security-update/ESU status.'
    }
    Write-OK "$($os.Caption) detected ($($os.Version), build $($os.BuildNumber))."
    Write-OK "CPU architecture: $(Get-NativeArchitecture)."

    if (-not (Test-Path -LiteralPath $Requirements)) {
        throw "requirements.txt was not found beside this installer: $Requirements"
    }
    if (-not (Test-Path -LiteralPath $AppScript)) {
        throw "firewall_monitor.py was not found beside this installer: $AppScript"
    }

    Write-Step 'Checking Python and Tkinter'
    $python = Get-UsablePython
    if ($python) {
        Write-OK "Python $($python.Version) found at $($python.Path)."
    } else {
        Write-WarnMsg 'No usable Python 3.8+ installation with Tkinter and pip was found.'
        if (-not (Read-YesNo 'Python is required for PyFirewall. Install Python 3.14.7?')) {
            throw 'Python installation was declined. PyFirewall cannot be installed without Python.'
        }
        Install-Python
        $python = Get-UsablePython
        if (-not $python) { throw 'Python installation completed, but a usable interpreter could not be located.' }
        Write-OK "Python $($python.Version) ready at $($python.Path)."
    }

    Write-Step 'Checking Python packages'
    $psutil = Get-PythonPackageStatus $python.Path 'psutil' ([Version]'5.9.0') ([Version]'8.0.0')
    if ($psutil.Installed) {
        Write-OK "psutil $($psutil.Version) is already installed."
    } else {
        $psutilAction = Read-YesNo 'psutil is required and is not installed in the expected version range. Install/upgrade psutil?'
        if ($psutilAction) {
            Install-PythonPackage $python.Path 'psutil>=5.9.0,<8.0' 'psutil'
            $psutil = Get-PythonPackageStatus $python.Path 'psutil' ([Version]'5.9.0') ([Version]'8.0.0')
        } else {
            Write-WarnMsg 'psutil installation was declined.'
        }
    }

    $scapy = Get-PythonPackageStatus $python.Path 'scapy' ([Version]'2.5.0') ([Version]'3.0.0')
    if ($scapy.Installed) {
        Write-OK "Scapy $($scapy.Version) is already installed."
    } else {
        $scapyAction = Read-YesNo 'Scapy is required and is not installed in the expected version range. Install/upgrade Scapy?'
        if ($scapyAction) {
            Install-PythonPackage $python.Path 'scapy>=2.5.0,<3.0' 'Scapy'
            $scapy = Get-PythonPackageStatus $python.Path 'scapy' ([Version]'2.5.0') ([Version]'3.0.0')
        } else {
            Write-WarnMsg 'Scapy installation was declined.'
        }
    }

    if (-not $psutil.Installed -or -not $scapy.Installed) {
        throw 'One or more required Python packages are missing. PyFirewall was not launched. Re-run the installer and allow the missing package(s).'
    }

    Write-Step 'Checking Npcap'
    $npcap = Get-NpcapInstall
    if ($npcap) {
        Write-OK "Npcap is already installed ($($npcap.Version))."
        $npcapInstalled = $true
    } else {
        $npcapAction = Read-YesNo 'Npcap is needed for Scapy packet capture. Install Npcap?'
        if ($npcapAction) {
            $npcapInstalled = Install-Npcap
            if ($npcapInstalled) {
                $npcap = Get-NpcapInstall
                Write-OK "Npcap detected at $($npcap.Path)."
            }
        } else {
            $npcapInstalled = $false
            Write-WarnMsg 'Npcap installation was declined. Packet-capture features may not function.'
        }
    }

    if ($npcapInstalled) {
        $npcapService = Get-Service -Name npcap -ErrorAction SilentlyContinue
        if ($npcapService -and $npcapService.Status -ne 'Running') {
            Start-Service -Name npcap -ErrorAction Stop
        }
        if ($npcapService) { Write-OK 'Npcap driver service is available.' }
    }

    Write-Step 'Checking Windows Defender Firewall'
    Ensure-Service 'mpssvc' 'Windows Defender Firewall'
    try {
        & powershell.exe -NoProfile -Command "Get-NetFirewallProfile | Out-Null"
        if ($LASTEXITCODE -ne 0) { throw 'Get-NetFirewallProfile failed.' }
        Write-OK 'Windows Firewall PowerShell management is available.'
    } catch {
        Write-WarnMsg "Windows Firewall PowerShell check failed: $($_.Exception.Message)"
    }

    Write-Step 'Final dependency test'
    & $python.Path -c "import tkinter, psutil, scapy.all as scapy; print('Tkinter:', tkinter.TkVersion); print('psutil:', psutil.__version__); print('Scapy:', scapy.conf.version)"
    if ($LASTEXITCODE -ne 0) { throw 'The final Python import test failed.' }
    Write-OK 'Tkinter, psutil, and Scapy imported successfully.'

    Write-Step 'Creating desktop shortcut'

    $desktop = [Environment]::GetFolderPath('Desktop')
    $shortcutPath = Join-Path $desktop 'PyFirewall.lnk'
    $iconPath = Join-Path $ScriptDir 'PyFirewall.ico'
    $pythonw = Join-Path (Split-Path -Parent $python.Path) 'pythonw.exe'
    if (-not (Test-Path -LiteralPath $pythonw)) { $pythonw = $python.Path }

    if (-not (Test-Path -LiteralPath $pythonw)) {
        throw "Python executable was not found beside the verified Python interpreter: $pythonw"
    }

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $pythonw
    $shortcut.Arguments = '"' + $AppScript + '"'
    $shortcut.WorkingDirectory = $ScriptDir
    $shortcut.Description = 'PyFirewall - Python Personal Firewall & Network Monitor'
    if (Test-Path -LiteralPath $iconPath) {
        $shortcut.IconLocation = "$iconPath,0"
    }
    $shortcut.Save()
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut)
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
    Write-OK "Desktop shortcut created: $shortcutPath"

    Write-Step 'Startup at login'
    if (Read-YesNo 'Would you like PyFirewall to start automatically when you log in to Windows?') {
        Register-PyFirewallScheduledTask $pythonw $AppScript $ScriptDir
    } else {
        Remove-PyFirewallScheduledTask
    }

    Write-Step 'Launching PyFirewall'
    Write-Host 'Launching firewall_monitor.py...' -ForegroundColor White
    $process = Start-Process -FilePath $pythonw -ArgumentList @('"' + $AppScript + '"') -WorkingDirectory $ScriptDir -WindowStyle Hidden -PassThru -ErrorAction Stop
    Write-OK "PyFirewall launch requested (PID $($process.Id)). The application will request Administrator privileges if needed."

}
catch {
    Write-Host "`n[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Source files were not deleted or modified by this installer.' -ForegroundColor Gray
    exit 1
}
finally {
    Remove-Item -LiteralPath $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
