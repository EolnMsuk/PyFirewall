@echo off
setlocal EnableExtensions


set "PYFW_UNINSTALL_FILE=%~f0"
set "PYFW_EXITCODE=0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$lines=Get-Content -LiteralPath $env:PYFW_UNINSTALL_FILE; $marker='# POWERSHELL START'; $index=-1; for($i=0;$i -lt $lines.Count;$i++){if($lines[$i] -eq $marker){$index=$i;break}}; if($index -lt 0){throw 'Embedded PowerShell section was not found.'}; & ([ScriptBlock]::Create(($lines[($index+1)..($lines.Count-1)] -join [Environment]::NewLine)))"
set "PYFW_EXITCODE=%ERRORLEVEL%"

echo.
if not "%PYFW_EXITCODE%"=="0" echo Uninstaller exited with code %PYFW_EXITCODE%.
pause
exit /b %PYFW_EXITCODE%

# POWERSHELL START
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host ''
    Write-Host 'Requesting Administrator privileges...' -ForegroundColor Yellow
    $self = $env:PYFW_UNINSTALL_FILE
    $child = Start-Process -FilePath 'cmd.exe' -Verb RunAs -ArgumentList @('/c', "`"$self`"") -Wait -PassThru
    exit $child.ExitCode
}

function Write-Step([string]$Message) {
    Write-Host "`n== $Message ==" -ForegroundColor Cyan
}

function Write-OK([string]$Message) {
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-WarnMsg([string]$Message) {
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-Info([string]$Message) {
    Write-Host "    $Message" -ForegroundColor Gray
}

function Ask-YesNo([string]$Question) {
    do {
        $answer = Read-Host "$Question [Y/N]"
        if ($answer -match '^(?i)y$') { return $true }
        if ($answer -match '^(?i)n$') { return $false }
        Write-WarnMsg 'Please type Y or N.'
    } while ($true)
}

function Get-UninstallEntries {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($path in $paths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.UninstallString }
    }
}

function Get-PythonEntry {
    Get-UninstallEntries |
        Where-Object { $_.DisplayName -match '^Python 3\.14\.7(?:\s|$)' } |
        Sort-Object { if ($_.PSPath -like 'Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE*') { 0 } else { 1 } } |
        Select-Object -First 1
}

function Get-PythonPath([object]$Entry) {
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($Entry.InstallLocation) {
        $candidates.Add((Join-Path $Entry.InstallLocation 'python.exe'))
    }
    $candidates.Add((Join-Path $env:ProgramFiles 'Python314\python.exe'))
    if ($env:LocalAppData) { $candidates.Add((Join-Path $env:LocalAppData 'Programs\Python\Python314\python.exe')) }
    foreach ($path in ($candidates | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $path) { return $path }
    }
    return $null
}

function Get-NpcapEntry {
    Get-UninstallEntries |
        Where-Object { $_.DisplayName -match '^Npcap(?:\s|$)' } |
        Sort-Object DisplayName -Descending |
        Select-Object -First 1
}

function Get-NpcapUninstaller([object]$Entry) {
    $candidates = @(
        (Join-Path $env:ProgramFiles 'Npcap\Uninstall.exe'),
        (Join-Path $env:ProgramFiles 'Npcap\uninstall.exe')
    )
    foreach ($path in $candidates) {
        if (Test-Path -LiteralPath $path) { return $path }
    }
    if ($Entry.UninstallString) {
        if ($Entry.UninstallString -match '^\s*"([^"]+)"') { return $matches[1] }
        if ($Entry.UninstallString -match '^\s*([^\s]+)') { return $matches[1] }
    }
    return $null
}

function Get-NormalizedUninstallCommand([string]$CommandLine) {
    if ($CommandLine -match '^\s*"([^"]+)"\s*(.*)$') {
        return [PSCustomObject]@{ File=$matches[1]; Arguments=$matches[2] }
    }
    if ($CommandLine -match '^\s*(\S+)\s*(.*)$') {
        return [PSCustomObject]@{ File=$matches[1]; Arguments=$matches[2] }
    }
    return $null
}

function Invoke-RegistryUninstaller([object]$Entry, [switch]$Npcap) {
    $command = Get-NormalizedUninstallCommand $Entry.UninstallString
    if (-not $command -or -not (Test-Path -LiteralPath $command.File)) {
        throw "Uninstaller could not be located for $($Entry.DisplayName)."
    }

    $args = $command.Arguments
    if ($Npcap) {
        if ($args -notmatch '(?i)(^|\s)/S(\s|$)') { $args = ($args + ' /S').Trim() }
        if ($args -notmatch '(?i)(^|\s)/Q(\s|$)') { $args = ($args + ' /Q').Trim() }
    }

    Write-Host "Running: $($command.File) $args" -ForegroundColor Gray
    $process = Start-Process -FilePath $command.File -ArgumentList $args -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010, 1641)) {
        throw "$($Entry.DisplayName) uninstaller returned exit code $($process.ExitCode)."
    }
}

function Get-PythonPackageInfo([string]$PythonPath) {
    if (-not $PythonPath) { return @() }
    try {
        $json = & $PythonPath -m pip list --format=json 2>$null
        if ($LASTEXITCODE -ne 0) { return @() }
        return ($json -join '' | ConvertFrom-Json) |
            Where-Object { $_.name -in @('psutil', 'scapy') }
    } catch {
        return @()
    }
}

function Get-PyFirewallRules {
    try {
        return @(
            Get-NetFirewallRule -ErrorAction Stop |
                Where-Object {
                    ([string]$_.DisplayName -like 'PyFirewall_*') -or
                    ([string]$_.Name -like 'PyFirewall_*')
                }
        )
    } catch {
        throw "Could not enumerate PyFirewall firewall rules: $($_.Exception.Message)"
    }
}

function Remove-PyFirewallFirewallRules {
    Write-Step 'Removing PyFirewall firewall rules'

    $rules = @(Get-PyFirewallRules)
    if ($rules.Count -eq 0) {
        Write-OK 'No PyFirewall-managed firewall rules were found.'
        return
    }

    $initialCount = $rules.Count
    foreach ($rule in $rules) {
        $removed = $false
        try {
            Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
            $removed = $true
        } catch {
            Write-WarnMsg "PowerShell removal failed for '$($rule.DisplayName)': $($_.Exception.Message)"
        }

        if (-not $removed) {
            foreach ($name in @([string]$rule.Name, [string]$rule.DisplayName) | Where-Object { $_ }) {
                try {
                    & netsh.exe advfirewall firewall delete rule "name=$name" | Out-Null
                    if ($LASTEXITCODE -eq 0) {
                        $removed = $true
                        break
                    }
                } catch {
                    # Try the next identifier before reporting failure.
                }
            }
        }

        if (-not $removed) {
            Write-WarnMsg "Could not remove firewall rule '$($rule.DisplayName)'."
        }
    }

    Start-Sleep -Milliseconds 500
    $remaining = @(Get-PyFirewallRules)

    if ($remaining.Count -gt 0) {
        Write-WarnMsg "$($remaining.Count) PyFirewall firewall rule(s) remain after the first cleanup pass. Retrying..."
        foreach ($rule in $remaining) {
            foreach ($name in @([string]$rule.Name, [string]$rule.DisplayName) | Where-Object { $_ }) {
                try {
                    & netsh.exe advfirewall firewall delete rule "name=$name" | Out-Null
                } catch {
                    # Verification below determines whether the retry succeeded.
                }
            }
        }
        Start-Sleep -Milliseconds 500
        $remaining = @(Get-PyFirewallRules)
    }

    if ($remaining.Count -gt 0) {
        $names = ($remaining | ForEach-Object { [string]$_.DisplayName }) -join ', '
        throw "$($remaining.Count) PyFirewall-managed firewall rule(s) could not be removed: $names"
    }

    Write-OK "Removed $initialCount PyFirewall-managed firewall rule(s)."
}

function Stop-PyFirewallProcesses {
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction Stop |
            Where-Object { $_.CommandLine -and $_.CommandLine -match '(?i)firewall_monitor\.py' }
        foreach ($process in $processes) {
            Write-WarnMsg "Stopping PyFirewall process $($process.ProcessId) before removing selected prerequisites."
            Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-WarnMsg "Could not inspect running processes: $($_.Exception.Message)"
    }
}

try {
    $desktop = [Environment]::GetFolderPath('Desktop')
    $shortcut = Join-Path $desktop 'PyFirewall - Firewall & Network Monitor.lnk'
    $legacyShortcut = Join-Path $desktop 'PyFirewall.lnk'
    $shortcutPaths = @($shortcut, $legacyShortcut) | Select-Object -Unique
    $taskName = 'PyFirewall - At Login'
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    $pythonEntry = Get-PythonEntry
    $pythonPath = Get-PythonPath $pythonEntry
    $packages = @(Get-PythonPackageInfo $pythonPath)
    $npcapEntry = Get-NpcapEntry
    $npcapUninstaller = if ($npcapEntry) { Get-NpcapUninstaller $npcapEntry } else { $null }
    $firewallRules = @(Get-PyFirewallRules)

    $hasPython = [bool]$pythonEntry
    $hasPackages = $packages.Count -gt 0
    $hasNpcap = [bool]$npcapEntry
    $existingShortcuts = @($shortcutPaths | Where-Object { Test-Path -LiteralPath $_ })
    $hasShortcut = $existingShortcuts.Count -gt 0
    $hasTask = [bool]$task
    $hasFirewallRules = $firewallRules.Count -gt 0

    Write-Step 'PyFirewall Uninstall Review'
    Write-Host 'Detected components:' -ForegroundColor White

    if ($hasFirewallRules) {
        Write-Host "  - PyFirewall-managed firewall rules: $($firewallRules.Count)" -ForegroundColor White
    }
    if ($hasTask) {
        Write-Host "  - Scheduled Task: $taskName" -ForegroundColor White
    }
    if ($hasShortcut) {
        foreach ($path in $existingShortcuts) {
            Write-Host ("  - Desktop shortcut: {0}" -f (Split-Path -Leaf $path)) -ForegroundColor White
        }
    }
    if ($hasPackages) {
        foreach ($package in $packages) {
            Write-Host "  - Python package: $($package.name) $($package.version)" -ForegroundColor White
        }
    }
    if ($hasNpcap) {
        Write-Host "  - $($npcapEntry.DisplayName)" -ForegroundColor White
    }
    if ($hasPython) {
        Write-Host "  - $($pythonEntry.DisplayName)" -ForegroundColor White
    }

    if (-not ($hasPython -or $hasPackages -or $hasNpcap -or $hasShortcut -or $hasTask -or $hasFirewallRules)) {
        Write-Host '  No removable PyFirewall components were detected.' -ForegroundColor Gray
        exit 0
    }

    Write-Host ''
    Write-Host 'Choose what to remove. Answer Y or N for each detected component.' -ForegroundColor White
    Write-Host 'Answering N keeps that component in place.' -ForegroundColor Gray
    Write-Host ''

    $removeFirewallRules = $false
    $removeTask = $false
    $removeShortcut = $false
    $removePython = $false
    $removeNpcap = $false
    $removePsutil = $false
    $removeScapy = $false

    if ($hasFirewallRules) {
        $removeFirewallRules = Ask-YesNo "Remove all $($firewallRules.Count) PyFirewall-managed Windows Firewall rule(s)?"
    }

    if ($hasTask) {
        $removeTask = Ask-YesNo "Remove the '$taskName' Scheduled Task?"
    }

    if ($hasShortcut) {
        $removeShortcut = Ask-YesNo 'Remove the PyFirewall desktop shortcut(s)?'
    }

    if ($hasPython) {
        Write-Host ''
        Write-Host 'Python is managed separately from the Python packages.' -ForegroundColor Gray
        Write-Host 'Choosing Y for Python will remove the detected Python 3.14.7 installation.' -ForegroundColor Gray
        $removePython = Ask-YesNo "Uninstall $($pythonEntry.DisplayName)?"

        if (-not $removePython -and $hasPackages) {
            $removePsutil = Ask-YesNo 'Uninstall the Python package psutil from the detected Python 3.14.7 environment?'
            $removeScapy = Ask-YesNo 'Uninstall the Python package scapy from the detected Python 3.14.7 environment?'
        } elseif ($removePython -and $hasPackages) {
            Write-Info 'Python 3.14.7 is selected for removal, so its psutil/scapy packages will be removed with that Python installation.'
        }
    }

    if ($hasNpcap) {
        Write-Host ''
        Write-Host 'Npcap may also be used by other network-analysis software.' -ForegroundColor Yellow
        $removeNpcap = Ask-YesNo "Uninstall $($npcapEntry.DisplayName)?"
    }

    if (-not ($removeFirewallRules -or $removeTask -or $removeShortcut -or $removePsutil -or $removeScapy -or $removeNpcap -or $removePython)) {
        Write-Host ''
        Write-Host 'No removals were selected. No changes were made.' -ForegroundColor Yellow
        exit 0
    }

    Write-Host ''
    Write-Host 'Selected removals:' -ForegroundColor White
    if ($removeFirewallRules) { Write-Host "  - PyFirewall-managed firewall rules ($($firewallRules.Count))" }
    if ($removeTask) { Write-Host "  - Scheduled Task: $taskName" }
    if ($removeShortcut) {
        foreach ($path in $existingShortcuts) {
            Write-Host ("  - Desktop shortcut: {0}" -f (Split-Path -Leaf $path))
        }
    }
    if ($removePsutil) { Write-Host '  - Python package: psutil' }
    if ($removeScapy) { Write-Host '  - Python package: scapy' }
    if ($removeNpcap) { Write-Host "  - $($npcapEntry.DisplayName)" }
    if ($removePython) { Write-Host "  - $($pythonEntry.DisplayName)" }
    Write-Host ''

    $needsProcessStop = $removeFirewallRules -or $removePsutil -or $removeScapy -or $removeNpcap -or $removePython
    if ($needsProcessStop) {
        Stop-PyFirewallProcesses
    }

    if ($removeFirewallRules) {
        Remove-PyFirewallFirewallRules
    }

    if ($removeTask) {
        Write-Step 'Removing scheduled task'
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
        Write-OK "Scheduled Task removed: $taskName"
    }

    if ($removeShortcut) {
        Write-Step 'Removing desktop shortcut(s)'
        $removedShortcutCount = 0
        foreach ($path in $shortcutPaths) {
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Force
                $removedShortcutCount++
                Write-OK ("Removed desktop shortcut: {0}" -f (Split-Path -Leaf $path))
            }
        }
        if ($removedShortcutCount -eq 0) {
            Write-WarnMsg 'No PyFirewall desktop shortcut was found at removal time.'
        }
    }

    if ($removePsutil -or $removeScapy) {
        Write-Step 'Removing selected Python packages'
        $packageNames = @()
        if ($removePsutil) { $packageNames += 'psutil' }
        if ($removeScapy) { $packageNames += 'scapy' }
        & $pythonPath -m pip uninstall -y @packageNames
        if ($LASTEXITCODE -ne 0) {
            Write-WarnMsg "pip returned exit code $LASTEXITCODE while removing selected packages."
        } else {
            Write-OK ("Removed selected Python package(s): " + ($packageNames -join ', '))
        }
    }

    if ($removeNpcap) {
        Write-Step "Uninstalling $($npcapEntry.DisplayName)"
        if ($npcapUninstaller -and (Split-Path -Leaf $npcapUninstaller) -match '(?i)^uninstall\.exe$') {
            $process = Start-Process -FilePath $npcapUninstaller -ArgumentList @('/S') -Wait -PassThru
            if ($process.ExitCode -notin @(0, 3010, 1641)) {
                throw "Npcap uninstaller returned exit code $($process.ExitCode)."
            }
        } else {
            Invoke-RegistryUninstaller $npcapEntry -Npcap
        }
        Write-OK 'Npcap uninstall requested.'
    }

    if ($removePython) {
        Write-Step "Uninstalling $($pythonEntry.DisplayName)"
        Invoke-RegistryUninstaller $pythonEntry
        Write-OK 'Python 3.14.7 uninstall requested.'
    }

    Write-Step 'Verification'

    Start-Sleep -Seconds 2

    if ($hasFirewallRules) {
        $remainingFirewallRules = @(Get-PyFirewallRules)
        if ($removeFirewallRules) {
            if ($remainingFirewallRules.Count -gt 0) {
                Write-WarnMsg "$($remainingFirewallRules.Count) PyFirewall-managed firewall rule(s) are still present."
            } else {
                Write-OK 'PyFirewall-managed firewall rules selected for removal are gone.'
            }
        } elseif ($remainingFirewallRules.Count -eq $firewallRules.Count) {
            Write-OK "PyFirewall-managed firewall rules were kept ($($firewallRules.Count) remain)."
        } else {
            Write-WarnMsg 'The firewall-rule count changed even though removal was not selected.'
        }
    }

    $remainingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($removeTask) {
        if ($remainingTask) {
            Write-WarnMsg "Scheduled Task '$taskName' is still registered."
        } else {
            Write-OK 'PyFirewall scheduled task selected for removal is gone.'
        }
    } elseif ($hasTask -and $remainingTask) {
        Write-OK "Scheduled Task '$taskName' was kept."
    }

    $remainingShortcuts = @($shortcutPaths | Where-Object { Test-Path -LiteralPath $_ })
    if ($removeShortcut) {
        if ($remainingShortcuts.Count -gt 0) {
            $names = ($remainingShortcuts | ForEach-Object { Split-Path -Leaf $_ }) -join ', '
            Write-WarnMsg ("The following PyFirewall desktop shortcut(s) could not be verified as removed: {0}" -f $names)
        } else {
            Write-OK 'PyFirewall desktop shortcut(s) selected for removal are gone.'
        }
    } elseif ($hasShortcut -and $remainingShortcuts.Count -gt 0) {
        Write-OK 'PyFirewall desktop shortcut(s) were kept.'
    }

    if ($removePython) {
        $remainingPython = Get-PythonEntry
        if ($remainingPython) {
            Write-WarnMsg "$($remainingPython.DisplayName) is still registered. A restart may be required, or the uninstall may have been cancelled by Windows."
        } else {
            Write-OK 'Python 3.14.7 selected for removal is no longer registered.'
        }
    } elseif ($hasPython) {
        Write-OK 'Python 3.14.7 was kept.'
    }

    if ($removeNpcap) {
        $remainingNpcap = Get-NpcapEntry
        if ($remainingNpcap) {
            Write-WarnMsg "$($remainingNpcap.DisplayName) is still registered. A restart may be required."
        } else {
            Write-OK 'Npcap selected for removal is no longer registered.'
        }
    } elseif ($hasNpcap) {
        Write-OK 'Npcap was kept.'
    }

    Write-Host ''
    Write-Host 'PyFirewall uninstall selections have been processed.' -ForegroundColor Green
    Write-Host 'PyFirewall source/project files, including PyFirewall.ico, were not deleted by this script.' -ForegroundColor Green
    exit 0
}
catch {
    Write-Host "`n[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
