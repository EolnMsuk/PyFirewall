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
$ScriptDir = Split-Path -Parent $PYFW_UNINSTALL_FILE
$InstallMetadataFile = Join-Path $ScriptDir 'pyfirewall_install.json'
$FirewallProfileBackupFile = Join-Path $ScriptDir 'firewall_profile_backup.json'

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

function Get-PyFirewallInstallMetadata {
    if (-not (Test-Path -LiteralPath $InstallMetadataFile)) { return $null }
    try {
        return Get-Content -LiteralPath $InstallMetadataFile -Raw -ErrorAction Stop | ConvertFrom-Json
    } catch {
        Write-WarnMsg "PyFirewall installation metadata could not be read: $($_.Exception.Message)"
        return $null
    }
}

function Get-PythonPath([object]$Entry, [string]$PreferredPath = $null) {
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($PreferredPath) { $candidates.Add($PreferredPath) }
    if ($Entry -and $Entry.InstallLocation) {
        $candidates.Add((Join-Path $Entry.InstallLocation 'python.exe'))
    }
    foreach ($path in ($candidates | Select-Object -Unique)) {
        if ($path -and (Test-Path -LiteralPath $path)) { return $path }
    }
    return $null
}

function Get-PythonEntry([string]$PreferredPath = $null) {
    $entries = @(Get-UninstallEntries | Where-Object {
        $_.DisplayName -match '^Python\s+\d+\.\d+\.\d+(?:\s|$)' -and
        $_.DisplayName -notmatch '(?i)(Documentation|Development|Debug|Test Suite|Examples|Tools|Tcl/Tk)'
    })

    if ($PreferredPath) {
        $preferred = [System.IO.Path]::GetFullPath($PreferredPath)
        foreach ($entry in $entries) {
            $candidate = Get-PythonPath $entry
            if ($candidate) {
                try {
                    if ([string]::Equals([System.IO.Path]::GetFullPath($candidate), $preferred, [StringComparison]::OrdinalIgnoreCase)) {
                        return $entry
                    }
                } catch { }
            }
        }
        return $null
    }

    $entries | Sort-Object @{Expression={
        $match = [regex]::Match([string]$_.DisplayName, '\d+\.\d+\.\d+')
        if ($match.Success) { try { [Version]$match.Value } catch { [Version]'0.0' } } else { [Version]'0.0' }
    }; Descending=$true}, @{Expression={ if ($_.PSPath -like 'Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE*') { 0 } else { 1 } }; Ascending=$true} | Select-Object -First 1
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
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    if ($CommandLine -match '^\s*"([^"]+)"\s*(.*)$') {
        $file = $matches[1]
        $args = $matches[2]
    } elseif ($CommandLine -match '^\s*(\S+)\s*(.*)$') {
        $file = $matches[1]
        $args = $matches[2]
    } else {
        return $null
    }

    if (-not (Test-Path -LiteralPath $file)) {
        $resolved = Get-Command $file -ErrorAction SilentlyContinue
        if ($resolved) { $file = $resolved.Source }
    }
    return [PSCustomObject]@{ File=$file; Arguments=$args }
}

function Invoke-RegistryUninstaller([object]$Entry, [switch]$Npcap) {
    $rawCommand = if ($Entry.QuietUninstallString) { [string]$Entry.QuietUninstallString } else { [string]$Entry.UninstallString }
    $command = Get-NormalizedUninstallCommand $rawCommand
    if (-not $command -or -not (Test-Path -LiteralPath $command.File)) {
        throw "Uninstaller could not be located for $($Entry.DisplayName)."
    }

    $args = $command.Arguments
    $commandName = Split-Path -Leaf $command.File
    if ($commandName -match '(?i)^msiexec(?:\.exe)?$') {
        if ($args -match '(?i)(^|\s)/I(?=\s*\{[0-9A-F-]+\})') {
            $args = [regex]::Replace($args, '(?i)(^|\s)/I(?=\s*\{[0-9A-F-]+\})', '$1/X')
        } elseif ($args -notmatch '(?i)(^|\s)/X(\s|$)') {
            $product = [regex]::Match($args, '\{[0-9A-F-]+\}')
            if ($product.Success) { $args = "/X $($product.Value)" }
        }
    }

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

function Get-PyFirewallFirewallProfileBackup {
    if (-not (Test-Path -LiteralPath $FirewallProfileBackupFile)) { return $null }
    try {
        $backup = Get-Content -LiteralPath $FirewallProfileBackupFile -Raw -ErrorAction Stop | ConvertFrom-Json
        if (-not $backup.profiles) { throw 'The backup contains no firewall profiles.' }
        return $backup
    } catch {
        Write-WarnMsg "PyFirewall firewall-profile backup could not be read: $($_.Exception.Message)"
        return $null
    }
}

function Get-CurrentPyFirewallFirewallProfiles {
    return @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction)
}

function Restore-PyFirewallFirewallProfileState([object]$Backup) {
    if (-not $Backup) {
        Write-WarnMsg 'No valid PyFirewall firewall-profile backup was found; profile defaults were not changed.'
        return $false
    }

    Write-Step 'Restoring Windows Firewall profile state'
    $current = @(Get-CurrentPyFirewallFirewallProfiles)
    $restoredNames = @()
    $skippedNames = @()

    foreach ($saved in @($Backup.profiles)) {
        $name = [string]$saved.name
        $currentProfile = $current | Where-Object { [string]$_.Name -eq $name } | Select-Object -First 1
        if (-not $currentProfile) {
            Write-WarnMsg "Firewall profile '$name' no longer exists; it was not restored."
            $skippedNames += $name
            continue
        }

        $stillPyFirewallState = ([bool]$currentProfile.Enabled) -and
            ([string]$currentProfile.DefaultInboundAction -eq 'Allow') -and
            ([string]$currentProfile.DefaultOutboundAction -eq 'Allow')
        if (-not $stillPyFirewallState) {
            Write-WarnMsg "Firewall profile '$name' differs from the state PyFirewall set. Leaving the current state unchanged."
            $skippedNames += $name
            continue
        }

        Set-NetFirewallProfile `
            -Name $name `
            -Enabled ([bool]$saved.enabled) `
            -DefaultInboundAction ([string]$saved.default_inbound_action) `
            -DefaultOutboundAction ([string]$saved.default_outbound_action) `
            -ErrorAction Stop
        $restoredNames += $name
        Write-OK "Restored firewall profile '$name'."
    }

    $verified = @(Get-CurrentPyFirewallFirewallProfiles)
    foreach ($name in $restoredNames) {
        $saved = @($Backup.profiles | Where-Object { [string]$_.name -eq $name }) | Select-Object -First 1
        $actual = $verified | Where-Object { [string]$_.Name -eq $name } | Select-Object -First 1
        if (-not $actual -or
            ([bool]$actual.Enabled -ne [bool]$saved.enabled) -or
            ([string]$actual.DefaultInboundAction -ne [string]$saved.default_inbound_action) -or
            ([string]$actual.DefaultOutboundAction -ne [string]$saved.default_outbound_action)) {
            throw "Firewall profile '$name' could not be verified after restoration."
        }
    }

    if ($skippedNames.Count -eq 0 -and $restoredNames.Count -gt 0) {
        Remove-Item -LiteralPath $FirewallProfileBackupFile -Force -ErrorAction Stop
        Write-OK 'PyFirewall firewall-profile backup removed after successful restoration.'
    } elseif ($skippedNames.Count -gt 0) {
        Write-WarnMsg 'The firewall-profile backup was retained because one or more profiles were skipped or could not be restored.'
    }
    return $skippedNames.Count -eq 0
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
    $installMetadata = Get-PyFirewallInstallMetadata
    $preferredPythonPath = if ($installMetadata) { [string]$installMetadata.python_path } else { $null }
    $pythonEntry = Get-PythonEntry $preferredPythonPath
    $pythonPath = Get-PythonPath $pythonEntry $preferredPythonPath
    $packages = @(Get-PythonPackageInfo $pythonPath)
    $npcapEntry = Get-NpcapEntry
    $npcapUninstaller = if ($npcapEntry) { Get-NpcapUninstaller $npcapEntry } else { $null }
    $firewallRules = @(Get-PyFirewallRules)

    $pythonInstalledByPyFirewall = [bool]($installMetadata -and $installMetadata.python_installed_by_pyfirewall)
    $psutilInstalledByPyFirewall = [bool]($installMetadata -and $installMetadata.psutil_installed_by_pyfirewall)
    $scapyInstalledByPyFirewall = [bool]($installMetadata -and $installMetadata.scapy_installed_by_pyfirewall)
    $hasPython = [bool]$pythonPath -or [bool]$pythonEntry
    $hasPackages = $packages.Count -gt 0
    $hasNpcap = [bool]$npcapEntry
    $existingShortcuts = @($shortcutPaths | Where-Object { Test-Path -LiteralPath $_ })
    $hasShortcut = $existingShortcuts.Count -gt 0
    $hasTask = [bool]$task
    $hasFirewallRules = $firewallRules.Count -gt 0
    $firewallProfileBackup = Get-PyFirewallFirewallProfileBackup
    $hasFirewallProfileBackup = [bool]$firewallProfileBackup

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
        $pythonLabel = if ($pythonEntry) { [string]$pythonEntry.DisplayName } else { "Python interpreter at $pythonPath" }
        $ownership = if ($pythonInstalledByPyFirewall) { 'installed by PyFirewall' } else { 'existing/shared installation' }
        Write-Host "  - $pythonLabel ($ownership)" -ForegroundColor White
    }
    if ($hasFirewallProfileBackup) {
        Write-Host '  - Saved Windows Firewall profile state' -ForegroundColor White
    }

    if (-not ($hasPython -or $hasPackages -or $hasNpcap -or $hasShortcut -or $hasTask -or $hasFirewallRules -or $hasFirewallProfileBackup)) {
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
    $restoreFirewallProfile = $false

    if ($hasFirewallRules) {
        $removeFirewallRules = Ask-YesNo "Remove all $($firewallRules.Count) PyFirewall-managed Windows Firewall rule(s)?"
    }

    if ($hasFirewallProfileBackup) {
        $restoreFirewallProfile = Ask-YesNo 'Restore the Windows Firewall profile settings that PyFirewall saved before initialization?'
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
        if ($pythonEntry -and $pythonInstalledByPyFirewall) {
            Write-Host 'PyFirewall recorded this Python installation as installed by the PyFirewall installer.' -ForegroundColor Gray
        } else {
            Write-WarnMsg 'This Python installation was detected but was not recorded as installed by PyFirewall. Removing it may affect other software.'
        }

        if ($pythonEntry) {
            $removePython = Ask-YesNo "Uninstall $($pythonEntry.DisplayName)?"
        } else {
            Write-WarnMsg "The detected Python interpreter at $pythonPath has no matching Windows uninstall entry. Python will be kept."
        }

        if (-not $removePython -and $hasPackages) {
            $psutilLabel = if ($psutilInstalledByPyFirewall) { 'psutil was installed by PyFirewall' } else { 'psutil was already present or its ownership is unknown' }
            $scapyLabel = if ($scapyInstalledByPyFirewall) { 'Scapy was installed by PyFirewall' } else { 'Scapy was already present or its ownership is unknown' }
            Write-Info $psutilLabel
            $removePsutil = Ask-YesNo 'Uninstall the Python package psutil from the detected Python environment?'
            Write-Info $scapyLabel
            $removeScapy = Ask-YesNo 'Uninstall the Python package scapy from the detected Python environment?'
        } elseif ($removePython -and $hasPackages) {
            Write-Info 'The selected Python installation is being removed, so its psutil/scapy packages will be removed with that Python installation.'
        }
    }

    if ($hasNpcap) {
        Write-Host ''
        Write-Host 'Npcap may also be used by other network-analysis software.' -ForegroundColor Yellow
        $removeNpcap = Ask-YesNo "Uninstall $($npcapEntry.DisplayName)?"
    }

    if (-not ($removeFirewallRules -or $restoreFirewallProfile -or $removeTask -or $removeShortcut -or $removePsutil -or $removeScapy -or $removeNpcap -or $removePython)) {
        Write-Host ''
        Write-Host 'No removals were selected. No changes were made.' -ForegroundColor Yellow
        exit 0
    }

    Write-Host ''
    Write-Host 'Selected removals:' -ForegroundColor White
    if ($removeFirewallRules) { Write-Host "  - PyFirewall-managed firewall rules ($($firewallRules.Count))" }
    if ($restoreFirewallProfile) { Write-Host '  - Restore saved Windows Firewall profile settings' }
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

    $needsProcessStop = $removeFirewallRules -or $restoreFirewallProfile -or $removePsutil -or $removeScapy -or $removeNpcap -or $removePython
    if ($needsProcessStop) {
        Stop-PyFirewallProcesses
    }

    if ($removeFirewallRules) {
        Remove-PyFirewallFirewallRules
    }

    if ($restoreFirewallProfile) {
        [void](Restore-PyFirewallFirewallProfileState $firewallProfileBackup)
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
        Write-OK "$($pythonEntry.DisplayName) uninstall requested."
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
        $remainingPythonPath = if ($preferredPythonPath) { $preferredPythonPath } else { $pythonPath }
        $remainingPythonEntry = if ($remainingPythonPath) { Get-PythonEntry $remainingPythonPath } else { $null }
        $pythonStillExists = [bool]($remainingPythonPath -and (Test-Path -LiteralPath $remainingPythonPath))
        if ($pythonStillExists -or $remainingPythonEntry) {
            Write-WarnMsg 'The selected Python installation may still be present. A restart may be required, or the uninstall may have been cancelled by Windows.'
        } else {
            Write-OK 'The selected Python installation is no longer registered and its recorded interpreter path is gone.'
        }
    } elseif ($hasPython) {
        Write-OK "Python was kept."
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

    if ($restoreFirewallProfile) {
        if (Test-Path -LiteralPath $FirewallProfileBackupFile) {
            Write-WarnMsg 'The firewall-profile backup is still present because restoration was incomplete or skipped for one or more profiles.'
        } else {
            Write-OK 'Saved Windows Firewall profile state was restored and the backup was removed.'
        }
    } elseif ($hasFirewallProfileBackup) {
        Write-OK 'Saved Windows Firewall profile state was kept.'
    }

    if ($removePython -and (Test-Path -LiteralPath $InstallMetadataFile)) {
        Remove-Item -LiteralPath $InstallMetadataFile -Force -ErrorAction SilentlyContinue
        Write-OK 'PyFirewall installation ownership metadata was removed.'
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
