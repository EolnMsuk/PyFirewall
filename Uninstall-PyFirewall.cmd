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
$ScriptDir = Split-Path -Parent $env:PYFW_UNINSTALL_FILE
$InstallMetadataFile = Join-Path $ScriptDir 'pyfirewall_install.json'
$FirewallProfileBackupFile = Join-Path $ScriptDir 'firewall_profile_backup.json'
$ConfigFile = Join-Path $ScriptDir 'firewall_config.json'
$script:RetainedComponents = [ordered]@{}
$script:MetadataProblem = 'install log file was missing'

function Test-InstallerOwned([object]$Metadata, [string]$Component) {
    $value = $Metadata."${Component}_installed_by_pyfirewall"
    return ($value -is [bool] -and $value -eq $true)
}

function Select-Removal([string]$Name, [bool]$Present, [bool]$Eligible, [string]$Question, [string]$SkipReason) {
    if (-not $Eligible) {
        $script:RetainedComponents[$Name] = $SkipReason
        return $false
    }
    if (-not $Present) {
        $script:RetainedComponents[$Name] = 'not detected, or no usable uninstaller was found'
        return $false
    }
    if (Ask-YesNo $Question) {
        $script:RetainedComponents[$Name] = 'removal selected but not completed or verified'
        return $true
    }
    $script:RetainedComponents[$Name] = 'removal rejected by the user'
    return $false
}

function Write-RetainedSummary {
    Write-Step 'Components / applications not uninstalled'
    foreach ($name in $script:RetainedComponents.Keys) {
        Write-Host ("  - {0}: {1}." -f $name, $script:RetainedComponents[$name])
    }
    Write-Host '  - PyFirewall source files, icon and exported backups: retained by design.'
    if (Test-Path -LiteralPath $InstallMetadataFile) {
        Write-Host '  - Installation log: retained to preserve ownership history for future uninstall attempts.'
    }
}

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
        $metadata = Get-Content -LiteralPath $InstallMetadataFile -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($null -eq $metadata -or $metadata -isnot [PSCustomObject]) { throw 'Expected an installation metadata object.' }
        return $metadata
    } catch {
        Write-WarnMsg "PyFirewall installation metadata could not be read: $($_.Exception.Message)"
        $script:MetadataProblem = 'install log file was unreadable or invalid'
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
        if ($LASTEXITCODE -ne 0) { throw 'pip could not enumerate packages in the recorded Python environment.' }
        return ($json -join '' | ConvertFrom-Json) |
            Where-Object { $_.name -in @('psutil', 'scapy') }
    } catch {
        throw "Could not inspect Python packages: $($_.Exception.Message)"
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

function ConvertTo-PyFirewallGpoBoolean([object]$Value) {
    if ($Value -is [bool]) {
        if ([bool]$Value) { return 'True' }
        return 'False'
    }

    $text = ([string]$Value).Trim()
    switch -Regex ($text) {
        '^(?i:true|1)$'        { return 'True' }
        '^(?i:false|0)$'       { return 'False' }
        '^(?i:notconfigured|2)$' { return 'NotConfigured' }
        default {
            throw "Invalid saved firewall profile Enabled value: '$text'. Expected True, False, or NotConfigured."
        }
    }
}

function ConvertTo-PyFirewallAction([object]$Value) {
    if ($null -eq $Value) {
        throw 'Firewall profile action value was empty.'
    }

    # Get-NetFirewallProfile exposes these properties as Action values such as
    # Allow/Block, while older backups can contain the underlying numeric WMI
    # values.  Microsoft documents the profile Action representation as:
    # NotConfigured=0, Allow=2, Block=4.
    if ($Value -is [System.Enum]) {
        $text = $Value.ToString().Trim()
    } else {
        $text = ([string]$Value).Trim()
    }

    switch -Regex ($text) {
        '^(?i:notconfigured)$' { return 'NotConfigured' }
        '^(?i:allow)$'         { return 'Allow' }
        '^(?i:block)$'         { return 'Block' }
        '^0$'                  { return 'NotConfigured' }
        '^2$'                  { return 'Allow' }
        '^4$'                  { return 'Block' }
        default {
            throw "Invalid saved firewall profile action value: '$text'. Expected NotConfigured, Allow, Block, or the corresponding numeric value 0, 2, or 4."
        }
    }
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

        $currentEnabled = ConvertTo-PyFirewallGpoBoolean $currentProfile.Enabled
        $stillPyFirewallState = ($currentEnabled -eq 'True') -and
            ([string]$currentProfile.DefaultInboundAction -eq 'Allow') -and
            ([string]$currentProfile.DefaultOutboundAction -eq 'Allow')
        if (-not $stillPyFirewallState) {
            Write-WarnMsg "Firewall profile '$name' differs from the state PyFirewall set. Leaving the current state unchanged."
            $skippedNames += $name
            continue
        }

        $enabledValue = ConvertTo-PyFirewallGpoBoolean $saved.enabled
        $inboundAction = ConvertTo-PyFirewallAction $saved.default_inbound_action
        $outboundAction = ConvertTo-PyFirewallAction $saved.default_outbound_action

        Set-NetFirewallProfile `
            -Name $name `
            -Enabled $enabledValue `
            -DefaultInboundAction $inboundAction `
            -DefaultOutboundAction $outboundAction `
            -ErrorAction Stop
        $restoredNames += $name
        Write-OK "Restored firewall profile '$name'."
    }

    $verified = @(Get-CurrentPyFirewallFirewallProfiles)
    foreach ($name in $restoredNames) {
        $saved = @($Backup.profiles | Where-Object { [string]$_.name -eq $name }) | Select-Object -First 1
        $actual = $verified | Where-Object { [string]$_.Name -eq $name } | Select-Object -First 1

        if (-not $actual) {
            throw "Firewall profile '$name' could not be found during post-restoration verification."
        }

        # Enabled can be represented as a GpoBoolean/enum on the live profile
        # and as a Boolean, string, or numeric value in the JSON backup. Compare
        # normalized textual values instead of relying on PowerShell's loose casts.
        $expectedEnabled = ConvertTo-PyFirewallGpoBoolean $saved.enabled
        $actualEnabled = ConvertTo-PyFirewallGpoBoolean $actual.Enabled
        $expectedInbound = ConvertTo-PyFirewallAction $saved.default_inbound_action
        $actualInbound = ConvertTo-PyFirewallAction $actual.DefaultInboundAction
        $expectedOutbound = ConvertTo-PyFirewallAction $saved.default_outbound_action
        $actualOutbound = ConvertTo-PyFirewallAction $actual.DefaultOutboundAction

        $mismatches = New-Object System.Collections.Generic.List[string]
        if ($actualEnabled -ne $expectedEnabled) {
            $mismatches.Add("Enabled expected '$expectedEnabled' but found '$actualEnabled'")
        }
        if ($actualInbound -ne $expectedInbound) {
            $mismatches.Add("DefaultInboundAction expected '$expectedInbound' but found '$actualInbound'")
        }
        if ($actualOutbound -ne $expectedOutbound) {
            $mismatches.Add("DefaultOutboundAction expected '$expectedOutbound' but found '$actualOutbound'")
        }

        if ($mismatches.Count -gt 0) {
            throw ("Firewall profile '$name' could not be verified after restoration: " + ($mismatches -join '; '))
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

function Get-PyFirewallProcesses {
    Get-CimInstance Win32_Process -ErrorAction Stop |
        Where-Object {
            $_.Name -match '^(?i:pythonw?|py)(?:\d+(?:\.\d+)*)?\.exe$' -and
            $_.CommandLine -match '(?i)firewall_monitor\.py(?:"|\s|$)'
        }
}

function Stop-PyFirewallProcesses {
    $processes = @(Get-PyFirewallProcesses)
    foreach ($process in $processes) {
        $running = Get-Process -Id $process.ProcessId -ErrorAction SilentlyContinue
        if (-not $running) { continue }
        Write-Info "Closing PyFirewall (PID $($process.ProcessId)) before uninstalling components."
        Stop-Process -InputObject $running -Force -ErrorAction Stop
        if (-not $running.WaitForExit(10000)) {
            throw 'PyFirewall did not close. Uninstall was stopped before removing components.'
        }
    }
}

try {
    $desktop = [Environment]::GetFolderPath('Desktop')
    # Capture the initial state before any selected removal closes PyFirewall.
    $pyFirewallWasRunning = @(Get-PyFirewallProcesses).Count -gt 0
    $firewallProfileBackupWasPresent = Test-Path -LiteralPath $FirewallProfileBackupFile
    $shortcut = Join-Path $desktop 'PyFirewall - Firewall & Network Monitor.lnk'
    $legacyShortcut = Join-Path $desktop 'PyFirewall.lnk'
    $shortcutPaths = @($shortcut, $legacyShortcut) | Select-Object -Unique
    $taskName = 'PyFirewall - At Login'
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    $installMetadata = Get-PyFirewallInstallMetadata
    $preferredPythonPath = if ($installMetadata) { [string]$installMetadata.python_path } else { $null }
    $pythonEntry = Get-PythonEntry $preferredPythonPath
    $pythonPath = Get-PythonPath $pythonEntry $preferredPythonPath
    $packageInspectionFailed = $false
    try {
        $packages = @(Get-PythonPackageInfo $pythonPath)
    } catch {
        $packages = @()
        $packageInspectionFailed = $true
        Write-WarnMsg $_.Exception.Message
    }
    $npcapEntry = Get-NpcapEntry
    $npcapUninstaller = if ($npcapEntry) { Get-NpcapUninstaller $npcapEntry } else { $null }
    $firewallRules = @(Get-PyFirewallRules)

    $hasPython = [bool]$pythonPath -or [bool]$pythonEntry
    $hasPackages = $packages.Count -gt 0
    $hasNpcap = [bool]$npcapEntry
    $existingShortcuts = @($shortcutPaths | Where-Object { Test-Path -LiteralPath $_ })
    $hasShortcut = $existingShortcuts.Count -gt 0
    $hasTask = [bool]$task
    $hasFirewallRules = $firewallRules.Count -gt 0
    $hasSettings = Test-Path -LiteralPath $ConfigFile
    $firewallProfileBackup = Get-PyFirewallFirewallProfileBackup
    $hasFirewallProfileBackup = [bool]$firewallProfileBackup

    Write-Step 'PyFirewall Uninstall Review'
    Write-Host 'Detected components:' -ForegroundColor White
    if ($hasSettings) {
        Write-Host '  - Saved settings, application/IP/domain rules, and column layout' -ForegroundColor White
    }

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
        $ownership = if (Test-InstallerOwned $installMetadata 'python') { 'installed by PyFirewall' } else { 'existing/shared installation' }
        Write-Host "  - $pythonLabel ($ownership)" -ForegroundColor White
    }
    if ($hasFirewallProfileBackup) {
        Write-Host '  - Saved Windows Firewall profile state' -ForegroundColor White
    }

    Write-Host ''
    Write-Host 'Choose what to remove. PyFirewall rules and saved settings can always be removed.' -ForegroundColor White
    Write-Host 'Other applications and Python packages are offered only if installed by the PyFirewall installer.' -ForegroundColor Gray
    Write-Host 'Answering N keeps that component in place.' -ForegroundColor Gray
    Write-Host ''

    $removeFirewallRules = $false
    $removeSettings = $false
    $removeTask = $false
    $removeShortcut = $false
    $removePython = $false
    $removeNpcap = $false
    $removePsutil = $false
    $removeScapy = $false
    $restoreFirewallProfile = $false

    $skipReason = if ($installMetadata) {
        'Not installed by PyFirewall install script (ignored)'
    } else { $MetadataProblem }
    # Application-owned rules/settings are eligible regardless of install metadata.
    # Offer one choice even if only the config exists, or neither exists yet.
    $rulesAndSettingsLabel = 'PyFirewall firewall rules and saved settings (firewall_config.json)'
    $removeFirewallRules = Select-Removal $rulesAndSettingsLabel $true $true 'Remove all PyFirewall firewall rules and saved configuration (firewall_config.json), including saved rules and column layout?' ''
    $removeSettings = $removeFirewallRules
    $restoreFirewallProfile = Select-Removal 'Windows Firewall profile settings' $hasFirewallProfileBackup $true 'Restore the Windows Firewall profile settings saved by PyFirewall?' ''
    if (-not $hasFirewallProfileBackup) {
        if (-not $pyFirewallWasRunning -and -not $firewallProfileBackupWasPresent) {
            $RetainedComponents['Windows Firewall profile settings'] = 'no backup profile found, PyFirewall restored it when last closed (ignored)'
        } else {
            $RetainedComponents['Windows Firewall profile settings'] = 'no valid firewall-profile backup was found; original settings cannot be restored safely'
        }
    }
    $removeTask = Select-Removal 'Scheduled task' $hasTask $true "Remove the '$taskName' Scheduled Task?" ''
    $removeShortcut = Select-Removal 'Desktop shortcuts' $hasShortcut $true 'Remove the PyFirewall desktop shortcut(s)?' ''

    # Only explicit JSON boolean true grants ownership. Missing fields and old logs
    # cannot authorize removal of a shared dependency.
    $pythonRecorded = [bool]($installMetadata -and $preferredPythonPath)
    $removePsutil = Select-Removal 'psutil' ([bool]($packages | Where-Object { $_.name -eq 'psutil' })) ($pythonRecorded -and (Test-InstallerOwned $installMetadata 'psutil')) 'Uninstall psutil from the recorded Python environment?' $skipReason
    $removeScapy = Select-Removal 'scapy' ([bool]($packages | Where-Object { $_.name -eq 'scapy' })) ($pythonRecorded -and (Test-InstallerOwned $installMetadata 'scapy')) 'Uninstall scapy from the recorded Python environment?' $skipReason
    $removeNpcap = Select-Removal 'Npcap' $hasNpcap (Test-InstallerOwned $installMetadata 'npcap') 'Uninstall Npcap installed by PyFirewall?' $skipReason

    # Removing Python must not bypass a decision to retain one of its packages.
    $keptPackages = @($packages | Where-Object {
        ($_.name -eq 'psutil' -and -not $removePsutil) -or
        ($_.name -eq 'scapy' -and -not $removeScapy)
    })
    $pythonEligible = $pythonRecorded -and (Test-InstallerOwned $installMetadata 'python')
    $pythonSkipReason = $skipReason
    if ($pythonEligible -and $keptPackages.Count -gt 0) {
        $pythonEligible = $false
        $pythonSkipReason = 'required by retained packages: ' + (($keptPackages | ForEach-Object { $_.name }) -join ', ')
    }
    if ($pythonEligible -and $packageInspectionFailed) {
        $pythonEligible = $false
        $pythonSkipReason = 'installed packages could not be inspected; retained to protect packages with unknown ownership'
    }
    $removePython = Select-Removal 'Python' ([bool]$pythonEntry) $pythonEligible 'Uninstall the Python installation recorded by PyFirewall?' $pythonSkipReason

    if (-not ($removeFirewallRules -or $removeSettings -or $restoreFirewallProfile -or $removeTask -or $removeShortcut -or $removePsutil -or $removeScapy -or $removeNpcap -or $removePython)) {
        Write-Host ''
        Write-Host 'No removals were selected. No changes were made.' -ForegroundColor Yellow
        exit 0
    }

    Write-Host ''
    Write-Host 'Selected removals:' -ForegroundColor White
    if ($removeSettings) { Write-Host '  - Saved settings, rules, and column layout (firewall_config.json)' }
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

    # The no-selections path exited above. Every removal, including just a task
    # or shortcut, must close the application before making changes.
    Stop-PyFirewallProcesses

    if ($removeFirewallRules) {
        Remove-PyFirewallFirewallRules
    }

    if ($removeSettings) {
        if (Test-Path -LiteralPath $ConfigFile) {
            Remove-Item -LiteralPath $ConfigFile -Force -ErrorAction Stop
        }
        if (Test-Path -LiteralPath $ConfigFile) { throw 'Saved settings could not be removed.' }
        Write-OK 'Saved settings and rule policy removed. A clean launch will use current column defaults.'
    }

    if ($restoreFirewallProfile) {
        if (Restore-PyFirewallFirewallProfileState $firewallProfileBackup) {
            $RetainedComponents.Remove('Windows Firewall profile settings')
        } else {
            $RetainedComponents['Windows Firewall profile settings'] = 'restoration incomplete; one or more profiles changed since PyFirewall initialization or no longer exist (backup retained)'
        }
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
            $remainingPackages = @(Get-PythonPackageInfo $pythonPath)
            foreach ($name in $packageNames) {
                if (-not ($remainingPackages | Where-Object { $_.name -eq $name })) {
                    $RetainedComponents.Remove($name)
                }
            }
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

    if ($hasFirewallRules -or $removeFirewallRules) {
        $remainingFirewallRules = @(Get-PyFirewallRules)
        if ($removeFirewallRules) {
            if ($remainingFirewallRules.Count -gt 0) {
                Write-WarnMsg "$($remainingFirewallRules.Count) PyFirewall-managed firewall rule(s) are still present."
            } else {
                if (-not (Test-Path -LiteralPath $ConfigFile)) {
                    $RetainedComponents.Remove($rulesAndSettingsLabel)
                }
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
            $RetainedComponents.Remove('Scheduled task')
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
            $RetainedComponents.Remove('Desktop shortcuts')
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
            $RetainedComponents.Remove('Python')
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
            $RetainedComponents.Remove('Npcap')
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

    Write-Host ''
    Write-Host 'PyFirewall uninstall selections have been processed.' -ForegroundColor Green
    Write-Host 'PyFirewall source code, exported rule backups, and PyFirewall.ico were not deleted by this script.' -ForegroundColor Green
    exit 0
}
catch {
    Write-Host "`n[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

finally {
    Write-RetainedSummary
}
