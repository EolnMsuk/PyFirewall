"""Installer and uninstaller policies with mocked Windows operations."""
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallerLifecycleTests(unittest.TestCase):
    def run_case(self, body):
        path = str(ROOT / 'requirements.ps1').replace("'", "''")
        source = r'''
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile('SCRIPT', [ref]$null, [ref]$null)
$ast.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $false) |
    ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
function Write-OK {}
function Get-CimInstance { [pscustomobject]@{Name='pythonw.exe';CommandLine='pythonw.exe "C:\PyFirewall\firewall_monitor.py"';ProcessId=42} }
function Stop-Process { throw 'Force-stopping a real process is forbidden' }
function Get-Process {
    $p = [pscustomobject]@{}
    $p | Add-Member ScriptMethod WaitForExit { param($timeout) return $true }
    return $p
}
function Unregister-ScheduledTask { throw 'Existing task must not be removed' }
'''.replace('SCRIPT', path)
        result = subprocess.run(
            ['powershell.exe', '-NoProfile', '-Command', '& ([scriptblock]::Create([Console]::In.ReadToEnd()))'],
            input=source + body, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_decline_leaves_app_running(self):
        self.run_case('''
function Read-YesNo { return $false }
if (Confirm-PyFirewallClosed) { throw 'Must cancel' }
if ($script:stopped) { throw 'App must remain running' }
''')

    def test_manual_exit_is_verified_without_force_stopping(self):
        self.run_case('''
function Get-CimInstance {
    if (-not $script:exited) { [pscustomobject]@{Name='pythonw.exe';CommandLine='pythonw.exe firewall_monitor.py';ProcessId=42} }
}
function Read-YesNo { $script:exited = $true; return $true }
if (-not (Confirm-PyFirewallClosed)) { throw 'Must continue' }
''')

    def test_still_running_aborts_before_mutations_and_preserves_recovery(self):
        self.run_case('''
function Read-YesNo { return $true }
$journal = 'original recovery state'
$blocked = $false
try { Confirm-PyFirewallClosed; throw 'Must not continue' }
catch { $blocked = $_.Exception.Message -like '*still running*' }
if (-not $blocked -or $journal -ne 'original recovery state') { throw 'Unsafe failed setup' }
''')

    def test_maintenance_guard_denies_a_second_owner_and_retains_ownership_until_cleanup(self):
        self.run_case(r'''
function New-Object {
    param($TypeName,$ArgumentList)
    if ($TypeName -ne 'Threading.Mutex') { throw 'Unexpected native object' }
    if ($ArgumentList[1] -ne 'Global\PyFirewall_NativePolicy_v1') { throw 'Wrong ownership identity' }
    $fake = [pscustomobject]@{}
    $fake | Add-Member ScriptMethod WaitOne { param($timeout) return $script:available }
    $fake | Add-Member ScriptMethod ReleaseMutex { $script:released = $true }
    $fake | Add-Member ScriptMethod Dispose { $script:disposed = $true }
    return $fake
}
$script:available = $false
$denied = $false
try { Enter-PyFirewallMaintenance } catch { $denied = $true }
if (-not $denied -or $script:PolicyMutexOwned) { throw 'Second controller was allowed' }
$script:available = $true
try {
    Enter-PyFirewallMaintenance
    if (-not $script:PolicyMutexOwned -or $script:released) { throw 'Lost ownership during setup' }
    throw 'Simulated setup failure'
} catch {
    if (-not $script:PolicyMutexOwned) { throw 'Owner released before failure cleanup' }
} finally {
    if ($script:PolicyMutexOwned) { $script:PolicyMutex.ReleaseMutex() }
    $script:PolicyMutex.Dispose()
}
if (-not $script:released -or -not $script:disposed) { throw 'Owner leaked on failure' }
''')

    def test_not_running_skips_prompt(self):
        self.run_case('''
function Get-CimInstance { @() }
function Read-YesNo { throw 'Unexpected prompt' }
if (-not (Confirm-PyFirewallClosed)) { throw 'Must continue' }
''')

    def test_existing_task_skips_prompt(self):
        self.run_case('''
function Get-ScheduledTask { [pscustomobject]@{TaskName='PyFirewall - At Login'} }
function Read-YesNo { throw 'Unexpected prompt' }
Configure-PyFirewallStartup 'pythonw.exe' 'app.py' 'C:/fake'
if ($script:registered) { throw 'Existing task must be preserved' }
''')

    def test_existing_owned_task_migrates_only_the_limit_and_preserves_disabled_choice(self):
        self.run_case(r'''
$script:task = [pscustomobject]@{TaskName='PyFirewall - At Login';TaskPath='\';State='Disabled';
    Actions=@([pscustomobject]@{Execute='C:\fake\pythonw.exe';Arguments='"C:\fake\firewall_monitor.py"';WorkingDirectory='C:\fake'});
    Settings=[pscustomobject]@{ExecutionTimeLimit='PT72H';Enabled=$false;Priority=5}}
function Get-ScheduledTask { $script:task }
function Read-YesNo { throw 'Must preserve startup choice' }
function Set-ScheduledTask { param($TaskName,$TaskPath,$Settings,$ErrorAction)
    if ($Settings.Enabled -ne $false -or $Settings.Priority -ne 5) { throw 'Settings changed' }
    $script:settingsApplied = $true
}
Configure-PyFirewallStartup 'C:\fake\pythonw.exe' 'C:\fake\firewall_monitor.py' 'C:\fake'
if (-not $script:settingsApplied -or $script:task.Settings.ExecutionTimeLimit -ne 'PT0S') { throw 'Limit not migrated' }
''')

    def test_fresh_task_explicitly_requests_unlimited_execution(self):
        self.run_case(r'''
function Test-Path { $true }
function New-ScheduledTaskAction { param($Execute,$Argument,$WorkingDirectory)
    [pscustomobject]@{Execute=$Execute;Arguments=$Argument;WorkingDirectory=$WorkingDirectory} }
function New-ScheduledTaskTrigger { param([switch]$AtLogOn,$User) 'trigger' }
function New-ScheduledTaskPrincipal { param($UserId,$LogonType,$RunLevel) 'principal' }
function New-ScheduledTaskSettingsSet {
    param($ExecutionTimeLimit,$Compatibility,[switch]$StartWhenAvailable,[switch]$AllowStartIfOnBatteries,
          [switch]$DontStopIfGoingOnBatteries,$MultipleInstances)
    if ($ExecutionTimeLimit -ne [TimeSpan]::Zero) { throw 'Missing unlimited execution' }
    [pscustomobject]@{ExecutionTimeLimit='PT0S'}
}
function Register-ScheduledTask { param($TaskName,$Action,$Trigger,$Principal,$Settings,$Description,[switch]$Force)
    $script:task = [pscustomobject]@{TaskName=$TaskName;Actions=@($Action);Settings=$Settings} }
function Get-ScheduledTask { $script:task }
Register-PyFirewallScheduledTask 'C:\fake\pythonw.exe' 'C:\fake\firewall_monitor.py' 'C:\fake'
if ($script:task.Settings.ExecutionTimeLimit -ne 'PT0S') { throw 'Wrong definition' }
''')

    def test_missing_task_asks_and_registers_only_if_accepted(self):
        for answer in ('$true', '$false'):
            with self.subTest(answer=answer):
                self.run_case('''
function Get-ScheduledTask { $null }
function Register-PyFirewallScheduledTask { $script:registered = $true }
function Read-YesNo { $script:asked = $true; return ANSWER }
Configure-PyFirewallStartup 'pythonw.exe' 'app.py' 'C:/fake'
if (-not $script:asked) { throw 'Missing prompt' }
if ([bool]$script:registered -ne ANSWER) { throw 'Incorrect task registration' }
'''.replace('ANSWER', answer))


class UninstallPolicyTests(unittest.TestCase):
    def run_review(self, metadata, extra_mocks=''):
        source = (ROOT / 'Uninstall-PyFirewall.cmd').read_text().split('# POWERSHELL START\n', 1)[1]
        start = source.index('if (-not (Test-Administrator))')
        end = source.index('function Write-Step', start)
        source = source[:start] + source[end:]
        mock = r'''
function Get-PyFirewallInstallMetadata { METADATA }
function Get-PythonEntry { [pscustomobject]@{ DisplayName='Python test' } }
function Get-PythonPath { 'C:\fake\python.exe' }
function Get-PythonPackageInfo { @([pscustomobject]@{name='psutil';version='1'}, [pscustomobject]@{name='scapy';version='1'}) }
function Get-NpcapEntry { [pscustomobject]@{DisplayName='Npcap test'} }
function Get-NpcapUninstaller { 'C:\fake\uninstall.exe' }
function Get-PyFirewallRules { @([pscustomobject]@{Name='PyFirewall_test'}) }
function Get-PyFirewallProcesses { @() }
function Get-ScheduledTask { [pscustomobject]@{TaskName='test'} }
function Get-PyFirewallFirewallProfileBackup { [pscustomobject]@{profiles=@()} }
function Test-Path { $true }
function Ask-YesNo([string]$Question) { Write-Host "PROMPT:$Question"; return $false }
'''.replace('METADATA', "return ('" + json.dumps(metadata) + "' | ConvertFrom-Json)")
        source = source.replace("try {\n    $desktop =", mock + extra_mocks + "\ntry {\n    $desktop =")
        source = "$env:PYFW_UNINSTALL_FILE='C:/fake/Uninstall-PyFirewall.cmd'\n" + source
        result = subprocess.run(
            ['powershell.exe', '-NoProfile', '-Command',
             '& ([scriptblock]::Create([Console]::In.ReadToEnd()))'],
            input=source, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def test_missing_log_only_prompts_for_core_cleanup(self):
        output = self.run_review(None)
        self.assertEqual(output.count('PROMPT:'), 4)
        for name in ('Python', 'Npcap', 'psutil', 'scapy'):
            self.assertIn(f'{name}: install log file was missing', output)
        self.assertIn('Components / applications not uninstalled', output)
        self.assertIn('removal rejected by the user', output)

    def test_preexisting_dependencies_are_not_offered(self):
        output = self.run_review({'python_path': 'C:\\fake\\python.exe'})
        self.assertEqual(output.count('PROMPT:'), 4)
        self.assertIn('Not installed by PyFirewall install script (ignored)', output)

    def test_owned_dependencies_are_offered_and_declines_reported(self):
        metadata = {'python_path': 'C:\\fake\\python.exe'}
        metadata.update({f'{name}_installed_by_pyfirewall': True for name in ('python', 'psutil', 'scapy', 'npcap')})
        output = self.run_review(metadata)
        self.assertEqual(output.count('PROMPT:'), 7)
        self.assertIn('psutil: removal rejected by the user', output)
        self.assertIn('scapy: removal rejected by the user', output)
        self.assertIn('Npcap: removal rejected by the user', output)
        self.assertIn('Python: required by retained packages', output)

    def test_string_boolean_does_not_authorize_removal(self):
        metadata = {'python_path': 'C:\\fake\\python.exe'}
        metadata.update({f'{name}_installed_by_pyfirewall': 'true' for name in ('python', 'psutil', 'scapy', 'npcap')})
        self.assertEqual(self.run_review(metadata).count('PROMPT:'), 4)

    def test_only_owned_detected_package_is_offered(self):
        output = self.run_review({'python_path': 'C:/fake/python.exe',
                                  'psutil_installed_by_pyfirewall': True})
        self.assertEqual(output.count('PROMPT:'), 5)
        self.assertIn('PROMPT:Uninstall psutil', output)
        self.assertNotIn('PROMPT:Uninstall scapy', output)

    def test_failed_package_discovery_does_not_block_core_cleanup(self):
        output = self.run_review(None, "\nfunction Get-PythonPackageInfo { throw 'pip unavailable' }\n")
        self.assertEqual(output.count('PROMPT:'), 4)
        self.assertIn('Python: install log file was missing', output)

    def test_task_only_removal_closes_app_before_removing_task(self):
        output = self.run_review(None, r'''
function Ask-YesNo([string]$Question) { return $Question -like '*Scheduled Task?*' }
function Stop-PyFirewallProcesses { $script:closed = $true; Write-Host 'APP_CLOSED' }
function Unregister-ScheduledTask {
    if (-not $script:closed) { throw 'App must close before task removal' }
    Write-Host 'TASK_REMOVED'
}
function Start-Sleep {}
''')
        self.assertLess(output.index('APP_CLOSED'), output.index('TASK_REMOVED'))
        self.assertIn('Windows Firewall profile settings: removal rejected by the user', output)

    def test_combined_choice_declined_keeps_rules_and_config(self):
        output = self.run_review(None, r'''
function Remove-Item { throw 'Must preserve config' }
function Remove-PyFirewallFirewallRules { throw 'Must preserve rules' }
function Stop-PyFirewallProcesses { throw 'No removals selected' }
''')
        self.assertIn('PyFirewall firewall rules and saved settings (firewall_config.json): removal rejected by the user', output)
        self.assertEqual(output.count('PROMPT:Remove all PyFirewall firewall rules and saved configuration'), 1)

    def test_combined_choice_removes_config_and_rules_without_ownership_log(self):
        for rules_present, config_present in ((True, True), (False, True), (True, False), (False, False)):
            with self.subTest(rules=rules_present, config=config_present):
                mocks = r'''
$script:rulesPresent = INITIAL_RULES
$script:configPresent = INITIAL_CONFIG
function Ask-YesNo([string]$Question) { return $Question -like '*saved configuration*' }
function Stop-PyFirewallProcesses { $script:closed = $true; Write-Host 'APP_CLOSED' }
function Get-PyFirewallRules { if ($script:rulesPresent) { [pscustomobject]@{Name='PyFirewall_test'} } }
function Remove-PyFirewallFirewallRules {
    if (-not $script:closed) { throw 'App must close first' }
    $script:rulesPresent = $false
    Write-Host 'RULES_CLEANED'
}
function Test-Path([string]$LiteralPath) {
    if ($LiteralPath -like '*firewall_config.json') { return $script:configPresent }
    return $true
}
function Remove-Item([string]$LiteralPath) {
    if (-not $script:closed) { throw 'App must close first' }
    if ($LiteralPath -notlike '*firewall_config.json') { throw 'Unexpected deletion' }
    $script:configPresent = $false
    Write-Host 'CONFIG_REMOVED'
}
function Start-Sleep {}
'''.replace('INITIAL_RULES', '$true' if rules_present else '$false').replace('INITIAL_CONFIG', '$true' if config_present else '$false')
                output = self.run_review(None, mocks)
                self.assertIn('Saved settings and rule policy removed', output)
                summary = output.split('== Components / applications not uninstalled ==')[1]
                self.assertNotIn('PyFirewall firewall rules and saved settings', summary)
                self.assertIn('Python: install log file was missing', summary)


if __name__ == '__main__':
    unittest.main()
