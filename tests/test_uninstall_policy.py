"""Exercise the embedded PowerShell with mocked discovery and no system changes."""
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


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
