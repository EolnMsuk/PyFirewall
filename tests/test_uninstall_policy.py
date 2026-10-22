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
        self.assertIn('not recorded as newly installed', output)

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


if __name__ == '__main__':
    unittest.main()
