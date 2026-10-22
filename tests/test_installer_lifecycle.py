"""Run installer lifecycle functions with mocked Windows operations."""
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
function Stop-Process { $script:stopped = $true }
function Get-Process {
    $p = [pscustomobject]@{}
    $p | Add-Member ScriptMethod WaitForExit { param($timeout) return $true }
    return $p
}
function Register-PyFirewallScheduledTask { $script:registered = $true }
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

    def test_accept_closes_app(self):
        self.run_case('''
function Read-YesNo { return $true }
if (-not (Confirm-PyFirewallClosed)) { throw 'Must continue' }
if (-not $script:stopped) { throw 'App must close' }
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

    def test_missing_task_asks_and_registers_only_if_accepted(self):
        for answer in ('$true', '$false'):
            with self.subTest(answer=answer):
                self.run_case('''
function Get-ScheduledTask { $null }
function Read-YesNo { $script:asked = $true; return ANSWER }
Configure-PyFirewallStartup 'pythonw.exe' 'app.py' 'C:/fake'
if (-not $script:asked) { throw 'Missing prompt' }
if ([bool]$script:registered -ne ANSWER) { throw 'Incorrect task registration' }
'''.replace('ANSWER', answer))


if __name__ == '__main__':
    unittest.main()
