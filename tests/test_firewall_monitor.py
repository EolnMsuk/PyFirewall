"""Regression tests using importable modules and mocked firewall/OS dependencies."""
import json
import pathlib
import queue
import shutil
import socket
import tempfile
import threading
import types
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, patch

from support import App, NS, patch_dependencies


def app():
    a = App.__new__(App)
    a.lock = threading.RLock()
    a.firewall_lock = threading.RLock()
    a.closed = a.is_paused = False
    a.dark_mode = NS['DEFAULT_DARK_MODE']
    a.check_updates_on_startup = NS['DEFAULT_CHECK_UPDATES_ON_STARTUP']
    a.check_updates_on_startup_var = Mock()
    a.update_check_running = a.update_check_manual = False
    a.update_dialog = None
    a.log_alerts_only = a.auto_block_enabled = True
    a.auto_prompt_generation = 0
    a.auto_prompt_keys = set()
    a.auto_prompt_dialog = a.auto_prompt_key = None
    a.auto_prompt_active = False
    a.prompt_queue = queue.Queue()
    a.allowed_apps = set()
    a.blocked_paths = {}
    a.global_blocks = {}
    a.global_allows = {}
    a.global_ports = {}
    a.connection_rates = {}
    a.upload_alerted = set()
    a.queue_alert = Mock()
    a.save_settings = Mock(return_value=True)
    a.rules_changed = Mock()
    a.capture_error = None
    a.capture_healthy = False
    return a


class GlobalTargetDiagnosticsTests(unittest.TestCase):
    def test_localhost_resolves_both_address_families(self):
        results = [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::1', 0, 0, 0)),
                   (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 0))]
        with patch.object(socket, 'getaddrinfo', return_value=results) as resolve:
            self.assertEqual(app().resolve_global_target(' LOCALHOST. '), ('127.0.0.1', '::1'))
        resolve.assert_called_once_with('localhost', None, type=socket.SOCK_STREAM)

    def test_resolution_failure_preserves_reason(self):
        with patch.object(socket, 'getaddrinfo', side_effect=socket.gaierror(11001, 'Host not found')):
            with self.assertRaisesRegex(ValueError, "Could not resolve global target 'localhost'.*Host not found"):
                app().resolve_global_target('localhost')

    def test_command_diagnostics_reach_alert_dialog_and_log(self):
        for quiet in (False, True):
            with self.subTest(quiet=quiet):
                a = app()
                failure = NS['subprocess'].CalledProcessError(
                    1, ['netsh', 'remoteip=127.0.0.1,::1'],
                    output='The address is invalid.\n', stderr='Additional diagnostic.\n')
                a.add_global_rule_sync = Mock(side_effect=failure)
                messages = types.SimpleNamespace(showerror=Mock())
                with tempfile.TemporaryDirectory() as directory:
                    log = pathlib.Path(directory) / 'errors.log'
                    with patch_dependencies(messagebox=messages, INTERNAL_ERROR_LOG_FILE=str(log)):
                        self.assertFalse(a.add_global_rule('localhost', True, quiet=quiet))
                    logged = log.read_text(encoding='utf-8')
                alert = a.queue_alert.call_args.args[-1]
                for detail in ('The address is invalid.', 'Additional diagnostic.'):
                    self.assertIn(detail, alert)
                    self.assertIn(detail, logged)
                    if not quiet:
                        self.assertIn(detail, messages.showerror.call_args.args[1])
                if quiet:
                    messages.showerror.assert_not_called()
                a.save_settings.assert_not_called()
                self.assertEqual(a.global_allows, {})


class ProfileTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('powershell'), 'Windows PowerShell is required')
    def test_restore_commands_bind_to_real_windows_enum_types(self):
        profiles = [{'name': n, 'enabled': enabled, 'default_inbound_action': '2',
                     'default_outbound_action': '4'}
                    for n, enabled in [('Domain', True), ('Private', False), ('Public', True)]]
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'backup.json'
            path.write_text(json.dumps({'profiles': profiles}))
            a = app()
            a.run_ps = Mock()
            with patch_dependencies(FIREWALL_PROFILE_BACKUP_FILE=str(path)):
                a._restore_firewall_profile_state_locked()
        # Bind generated arguments to NetSecurity's real types without calling a firewall cmdlet.
        script = '''$ErrorActionPreference = 'Stop'
Import-Module NetSecurity -ErrorAction Stop
function Test-ProfileParameters {
    [CmdletBinding()]
    param([string]$Name,
          [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean]$Enabled,
          [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action]$DefaultInboundAction,
          [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action]$DefaultOutboundAction)
    "$Name|$Enabled|$DefaultInboundAction|$DefaultOutboundAction"
}
'''
        for call in a.run_ps.call_args_list:
            command = call.args[0]
            self.assertTrue(command.startswith('Set-NetFirewallProfile '))
            script += command.replace('Set-NetFirewallProfile ', 'Test-ProfileParameters ', 1) + '\n'
        result = NS['subprocess'].run(['powershell', '-NoProfile', '-Command', script],
                                      capture_output=True, text=True, timeout=30,
                                      creationflags=NS['CREATE_NO_WINDOW'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['Domain|True|Allow|Block',
                                                       'Private|False|Allow|Block',
                                                       'Public|True|Allow|Block'])

    def test_startup_failure_logs_powershell_diagnostics(self):
        a = app()
        failure = NS['subprocess'].CalledProcessError(1, ['powershell'], stderr='Invalid cast from System.Boolean')
        a._restore_firewall_profile_state_locked = Mock(side_effect=failure)
        with tempfile.TemporaryDirectory() as directory:
            backup = pathlib.Path(directory) / 'backup.json'
            backup.write_text('{}')
            log = pathlib.Path(directory) / 'errors.log'
            with patch_dependencies(FIREWALL_PROFILE_BACKUP_FILE=str(backup), INTERNAL_ERROR_LOG_FILE=str(log)):
                ok, error = a.initialize_or_restore_firewall()
            self.assertFalse(ok)
            self.assertIn('Invalid cast from System.Boolean', error)
            self.assertIn('Invalid cast from System.Boolean', log.read_text(encoding='utf-8'))
            self.assertIn('initialize_or_restore_firewall', log.read_text(encoding='utf-8'))
            self.assertTrue(backup.exists())

    def test_setup_and_rollback_errors_are_both_reported(self):
        a = app()
        a._backup_firewall_profile_state = Mock()
        a.run_ps = Mock(side_effect=NS['subprocess'].CalledProcessError(1, 'setup', stderr='setup detail'))
        a._restore_firewall_profile_state_locked = Mock(
            side_effect=NS['subprocess'].CalledProcessError(1, 'restore', stderr='restore detail'))
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / 'errors.log'
            with patch_dependencies(FIREWALL_PROFILE_BACKUP_FILE=str(pathlib.Path(directory) / 'absent.json'),
                            INTERNAL_ERROR_LOG_FILE=str(log)):
                ok, error = a.initialize_or_restore_firewall()
            self.assertFalse(ok)
            for detail in ('setup detail', 'restore detail'):
                self.assertIn(detail, error)
                self.assertIn(detail, log.read_text(encoding='utf-8'))

    def test_numeric_and_named_actions(self):
        for raw, expected in [(0, 'NotConfigured'), ('2', 'Allow'), (4, 'Block'), ('Block', 'Block')]:
            self.assertEqual(App._profile_action(raw), expected)
        self.assertFalse(App._profile_enabled('False'))
        with self.assertRaises(ValueError):
            App._profile_action(3)

    def test_backup_is_fully_validated_before_restore(self):
        profiles = [{'name': n, 'enabled': True, 'default_inbound_action': '2', 'default_outbound_action': '4'}
                    for n in ('Domain', 'Private', 'Public')]
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'backup.json'
            a = app()
            a.run_ps = Mock()
            with patch_dependencies(FIREWALL_PROFILE_BACKUP_FILE=str(path)):
                profiles[-1]['default_outbound_action'] = 'invalid'
                path.write_text(json.dumps({'profiles': profiles}))
                with self.assertRaises(ValueError):
                    a._restore_firewall_profile_state_locked()
                a.run_ps.assert_not_called()
                self.assertTrue(path.exists())
                profiles[-1]['default_outbound_action'] = '4'
                path.write_text(json.dumps({'profiles': profiles}))
                self.assertTrue(a._restore_firewall_profile_state_locked())
                self.assertEqual(a.run_ps.call_count, 3)
                self.assertFalse(path.exists())
                self.assertFalse(a.firewall_initialized)

    def test_restore_failure_keeps_recovery_journal(self):
        profiles = [{'name': n, 'enabled': True, 'default_inbound_action': '2', 'default_outbound_action': '2'}
                    for n in ('Domain', 'Private', 'Public')]
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'backup.json'
            path.write_text(json.dumps({'profiles': profiles}))
            a = app()
            a.run_ps = Mock(side_effect=RuntimeError('denied'))
            with patch_dependencies(FIREWALL_PROFILE_BACKUP_FILE=str(path)):
                with self.assertRaises(RuntimeError):
                    a._restore_firewall_profile_state_locked()
            self.assertTrue(path.exists())

    def test_each_launch_sets_profiles_and_recovers_crash_first(self):
        a = app()
        a.firewall_initialized = True  # Historical settings must not bypass this launch.
        events = []
        a._restore_firewall_profile_state_locked = lambda: events.append('recover')
        a._backup_firewall_profile_state = lambda: events.append('backup')
        a.run_ps = lambda _: events.append('configure')
        a.restore_saved_rules_locked = lambda: events.append('rules')
        a.remove_auto_holds_locked = lambda: events.append('holds')
        with patch.object(NS['os'].path, 'exists', return_value=True):
            self.assertEqual(a.initialize_or_restore_firewall(), (True, ''))
        self.assertEqual(events, ['recover', 'backup', 'configure', 'rules', 'holds'])

    def test_close_before_startup_does_not_modify_profiles(self):
        a = app()
        a.closed = True
        a.run_ps = Mock()
        self.assertFalse(a.initialize_or_restore_firewall()[0])
        a.run_ps.assert_not_called()


class RuleTests(unittest.TestCase):
    def test_partial_delete_rolls_back(self):
        a = app()
        previous = [{'name': 'in'}, {'name': 'out'}]
        state = {'in', 'out'}
        calls = 0
        def delete(names, strict=True):
            nonlocal calls
            names = set(names)
            calls += 1
            if calls == 1:
                state.remove('in')
                raise RuntimeError('partial deletion')
            state.difference_update(names)
        a.delete_rule_names = delete
        a.get_firewall_rules = lambda: [{'name': n} for n in state]
        a._restore_app_rule_records = lambda rows: state.update(r['name'] for r in rows)
        apply = Mock()
        with self.assertRaisesRegex(RuntimeError, 'partial deletion'):
            a._replace_rule_records(previous, (), apply)
        self.assertEqual(state, {'in', 'out'})
        apply.assert_not_called()

    def test_failed_cleanup_still_restores_missing_original(self):
        a = app()
        state = {'out'}
        a.delete_rule_names = Mock(side_effect=RuntimeError('delete denied'))
        a.get_firewall_rules = lambda: [{'name': n} for n in state]
        a._restore_app_rule_records = lambda rows: state.update(r['name'] for r in rows)
        a.sync_rule_cache = Mock()
        with self.assertRaisesRegex(RuntimeError, 'rollback failed'):
            a._replace_rule_records([{'name': 'in'}, {'name': 'out'}], (), Mock())
        self.assertEqual(state, {'in', 'out'})

    def test_missing_delete_is_noop_and_real_failure_raises(self):
        a = app()
        a.run_ps = Mock(side_effect=RuntimeError('batch unavailable'))
        a.get_firewall_rules = Mock(return_value=[])
        a.run_netsh = Mock()
        self.assertFalse(a.delete_rule_names(['absent']))
        a.run_netsh.assert_not_called()
        a.get_firewall_rules.return_value = [{'name': 'present'}]
        a.run_netsh.side_effect = NS['subprocess'].CalledProcessError(1, 'netsh')
        with self.assertRaises(RuntimeError):
            a.delete_rule_names(['present'])

    def test_failed_allow_keeps_cached_block_and_prompt(self):
        a = app()
        exe = NS['normalize_path']('C:/test.exe')
        a.blocked_paths[exe] = {'in': True, 'out': True}
        dialog = Mock()
        a.auto_prompt_key = exe
        a.auto_prompt_dialog = dialog
        a.get_firewall_rules = Mock(return_value=[])
        a._replace_rule_records = Mock(side_effect=RuntimeError('failed'))
        self.assertFalse(a.allow_executable(exe, quiet=True))
        self.assertIn(exe, a.blocked_paths)
        dialog.destroy.assert_not_called()
        a.save_settings.assert_not_called()
        a.queue_alert.assert_called_once()

    def test_successful_allow_preserves_other_pending_prompt(self):
        a = app()
        exe = NS['normalize_path']('C:/one.exe')
        other = NS['normalize_path']('C:/two.exe')
        a.auto_prompt_keys = {exe, other}
        a.auto_prompt_key = other
        a.auto_prompt_dialog = Mock()
        a.prompt_queue.put(('pending', other))
        a.get_firewall_rules = Mock(return_value=[])
        a._replace_rule_records = Mock()
        self.assertTrue(a.allow_executable(exe, quiet=True))
        self.assertIn(other, a.auto_prompt_keys)
        self.assertEqual(a.prompt_queue.qsize(), 1)
        a.auto_prompt_dialog.destroy.assert_not_called()

    def test_failed_hold_cleanup_preserves_prompt(self):
        a = app()
        a.auto_prompt_keys = {'one'}
        a.prompt_queue.put((0, 'one'))
        a.remove_auto_holds_locked = Mock(side_effect=RuntimeError('denied'))
        with self.assertRaises(RuntimeError):
            a.release_auto_holds()
        self.assertEqual(a.auto_prompt_keys, {'one'})
        self.assertFalse(a.prompt_queue.empty())

    def test_cancel_only_removes_its_queued_decision(self):
        a = app()
        a.prompt_queue.put((0, 'one'))
        a.prompt_queue.put((0, 'two'))
        a._cancel_app_prompt('one')
        self.assertEqual(a.prompt_queue.get_nowait(), (0, 'two'))
        self.assertTrue(a.prompt_queue.empty())

    def test_global_creation_failure_restores_original(self):
        a = app()
        target = '192.0.2.1'
        old_base = a.global_rule_base(target, False)
        original = {old_base + '_' + side: {'name': old_base + '_' + side, 'action': 'Block',
                    'direction': direction, 'addresses': [target], 'is_global': True}
                    for side, direction in [('In', 'Inbound'), ('Out', 'Outbound')]}
        state = dict(original)
        a.get_firewall_rules = lambda: list(state.values())
        a.delete_rule_names = lambda names, strict=True: [state.pop(n, None) for n in list(names)]
        a._restore_app_rule_records = lambda rows: state.update((r['name'], r) for r in rows)
        a.resolve_global_target = lambda _: (target,)
        calls = 0
        def create(args):
            nonlocal calls
            calls += 1
            name = next(arg[5:] for arg in args if arg.startswith('name='))
            if calls == 2:
                raise RuntimeError('second direction failed')
            state[name] = {'name': name}
        a.run_netsh = create
        with self.assertRaisesRegex(RuntimeError, 'second direction failed'):
            a.add_global_rule_sync(target, True)
        self.assertEqual(state, original)

    def test_import_reports_batch_failure(self):
        a = app()
        a._apply_rule_batch = Mock(return_value=False)
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'rules.json'
            path.write_text(json.dumps({'rules': [{'path': 'C:/one.exe', 'action': 'Allow'},
                                                  {'path': 'C:/two.exe', 'action': 'Block'}]}))
            messages = types.SimpleNamespace(askyesno=Mock(return_value=True), showerror=Mock(), showinfo=Mock())
            with patch_dependencies(filedialog=types.SimpleNamespace(askopenfilename=lambda **kw: str(path)), messagebox=messages):
                a.import_rules()
            messages.showinfo.assert_not_called()
            self.assertEqual(messages.showerror.call_args.args[0], 'Import Incomplete')
            self.assertEqual(len(a._apply_rule_batch.call_args.args[0]), 2)
            self.assertTrue(a._apply_rule_batch.call_args.kwargs['quiet'])

    def test_release_serializes_with_hold_and_prompt_publication(self):
        a = app()
        entered, proceed = threading.Event(), threading.Event()
        holds = set()
        def install(*args):
            holds.add('one')
            entered.set()
            if not proceed.wait(2):
                raise RuntimeError('test timeout')
            return True
        a.install_auto_hold = install
        a.remove_auto_holds_locked = lambda *args: holds.clear()
        worker = threading.Thread(target=a.start_auto_block,
                                  args=('one', 'C:/one.exe', 1, '1.2.3.4', '', 'out', 'key', 'connection', ''))
        worker.start()
        self.assertTrue(entered.wait(2))
        release = threading.Thread(target=a.release_auto_holds)
        release.start()
        proceed.set()
        worker.join(3)
        release.join(3)
        self.assertFalse(worker.is_alive() or release.is_alive())
        self.assertEqual(holds, set())
        self.assertTrue(a.prompt_queue.empty())
        self.assertFalse(a.auto_prompt_keys)


class BatchRuleTests(unittest.TestCase):
    def test_temporary_hold_stays_until_permanent_block_is_verified(self):
        a = app()
        exe = NS['normalize_path']('C:/client.exe')
        previous = [{'name': 'hold', 'normalized_path': exe, 'is_hold': True}]
        events = []
        a.get_firewall_rules = lambda: previous
        a.add_app_rules = lambda *args, **kwargs: events.append('create_and_verify')
        a.delete_rule_names = lambda names: events.append(('delete', list(names)))
        self.assertTrue(a.block_executable(exe, direction='in', quiet=True))
        self.assertEqual(events, ['create_and_verify', ('delete', ['hold'])])
        self.assertTrue(a.blocked_paths[exe]['in'])
        self.assertFalse(a.blocked_paths[exe]['out'])

    def test_both_directions_use_one_process(self):
        a = app()
        a.run_ps = Mock()
        a._add_app_rules_individually = Mock()
        a.add_app_rules('client', "C:/a'b/client.exe", 'both')
        a.run_ps.assert_called_once()
        a._add_app_rules_individually.assert_not_called()
        command = a.run_ps.call_args.args[0]
        self.assertEqual(command.count('New-NetFirewallRule '), 2)
        self.assertEqual(command.count('Get-NetFirewallApplicationFilter '), 2)
        self.assertIn("'C:/a''b/client.exe'", command)

    def test_failed_batch_cleans_both_directions_before_fallback(self):
        a = app()
        a.run_ps = Mock(side_effect=RuntimeError('partial create'))
        events = []
        a.delete_rule_names = lambda names: events.append(('cleanup', names))
        a._add_app_rules_individually = lambda *args: events.append(('fallback', args))
        a.add_app_rules('client', 'C:/client.exe', 'both')
        self.assertEqual([e[0] for e in events], ['cleanup', 'fallback'])
        self.assertEqual(len(events[0][1]), 2)
        a.delete_rule_names = Mock(side_effect=RuntimeError('cleanup denied'))
        a._add_app_rules_individually = Mock()
        with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
            a.add_app_rules('client', 'C:/client.exe', 'both')
        a._add_app_rules_individually.assert_not_called()

    def test_delete_batch_and_fallback(self):
        a = app()
        a.run_ps = Mock(return_value=types.SimpleNamespace(stdout='removed\n'))
        a._delete_rule_names_individually = Mock(return_value=True)
        self.assertTrue(a.delete_rule_names(['one', 'two', 'one']))
        a.run_ps.assert_called_once()
        a._delete_rule_names_individually.assert_not_called()
        a.run_ps.side_effect = RuntimeError('partial delete')
        self.assertTrue(a.delete_rule_names(['one', 'two']))
        a._delete_rule_names_individually.assert_called_once_with(['one', 'two'], True)

    @unittest.skipUnless(shutil.which('powershell'), 'Windows PowerShell is required')
    def test_generated_batches_execute_against_fake_cmdlets(self):
        # Exercise real PowerShell parsing, quoting, pipeline deletion and verification
        # without importing NetSecurity or touching the live firewall.
        a = app()
        commands = []
        a.run_ps = lambda command: (commands.append(command) or types.SimpleNamespace(stdout='removed'))
        base = a.add_app_rules('client', "C:/a'b/client.exe", 'both')
        a.delete_rule_names([base + '_In', base + '_Out'])
        prelude = '''
$ErrorActionPreference='Stop'
$script:rules=@{}
function New-NetFirewallRule {
 param($Name,$DisplayName,$Direction,$Program,$Action,$Enabled,$Profile,$ErrorAction)
 $script:rules[$Name]=[pscustomobject]@{Name=$Name;DisplayName=$DisplayName;Direction=$Direction;Program=$Program;Action=$Action;Enabled=$Enabled}
}
function Get-NetFirewallRule {
 param($Name,$ErrorAction)
 if ($Name) {
   if (-not $script:rules.ContainsKey($Name)) { throw 'Missing rule' }
   $script:rules[$Name]
 } else { $script:rules.Values }
}
function Get-NetFirewallApplicationFilter {
 param($AssociatedNetFirewallRule,$ErrorAction)
 [pscustomobject]@{Program=$AssociatedNetFirewallRule.Program}
}
function Remove-NetFirewallRule {
 param([Parameter(ValueFromPipeline=$true)]$InputObject)
 process { $script:rules.Remove($InputObject.Name) }
}
'''
        script = prelude + commands[0] + "\nif ($script:rules.Count -ne 2) {throw 'Missing direction'}\n" + commands[1]
        script += "\nif ($script:rules.Count) {throw 'Deletion failed'}\n'passed'"
        result = NS['subprocess'].run(['powershell', '-NoProfile', '-Command', script],
                                      capture_output=True, text=True, timeout=30,
                                      creationflags=NS['CREATE_NO_WINDOW'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['removed', 'passed'])
        # A disabled rule's enum/string value must not pass a truthiness check.
        create, verify = a._app_rule_commands('disabled', 'C:/client.exe', 'in')
        result = NS['subprocess'].run(['powershell', '-NoProfile', '-Command',
            prelude + create + "\n$script:rules['disabled'].Enabled='False'\n" + verify],
            capture_output=True, text=True, timeout=30, creationflags=NS['CREATE_NO_WINDOW'])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Firewall rule is disabled', result.stderr)


class BulkOperationTests(unittest.TestCase):
    def test_selected_removal_uses_one_snapshot_and_delete_for_all_records(self):
        a = app()
        a.rules_tree = object()
        first, second = (NS['normalize_path'](p) for p in ('C:/one.exe', 'C:/two.exe'))
        base = a.global_rule_base('192.0.2.1', False)
        records = [{'name': 'one', 'normalized_path': first},
                   {'name': 'two', 'normalized_path': second},
                   {'name': base + '_In', 'normalized_path': ''},
                   {'name': base + '_Out', 'normalized_path': ''},
                   {'name': 'unselected', 'normalized_path': 'other'}]
        a.blocked_paths = {first: {}, second: {}}
        a.global_blocks = {'192.0.2.1': {}}
        a.get_firewall_rules = Mock(return_value=records)
        a.run_ps = Mock(return_value=types.SimpleNamespace(stdout='removed'))
        a.selected_rows = Mock(return_value=[
            (str(i), (status, '', '', '', '', path)) for i, (status, path) in enumerate([
                ('Block', first), ('Block', second), ('Block', first),
                ('Global Block', '192.0.2.1 (192.0.2.1)')])])
        a.remove_selected_rule()
        a.get_firewall_rules.assert_called_once()
        a.run_ps.assert_called_once()
        command = a.run_ps.call_args.args[0]
        for record in records[:-1]:
            self.assertIn(a._ps_quote(record['name']), command)
        self.assertNotIn('unselected', command)
        self.assertFalse(a.blocked_paths or a.global_blocks)
        a.save_settings.assert_called_once()
        a.rules_changed.assert_called_once()

    def test_connection_and_alert_removals_collect_requests(self):
        for source in ('connections', 'alerts'):
            with self.subTest(source=source):
                a = app()
                a._remove_rule_batch = Mock()
                a.get_rule_status = Mock(return_value='Block')
                rows = [{'exe': 'C:/one.exe'}, {'exe': 'C:/two.exe'}]
                if source == 'connections':
                    a.selected_connection_data = Mock(return_value=rows)
                    a.remove_selected_connection_rules(object())
                else:
                    a.alerts_tree = object()
                    a.selected_rows = Mock(return_value=[('1', rows[0]), ('2', rows[1])])
                    a.alert_context = lambda row: (row, '')
                    a.remove_selected_alert_rules()
                a._remove_rule_batch.assert_called_once_with([
                    ('Block', 'C:/one.exe'), ('Block', 'C:/two.exe')])

    def test_failed_delete_preserves_caches_and_prompts(self):
        a = app()
        norm = NS['normalize_path']('C:/one.exe')
        a.blocked_paths[norm] = {'in': True, 'out': True}
        a.get_firewall_rules = Mock(return_value=[])
        a._replace_rule_records = Mock(side_effect=RuntimeError('denied'))
        a._cancel_app_prompt = Mock()
        with patch_dependencies(messagebox=types.SimpleNamespace(showerror=Mock())):
            self.assertFalse(a._remove_rule_batch([('Block', norm)]))
        self.assertIn(norm, a.blocked_paths)
        a._cancel_app_prompt.assert_not_called()
        a.save_settings.assert_not_called()

    def test_many_additions_use_one_creation_process_and_one_save(self):
        a = app()
        a.get_firewall_rules = Mock(return_value=[])
        a.run_ps = Mock()
        a.run_netsh = Mock(side_effect=AssertionError('No per-rule process'))
        requests = [(f'C:/app{i}.exe', False, 'both', False) for i in range(100)]
        self.assertTrue(a._apply_rule_batch(requests, quiet=True))
        a.get_firewall_rules.assert_called_once()
        a.run_ps.assert_called_once()
        self.assertEqual(len(a.blocked_paths), 100)
        a.save_settings.assert_called_once()
        a.rules_changed.assert_called_once()
        a.run_netsh.assert_not_called()

    def test_conflicting_entries_use_last_action_before_duplicate_check(self):
        a = app()
        path = NS['normalize_path']('C:/one.exe')
        a.allowed_apps.add(path)
        a._commit_rule_batch = Mock()
        self.assertTrue(a._apply_rule_batch([(path, False, 'in', False),
                                           (path, True, 'both', False)], quiet=True))
        a._commit_rule_batch.assert_not_called()
        a.save_settings.assert_not_called()

    def test_mixed_replacement_keeps_holds_until_creation_and_verification(self):
        a = app()
        path = NS['normalize_path']('C:/one.exe')
        base = a.app_rule_base(None, path)
        records = [{'name': base + '_In', 'normalized_path': path},
                   {'name': 'hold', 'normalized_path': path, 'is_hold': True}]
        state = {r['name'] for r in records}
        a.get_firewall_rules = Mock(return_value=records)
        def delete(names):
            state.difference_update(names)
        def create(rules):
            self.assertEqual(state, {'hold'})
            state.update(r['name'] for r in rules)
        a.delete_rule_names = delete
        a._create_rule_batch = create
        a._commit_rule_batch([(path, False, 'both', False)])
        self.assertEqual(state, {base + '_In', base + '_Out'})

    def test_partial_creation_rolls_back_entire_batch_without_publishing_cache(self):
        a = app()
        path = NS['normalize_path']('C:/one.exe')
        original = {'old': {'name': 'old', 'normalized_path': path}}
        state = dict(original)
        a.blocked_paths[path] = {'in': True, 'out': False}
        a.get_firewall_rules = lambda: list(state.values())
        a.delete_rule_names = lambda names: [state.pop(n, None) for n in list(names)]
        a._restore_app_rule_records = lambda rows: state.update((r['name'], r) for r in rows)
        def create(rules):
            state[rules[0]['name']] = rules[0]
            raise RuntimeError('creation failed')
        a._create_rule_batch = create
        with patch_dependencies(log_internal_error=Mock()):
            self.assertFalse(a._apply_rule_batch([(path, False, 'both', False),
                                                 ('C:/two.exe', False, 'out', False)], quiet=True))
        self.assertEqual(state, original)
        self.assertEqual(a.blocked_paths, {path: {'in': True, 'out': False}})
        a.save_settings.assert_not_called()
        a.rules_changed.assert_not_called()

    def test_dns_failure_happens_before_any_firewall_mutation(self):
        a = app()
        a.resolve_global_target = Mock(side_effect=ValueError('DNS unavailable'))
        a.get_firewall_rules = Mock()
        a._create_rule_batch = Mock()
        with patch_dependencies(log_internal_error=Mock()):
            self.assertFalse(a._apply_rule_batch([('C:/one.exe', False, 'both', False),
                                                 ('example.test', True, 'both', True)], quiet=True))
        a.get_firewall_rules.assert_not_called()
        a._create_rule_batch.assert_not_called()
        self.assertFalse(a.blocked_paths or a.global_allows)

    def test_mixed_batch_replaces_opposite_global_action_and_releases_holds(self):
        a = app()
        target = '192.0.2.1'
        old_base = a.global_rule_base(target, False)
        new_base = a.global_rule_base(target, True)
        a.global_blocks[target] = {'addresses': (target,)}
        records = [{'name': old_base + '_In', 'normalized_path': ''},
                   {'name': old_base + '_Out', 'normalized_path': ''},
                   {'name': 'pending_hold', 'normalized_path': 'other', 'is_hold': True},
                   {'name': 'unrelated', 'normalized_path': 'keep'}]
        state = {r['name'] for r in records}
        a.get_firewall_rules = Mock(return_value=records)
        a.delete_rule_names = lambda names: state.difference_update(names)
        def create(rules):
            self.assertIn('pending_hold', state)
            state.update(r['name'] for r in rules)
        a._create_rule_batch = Mock(side_effect=create)
        def invalidate(**kwargs):
            self.assertTrue(a.firewall_lock._is_owned())
            self.assertNotIn('pending_hold', state)
        a._invalidate_auto_prompts = Mock(side_effect=invalidate)
        self.assertTrue(a._apply_rule_batch([('C:/one.exe', False, 'out', False),
                                             (target, True, 'both', True)], quiet=True))
        base = a.app_rule_base(None, NS['display_path']('C:/one.exe'))
        self.assertEqual(state, {'unrelated', base + '_Out', new_base + '_In', new_base + '_Out'})
        self.assertEqual(a.global_allows[target], {'addresses': (target,), 'direction': 'Both'})
        self.assertFalse(a.global_blocks)
        a.get_firewall_rules.assert_called_once()
        a._create_rule_batch.assert_called_once()
        a._invalidate_auto_prompts.assert_called_once_with(close_dialog=True)
        a.save_settings.assert_called_once()

    def test_startup_restoration_batches_pending_rules(self):
        a = app()
        a.pending_rules = [{'path': 'C:/one.exe', 'direction': 'Both'},
                           {'path': 'C:/two.exe', 'direction': 'Outbound'}]
        a.global_allows = {'192.0.2.1': {}}
        a.get_firewall_rules = Mock(return_value=[])
        a.run_ps = Mock()
        a.restore_saved_rules_locked()
        a.get_firewall_rules.assert_called_once()
        a.run_ps.assert_called_once()
        self.assertEqual(a.pending_rules, [])
        self.assertEqual(len(a.blocked_paths), 2)
        self.assertEqual(a.global_allows['192.0.2.1']['addresses'], ('192.0.2.1',))

    def test_import_combines_apps_and_both_global_actions(self):
        a = app()
        a._apply_rule_batch = Mock(return_value=True)
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'rules.json'
            path.write_text(json.dumps({'managed_rules': [{'path': 'C:/one.exe', 'direction': 'Inbound'},
                                                          {'path': 'C:/two.exe', 'action': 'Allow'}],
                                        'global_ip_blocks': [{'target': '192.0.2.1'}],
                                        'global_ip_allows': ['2001:db8::1']}))
            messages = types.SimpleNamespace(askyesno=Mock(return_value=True), showinfo=Mock(), showerror=Mock())
            with patch_dependencies(messagebox=messages, filedialog=types.SimpleNamespace(
                    askopenfilename=lambda **kwargs: str(path))):
                a.import_rules()
        a._apply_rule_batch.assert_called_once_with([
            (NS['display_path']('C:/one.exe'), False, 'Inbound', False),
            (NS['display_path']('C:/two.exe'), True, 'Both', False),
            ('192.0.2.1', False, 'both', True), ('2001:db8::1', True, 'both', True)], quiet=True)
        messages.showerror.assert_not_called()
        messages.showinfo.assert_called_once()

    def test_large_scripts_use_temporary_file_and_clean_up_on_failure(self):
        a = app()
        command = "# Unicode: \u00e9\n" * 2000
        paths = []
        def run(args, check, **kwargs):
            self.assertEqual(args[-2], '-File')
            path = pathlib.Path(args[-1])
            paths.append(path)
            self.assertEqual(path.read_text(encoding='utf-8-sig'), command)
            self.assertEqual(kwargs['timeout'], 90)
            raise RuntimeError('test failure')
        a._run = run
        with self.assertRaisesRegex(RuntimeError, 'test failure'):
            a.run_ps(command, timeout=90)
        self.assertFalse(paths[0].exists())

    @unittest.skipUnless(shutil.which('powershell'), 'Windows PowerShell is required')
    def test_mixed_creation_script_with_fake_cmdlets_and_address_normalization(self):
        a = app()
        a.run_ps = Mock()
        rules = [{'name': 'app_in', 'path': "C:/a'b/$app.exe", 'action': 'Block', 'direction': 'Inbound'},
                 {'name': 'app_out', 'path': 'C:/\u00e9.exe', 'action': 'Block', 'direction': 'Outbound'},
                 {'name': 'global_in', 'path': '', 'addresses': ['192.0.2.0/24', '2001:db8::1'],
                  'action': 'Allow', 'direction': 'Inbound'}]
        a._create_rule_batch(rules)
        command = a.run_ps.call_args.args[0]
        prelude = '''
$script:created=@{}
function New-NetFirewallRule {
 param($Name,$DisplayName,$Direction,$Program,$Action,$Enabled,$Profile,$RemoteAddress,$ErrorAction)
 $script:created[$Name]=[pscustomobject]@{Name=$Name;Direction=$Direction;Program=$Program;Action=$Action;Enabled=$Enabled}
}
function Get-NetFirewallRule {
 param($Name,$ErrorAction)
 if (-not $script:created.ContainsKey($Name)) { throw 'Missing rule' }
 $script:created[$Name]
}
function Get-NetFirewallApplicationFilter {
 param($AssociatedNetFirewallRule,$ErrorAction)
 [pscustomobject]@{Program=$AssociatedNetFirewallRule.Program}
}
function Get-NetFirewallAddressFilter {
 param($AssociatedNetFirewallRule,$ErrorAction)
 [pscustomobject]@{RemoteAddress=@('192.0.2.0/255.255.255.0','2001:0db8:0:0:0:0:0:1/128')}
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'fake.ps1'
            path.write_text(prelude + command + "\nif ($script:created.Count -ne 3) {throw 'Missing rule'}\n'passed'",
                            encoding='utf-8-sig')
            result = NS['subprocess'].run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(path)],
                                          capture_output=True, text=True, timeout=30,
                                          creationflags=NS['CREATE_NO_WINDOW'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'passed')


class DecisionTests(unittest.TestCase):
    def test_worker_preserves_direction_and_never_updates_ui(self):
        for choice, direction in [('allow', None), ('in', 'in'), ('both', 'both')]:
            with self.subTest(choice=choice):
                a = app()
                a.auto_prompt_key = 'key'
                a.allow_executable = Mock(return_value=True)
                a.block_executable = Mock(return_value=True)
                result = queue.Queue()
                a._auto_decision_worker(0, 'key', 'C:/client.exe', 'client', choice, result)
                self.assertTrue(result.get_nowait())
                if direction is None:
                    a.allow_executable.assert_called_once_with('C:/client.exe', refresh=False, quiet=True, update_ui=False)
                else:
                    a.block_executable.assert_called_once_with('C:/client.exe', 'client', direction,
                                                              refresh=False, quiet=True, update_ui=False)

    def test_stale_or_closed_decision_does_not_mutate(self):
        for generation, closed, key in [(1, False, 'key'), (0, True, 'key'), (0, False, 'other')]:
            a = app()
            a.auto_prompt_generation, a.closed, a.auto_prompt_key = generation, closed, key
            a.allow_executable = Mock()
            result = queue.Queue()
            a._auto_decision_worker(0, 'key', 'C:/client.exe', 'client', 'allow', result)
            self.assertIsNone(result.get_nowait())
            a.allow_executable.assert_not_called()

    def test_background_allow_leaves_dialog_to_ui(self):
        a = app()
        exe = NS['normalize_path']('C:/client.exe')
        a.auto_prompt_key = exe
        a.auto_prompt_dialog = Mock()
        a.get_firewall_rules = Mock(return_value=[])
        a._replace_rule_records = Mock()
        self.assertTrue(a.allow_executable(exe, quiet=True, update_ui=False))
        self.assertIn(exe, a.allowed_apps)
        a.auto_prompt_dialog.destroy.assert_not_called()
        a.rules_changed.assert_not_called()
        a.save_settings.assert_called_once()

    def test_decision_rechecks_cancellation_after_waiting_for_firewall(self):
        a = app()
        a.auto_prompt_key = 'key'
        a.allow_executable = Mock()
        result = queue.Queue()
        with a.firewall_lock:
            worker = threading.Thread(target=a._auto_decision_worker,
                                      args=(0, 'key', 'C:/client.exe', 'client', 'allow', result))
            worker.start()
            a._invalidate_auto_prompts(close_dialog=True)
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertIsNone(result.get_nowait())
        a.allow_executable.assert_not_called()

    def test_prompt_is_responsive_and_retries_only_after_failure(self):
        a = app()
        a.rules_generation = 0
        a.colors = {'frame': 'white', 'fg': 'black'}
        a.root = Mock()
        callbacks, widgets, workers = [], [], []
        a.root.after.side_effect = lambda delay, callback: callbacks.append(callback)
        a._theme_dialog = a._center_dialog = a._bind_button_hover = Mock()
        entered, proceed = threading.Event(), threading.Event()
        def apply(*args, **kwargs):
            entered.set()
            if not proceed.wait(3):
                raise RuntimeError('test timeout')
            return False
        a.allow_executable = Mock(side_effect=apply)
        real_thread = threading.Thread
        def start_thread(**kwargs):
            worker = real_thread(**kwargs)
            workers.append(worker)
            return worker
        def widget(*args, **kwargs):
            w = Mock()
            w.options = kwargs
            widgets.append(w)
            return w
        fake_tk = types.SimpleNamespace(**{name: widget for name in ('Toplevel', 'Frame', 'Label', 'Button')},
                                       BOTH='both', X='x', LEFT='left', W='w', DISABLED='disabled', NORMAL='normal')
        messages = types.SimpleNamespace(showerror=Mock())
        with patch_dependencies(tk=fake_tk, add_tooltip=Mock(), messagebox=messages), \
             patch.object(NS['threading'], 'Thread', side_effect=start_thread):
            a.show_auto_prompt(0, 'key', 'client', 'C:/client.exe', 1, '192.0.2.1', 'connection', '')
            dialog = a.auto_prompt_dialog
            allow = next(w for w in widgets if w.options.get('text') == 'Allow All')
            try:
                allow.options['command']()
                self.assertTrue(entered.wait(2))
                allow.configure.assert_called_with(state='disabled')
                allow.options['command']()  # Duplicate click must not create a worker.
                self.assertEqual(len(workers), 1)
                callbacks.pop(0)()  # UI callback returns even with worker blocked.
                dialog.destroy.assert_not_called()
            finally:
                proceed.set()
                workers[0].join(3)
            callbacks.pop(0)()
            allow.configure.assert_called_with(state='normal')
            messages.showerror.assert_called_once()
            dialog.destroy.assert_not_called()
            a.allow_executable.side_effect = None
            a.allow_executable.return_value = True
            allow.options['command']()
            workers[-1].join(3)
            callbacks.pop(0)()
            dialog.destroy.assert_called_once()
            self.assertEqual(a.rules_changed.call_count, 2)


class AddressTests(unittest.TestCase):
    def test_cidr_and_ipv6(self):
        a = app()
        collection = {'10.0.0.0/24': {'addresses': ()}, 'example.test': {'addresses': ('2001:db8::1',)}}
        self.assertTrue(a._global_match(collection, '10.0.0.8', ''))
        self.assertFalse(a._global_match(collection, '10.0.1.8', ''))
        self.assertTrue(a._global_match(collection, '2001:0db8:0:0:0:0:0:1', ''))
        self.assertFalse(a._global_match(collection, '192.0.2.1', 'example.test'))

    def test_remote_port_cannot_match_local_wildcard(self):
        a = app()
        a.refresh_process_cache = Mock()
        a.local_addresses = {'192.168.1.3'}
        a.socket_process_cache = {}
        a.listener_process_cache = {(2, 'UDP', '0.0.0.0', 53): {123}}
        self.assertEqual(a.get_process_info('203.0.113.10', 53, '192.168.1.3', 50000, 'UDP', 2), (None, None, None))

    def test_shared_listener_ownership_is_rejected(self):
        a = app()
        a.refresh_process_cache = Mock()
        a.local_addresses = {'192.168.1.3'}
        a.socket_process_cache = {}
        a.listener_process_cache = {(2, 'UDP', '0.0.0.0', 53): {123, 456}}
        self.assertEqual(a.get_process_info('192.168.1.3', 53, '203.0.113.10', 50000, 'UDP', 2), (None, None, None))

    def test_exact_socket_wins_over_listener(self):
        a = app()
        a.refresh_process_cache = Mock()
        a.local_addresses = {'192.168.1.3'}
        a.socket_process_cache = {(2, 'UDP', '192.168.1.3', 53, '203.0.113.10', 50000): {456}}
        a.listener_process_cache = {(2, 'UDP', '0.0.0.0', 53): {123}}
        process = types.SimpleNamespace(name=lambda: 'client', exe=lambda: 'C:/client.exe')
        psutil = types.SimpleNamespace(Process=lambda pid: process)
        with patch_dependencies(psutil=psutil):
            self.assertEqual(a.get_process_info('192.168.1.3', 53, '203.0.113.10', 50000, 'UDP', 2), ('client', 'C:/client.exe', 456))


class CaptureStatusTests(unittest.TestCase):
    def setUp(self):
        self.a = app()
        a = self.a
        a.startup_complete = True
        a.captured_bytes = a.captured_packets = a.total_download = a.total_upload = 0
        a.capture_rate = a.capture_pps = 0
        a._last_status_time = a._last_capture_bytes = a._last_capture_packets = 0
        a.active_connections = {}
        a.rule_rows = []
        for name in ('status_state', 'status_firewall', 'status_connections', 'status_rules',
                     'status_capture', 'status_traffic', 'btn_pause', 'pause_border'):
            setattr(a, name, Mock())
        a._set_button_colors = Mock()
        a.update_auto_block_controls = Mock()
        a.update_filter_ui = Mock()
        a.render_all = Mock()
        a.release_auto_holds = Mock()
        a._invalidate_auto_prompts = Mock()

    def assert_capture_failed(self):
        a = self.a
        a.status_state.config.assert_called_with(text='Capture failed', fg='#f44336')
        a.btn_pause.configure.assert_called_with(text='▶  Resume Monitoring')
        a._set_button_colors.assert_called_with(
            a.btn_pause, a.pause_border, '#9E9E9E', '#ffffff', NS['tk'].NORMAL)

    def test_startup_capture_failure_and_automatic_recovery_update_button(self):
        a = self.a
        a.capture_error = 'Npcap exposes no active non-loopback IP adapter.'
        a.update_status()
        self.assert_capture_failed()
        self.assertFalse(a.is_paused)  # Automatic retries remain enabled.
        a.capture_healthy = True
        a.capture_error = None
        a.update_status()
        a.status_state.config.assert_called_with(text='Monitoring', fg='#4CAF50')
        a.btn_pause.configure.assert_called_with(text='⏸  Pause Monitoring')
        a._set_button_colors.assert_called_with(
            a.btn_pause, a.pause_border, '#2196F3', '#ffffff', NS['tk'].NORMAL)

    def test_resume_failure_and_repeated_resume_keep_button_grey(self):
        a = self.a
        a.is_paused = True
        a.toggle_pause()
        self.assertFalse(a.is_paused)
        a.capture_error = 'No adapter'
        a.update_status()
        self.assert_capture_failed()
        a.toggle_pause()
        self.assertFalse(a.is_paused)
        self.assert_capture_failed()
        a.release_auto_holds.assert_not_called()

    def test_healthy_capture_can_still_be_paused(self):
        a = self.a
        a.capture_healthy = True
        a.toggle_pause()
        self.assertTrue(a.is_paused)
        a.status_state.config.assert_called_with(text='Paused', fg='#ff9800')
        a.btn_pause.configure.assert_called_with(text='▶  Resume Monitoring')
        a.release_auto_holds.assert_called_once()


class CaptureTests(unittest.TestCase):
    @staticmethod
    def interface(name, address='192.0.2.10', valid=True):
        return types.SimpleNamespace(name=name, description=name, network_name='NPF_' + name,
                                     ips={4: [address], 6: []}, is_valid=lambda: valid)

    def capture_config(self, interfaces, opener):
        table = Mock()
        table.values.return_value = interfaces
        return types.SimpleNamespace(use_pcap=True, ifaces=table, route=Mock(), route6=Mock(),
                                     iface=interfaces[0], loopback_name='NPF_loopback', L2listen=opener)

    def test_stale_default_falls_back_to_valid_adapter(self):
        a = app()
        a.sniffing = True
        stale, good = self.interface('stale'), self.interface('wifi')
        sock = Mock(closed=False)
        opener = Mock(side_effect=[OSError('Network interface was not found. (2150891563)'), sock])
        config = self.capture_config([stale, good], opener)
        with patch_dependencies(conf=config, psutil=types.SimpleNamespace(net_if_stats=lambda: {})):
            self.assertIs(a._open_capture_socket(), sock)
        config.ifaces.reload.assert_called_once()
        self.assertEqual([c.kwargs['iface'].name for c in opener.call_args_list], ['stale', 'wifi'])
        self.assertEqual(opener.call_args.kwargs['filter'], 'ip or ip6')
        self.assertFalse(opener.call_args.kwargs['promisc'])
        self.assertIn('wifi', a.capture_interface)

    def test_discovery_skips_down_invalid_and_loopback_but_accepts_ipv6(self):
        a = app()
        a.sniffing = True
        interfaces = [self.interface('loopback', '127.0.0.1'), self.interface('invalid', valid=False),
                      self.interface('down'), self.interface('ipv6', '::')]
        interfaces[-1].ips = {4: [], 6: ['2001:db8::1']}
        opener = Mock()
        config = self.capture_config(interfaces, opener)
        with patch_dependencies(conf=config, psutil=types.SimpleNamespace(
                net_if_stats=lambda: {'down': types.SimpleNamespace(isup=False)})):
            a._open_capture_socket()
        opener.assert_called_once()
        self.assertIs(opener.call_args.kwargs['iface'], interfaces[-1])

    def test_loopback_only_does_not_claim_internet_capture_is_healthy(self):
        a = app()
        a.sniffing = True
        config = self.capture_config([self.interface('loopback', '127.0.0.1')], Mock())
        with patch_dependencies(conf=config, psutil=types.SimpleNamespace(net_if_stats=lambda: {})):
            with self.assertRaisesRegex(OSError, 'Npcap exposes no active non-loopback IP adapter'):
                a._open_capture_socket()
        config.L2listen.assert_not_called()

    def test_failure_is_visible_and_recovery_clears_it(self):
        a = app()
        a.sniffing = True
        a.packet_handler = Mock()
        first, second = Mock(closed=False), Mock(closed=False)
        a._open_capture_socket = Mock(side_effect=[first, second])
        a._capture_wait = Mock()
        calls = 0
        def sniff(**kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError('capture unavailable')
            self.assertFalse(a.capture_healthy)
            self.assertEqual(a.capture_error, 'capture unavailable')
            a.closed = True
        with patch_dependencies(sniff=sniff, log_internal_error=Mock()), patch.object(NS['time'], 'sleep'):
            a.start_sniffing()
        self.assertTrue(a.capture_healthy)
        self.assertIsNone(a.capture_error)
        self.assertEqual(a.queue_alert.call_count, 2)
        first.close.assert_called_once()
        second.close.assert_called_once()
        self.assertEqual(a._open_capture_socket.call_count, 2)

    def test_scapy_silently_closed_socket_is_reopened(self):
        a = app()
        a.sniffing = True
        a.packet_handler = Mock()
        first, second = Mock(closed=True), Mock(closed=False)
        a._open_capture_socket = Mock(side_effect=[first, second])
        a._capture_wait = Mock()
        def sniff(**kwargs):
            if kwargs['opened_socket'] is second:
                a.closed = True
        with patch_dependencies(sniff=sniff, log_internal_error=Mock()):
            a.start_sniffing()
        self.assertTrue(a.capture_healthy)
        self.assertEqual(a._open_capture_socket.call_count, 2)
        self.assertEqual(a.queue_alert.call_count, 2)

    def test_persistent_failure_uses_capped_backoff_and_one_alert(self):
        a = app()
        a.sniffing = True
        a._open_capture_socket = Mock(side_effect=OSError('No adapter'))
        delays = []
        def wait(delay):
            delays.append(delay)
            if len(delays) == 7:
                a.closed = True
        a._capture_wait = wait
        with patch_dependencies(log_internal_error=Mock()):
            a.start_sniffing()
        self.assertEqual(delays, [1, 2, 4, 8, 16, 30, 30])
        self.assertFalse(a.capture_healthy)
        a.queue_alert.assert_called_once()

    def test_periodic_discovery_replaces_socket_and_closes_on_shutdown(self):
        a = app()
        a.sniffing = True
        a.packet_handler = Mock()
        first, second = Mock(closed=False), Mock(closed=False)
        a._open_capture_socket = Mock(side_effect=[first, second])
        def sniff(**kwargs):
            if kwargs['opened_socket'] is second:
                a.closed = True
        with patch_dependencies(sniff=sniff), patch.object(NS['time'], 'monotonic', side_effect=[0, 31, 31]):
            a.start_sniffing()
        first.close.assert_called_once()
        second.close.assert_called_once()


class DuplicateRuleTests(unittest.TestCase):
    def setUp(self):
        self.a = app()
        self.a.get_firewall_rules = Mock(side_effect=AssertionError('Unexpected firewall query'))
        self.a.run_ps = Mock(side_effect=AssertionError('Unexpected PowerShell call'))
        self.a.run_netsh = Mock(side_effect=AssertionError('Unexpected netsh call'))
        self.path = NS['normalize_path']('C:/Apps/Test.exe')
        self.messages = types.SimpleNamespace(showwarning=Mock(), showerror=Mock())

    def test_duplicate_block_and_allow_skip_all_firewall_io(self):
        a = self.a
        for direction, flags in [('in', (True, False)), ('out', (False, True)), ('both', (True, True))]:
            a.blocked_paths[self.path] = dict(zip(('in', 'out'), flags))
            with patch_dependencies(messagebox=self.messages):
                self.assertTrue(a.block_executable('c:/APPS/TEST.exe', direction=direction))
        a.blocked_paths.clear()
        a.allowed_apps.add(self.path)
        with patch_dependencies(messagebox=self.messages):
            self.assertTrue(a.allow_executable('C:/Apps/./Test.exe'))
        self.assertEqual(self.messages.showwarning.call_count, 4)
        a.get_firewall_rules.assert_not_called()
        a.run_ps.assert_not_called()
        a.run_netsh.assert_not_called()
        a.save_settings.assert_not_called()
        a.rules_changed.assert_not_called()

    def test_duplicate_does_not_wait_for_firewall_worker_lock(self):
        a = self.a
        a.allowed_apps.add(self.path)
        a.firewall_lock = Mock()  # Entering this non-context-manager would fail.
        with patch_dependencies(messagebox=self.messages):
            self.assertTrue(a.allow_executable(self.path))
        self.messages.showerror.assert_not_called()
        self.messages.showwarning.assert_called_once()

    def test_duplicate_is_rechecked_after_serializing_with_another_writer(self):
        a = self.a
        path = self.path
        class OtherWriter:
            def __enter__(self):
                a.blocked_paths[path] = {'in': True, 'out': True}
            def __exit__(self, *args):
                return False
        a.firewall_lock = OtherWriter()
        with patch_dependencies(messagebox=self.messages):
            self.assertTrue(a.block_executable(path))
        a.get_firewall_rules.assert_not_called()
        self.messages.showwarning.assert_called_once()

    def test_direction_change_and_opposite_action_are_not_duplicates(self):
        a = self.a
        a.blocked_paths[self.path] = {'in': True, 'out': True}
        self.assertFalse(a._rule_is_duplicate(self.path, direction='in'))
        self.assertFalse(a._rule_is_duplicate(self.path, allow=True))
        a.blocked_paths[self.path]['out'] = False
        self.assertFalse(a._rule_is_duplicate(self.path, direction='both'))
        a.blocked_paths.clear()  # Temporary auto-holds are not permanent blocks.
        self.assertFalse(a._rule_is_duplicate(self.path))

    def test_batch_warns_once_without_refresh_for_all_duplicates(self):
        a = self.a
        a.blocked_paths[self.path] = {'in': True, 'out': True}
        other = NS['normalize_path']('C:/other.exe')
        a.blocked_paths[other] = {'in': True, 'out': True}
        a.block_executable = Mock()
        with patch_dependencies(messagebox=self.messages):
            a._apply_rule_batch([(self.path, False, 'both', False),
                                 (other, False, 'both', False), (self.path.upper(), False, 'both', False)])
        self.messages.showwarning.assert_called_once()
        self.assertIn('Skipped 2', self.messages.showwarning.call_args.args[1])
        a.block_executable.assert_not_called()
        a.rules_changed.assert_not_called()

    def test_mixed_batch_applies_only_new_rule(self):
        a = self.a
        a.allowed_apps.add(self.path)
        a._commit_rule_batch = Mock(return_value=({}, False))
        with patch_dependencies(messagebox=self.messages):
            a._apply_rule_batch([(self.path, True, 'both', False), ('C:/new.exe', True, 'both', False)])
        a._commit_rule_batch.assert_called_once_with([(NS['display_path']('C:/new.exe'), True, 'both', False)])
        a.save_settings.assert_called_once()
        a.rules_changed.assert_called_once()

    def test_custom_app_rule_uses_duplicate_fast_path(self):
        a = self.a
        a.allowed_apps.add(self.path)
        a.ask_direction = Mock(return_value='allow')
        with patch_dependencies(messagebox=self.messages, filedialog=types.SimpleNamespace(
                askopenfilename=lambda **kw: self.path)):
            a.add_custom_rule()
        self.messages.showwarning.assert_called_once()
        a.get_firewall_rules.assert_not_called()

    def test_connection_context_menu_uses_duplicate_preflight(self):
        a = self.a
        a.tree = object()
        a.selected_connection_data = Mock(return_value=[{'exe': self.path, 'name': 'Test'}])
        a.blocked_paths[self.path] = {'in': True, 'out': True}
        with patch_dependencies(messagebox=self.messages):
            a.block_process(direction='both')
        self.messages.showwarning.assert_called_once()
        a.get_firewall_rules.assert_not_called()
        a.rules_changed.assert_not_called()

    def test_duplicate_global_rule_skips_dns_and_firewall_calls(self):
        a = self.a
        a.global_blocks['example.com'] = {'addresses': ('192.0.2.1',)}
        a.add_global_rule_sync = Mock()
        with patch_dependencies(messagebox=self.messages):
            self.assertTrue(a.add_global_rule('EXAMPLE.COM.', False))
        a.add_global_rule_sync.assert_not_called()
        a.rules_changed.assert_not_called()
        self.assertEqual(NS['normalize_target']('192.0.2.123/24'), '192.0.2.0/24')


class ContextGlobalRuleTests(unittest.TestCase):
    def setUp(self):
        self.a = app()
        self.a.active_connections = {}
        self.messages = types.SimpleNamespace(showwarning=Mock(), showerror=Mock(),
                                              showinfo=Mock(), askyesno=Mock(return_value=True))
        patches = ExitStack()
        self.addCleanup(patches.close)
        patches.enter_context(patch_dependencies(messagebox=self.messages))

    def test_managed_global_block_prompts_for_direction_before_applying(self):
        a = self.a
        a.root = object()
        for target in ('example.test', '192.0.2.1'):
            for direction in ('both', 'in', None):
                with self.subTest(target=target, direction=direction):
                    a.ask_direction = Mock(return_value=direction)
                    a.add_global_rule = Mock()
                    with patch_dependencies(simpledialog=types.SimpleNamespace(askstring=Mock(return_value=target))):
                        a.add_global_target('Block')
                    a.ask_direction.assert_called_once()
                    self.assertIn(target, a.ask_direction.call_args.args[0])
                    self.assertEqual(a.ask_direction.call_args.kwargs['block_labels'],
                                     ('Block All', 'Block Only Incoming'))
                    if direction:
                        a.add_global_rule.assert_called_once_with(target, False, direction=direction)
                    else:
                        a.add_global_rule.assert_not_called()

    def test_managed_global_target_cancel_or_blank_does_not_prompt_or_apply(self):
        a = self.a
        a.root = object()
        a.ask_direction = Mock()
        a.add_global_rule = Mock()
        for target in (None, '', '   '):
            with patch_dependencies(simpledialog=types.SimpleNamespace(askstring=Mock(return_value=target))):
                a.add_global_target('Block')
        a.ask_direction.assert_not_called()
        a.add_global_rule.assert_not_called()

    def test_managed_global_allow_still_applies_both_directions_without_block_prompt(self):
        a = self.a
        a.root = object()
        a.ask_direction = Mock()
        a.add_global_rule = Mock()
        with patch_dependencies(simpledialog=types.SimpleNamespace(askstring=Mock(return_value=' example.test '))):
            a.add_global_target('Allow')
        a.ask_direction.assert_not_called()
        a.add_global_rule.assert_called_once_with('example.test', True, direction='both')

    def test_live_and_active_columns_group_domain_and_observed_ip(self):
        for status_column in (False, True):
            for domain in ('example.test', '', '\u2014'):
                with self.subTest(status_column=status_column, domain=domain):
                    columns = ['#', 'Process Name', 'PID', 'Direction', 'Protocol', 'Local Port',
                               'Remote IP', 'Remote Host', 'Remote Port', 'Exe Path']
                    values = [1, 'App', 42, 'Outgoing', 'TCP', 5000, '192.0.2.1', domain, 443, 'C:/app.exe']
                    if status_column:
                        columns.insert(2, 'Status')
                        values.insert(2, 'Allowed')
                    tree = {'columns': columns, 'displaycolumns': list(reversed(columns))}
                    self.a.selected_rows = Mock(return_value=[('expired', values), ('duplicate', values)])
                    def capture(requests, **options):
                        self.requests = list(requests)
                        self.observed = options['observed_addresses']
                    self.a._apply_rule_batch = capture
                    self.a.bulk_global(tree, False, direction='in')
                    target = domain if domain == 'example.test' else '192.0.2.1'
                    self.assertEqual(self.requests, [(target, False, 'in', True)])
                    self.assertEqual(self.observed, {target: {'192.0.2.1'}})

    def test_alert_targets_use_recorded_endpoint_even_with_same_pid_active_elsewhere(self):
        self.a.alerts_tree = object()
        self.a.active_connections = {'other': {'pid': 42, 'dst_ip': '192.0.2.99',
                                               'domain': 'other.test', 'exe': 'C:/app.exe'}}
        for remote, expected_ip in [('192.0.2.1:443', '192.0.2.1'),
                                    ('[2001:db8::1]:443', '2001:db8::1'),
                                    ('2001:db8::1', '2001:db8::1')]:
            with self.subTest(remote=remote):
                self.a.selected_rows = Mock(return_value=[('alert', ['', '', 'App', 42, remote, 'example.test'])])
                self.a._apply_rule_batch = lambda requests: setattr(self, 'requests', list(requests))
                self.a.alert_action(False, True, 'in')
                self.assertEqual(set(self.requests), {(expected_ip, False, 'in', True),
                                                     ('example.test', False, 'in', True)})

    def test_expired_ip_only_alert_still_allows_ip(self):
        self.a.alerts_tree = object()
        self.a.selected_rows = Mock(return_value=[('alert', ['', '', 'App', 42, '192.0.2.1', '\u2014'])])
        self.a._apply_rule_batch = lambda requests: setattr(self, 'requests', list(requests))
        self.a.alert_global_domain(True)
        self.assertEqual(self.requests, [('192.0.2.1', True, 'both', True)])

    def test_rule_list_mixed_selections_are_filtered_in_both_directions(self):
        self.a.rules_tree = object()
        self.a.selected_rows = Mock(return_value=[
            ('app', ('Blocked', 'App', 'Both', 0, 0, 'C:/app.exe')),
            ('global', ('Global Block', 'IP', 'Both', 0, 0, 'example.test (192.0.2.1)'))])
        self.a._apply_rule_batch = Mock()
        self.a.bulk_rule_global(True)
        self.a._apply_rule_batch.assert_called_once_with([('example.test', True, 'both', True)])
        self.assertIn('not global IP/Domain rules', self.messages.showwarning.call_args.args[1])
        self.a._apply_rule_batch.reset_mock()
        self.a.rules_menu_block('in')
        self.a._apply_rule_batch.assert_called_once_with([('C:/app.exe', False, 'in', False)])
        self.assertIn('not application rules', self.messages.showwarning.call_args.args[1])

    def test_batch_rejects_wrong_target_types_before_dns_but_applies_valid_items(self):
        a = self.a
        a.get_firewall_rules = Mock(return_value=[])
        a._create_rule_batch = Mock()
        a._invalidate_auto_prompts = Mock()
        with patch.object(socket, 'getaddrinfo', side_effect=AssertionError('No DNS for paths or IPs')):
            self.assertTrue(a._apply_rule_batch([
                ('C:/app.exe', False, 'both', True),
                ('192.0.2.55', False, 'both', False),
                ('C:/valid.exe', False, 'both', False),
                ('192.0.2.1', False, 'in', True)]))
        self.assertEqual(set(a.global_blocks), {'192.0.2.1'})
        self.assertEqual(set(a.blocked_paths), {NS['normalize_path']('C:/valid.exe')})
        self.assertEqual(self.messages.showwarning.call_count, 2)

    def test_resolver_rejects_executable_paths_without_dns(self):
        with patch.object(socket, 'getaddrinfo') as dns:
            for path in ('C:/app.exe', r'C:\Program Files\app.exe', r'\\server\share\app.exe'):
                with self.assertRaisesRegex(ValueError, 'Not a global IP/Domain target'):
                    self.a.resolve_global_target(path)
            dns.assert_not_called()

    def test_incoming_rule_replaces_both_directions_and_is_not_duplicate_of_both(self):
        a = self.a
        target = '192.0.2.1'
        base = a.global_rule_base(target, False)
        a.global_blocks[target] = {'addresses': (target,)}
        self.assertFalse(a._rule_is_duplicate(target, False, 'in', True))
        records = [{'name': base + '_In'}, {'name': base + '_Out'}]
        state = {r['name'] for r in records}
        a.get_firewall_rules = Mock(return_value=records)
        a.delete_rule_names = lambda names: state.difference_update(names)
        a._create_rule_batch = Mock(side_effect=lambda rows: state.update(r['name'] for r in rows))
        a._commit_rule_batch([(target, False, 'in', True)])
        self.assertEqual(state, {base + '_In'})
        self.assertEqual(a._create_rule_batch.call_args.args[0][0]['direction'], 'Inbound')
        self.assertTrue(a._rule_is_duplicate(target, False, 'in', True))
        self.assertFalse(a._rule_is_duplicate(target, False, 'both', True))
        self.assertTrue(a.connection_has_rule('', target, '', 'Incoming'))
        self.assertFalse(a.connection_has_rule('', target, '', 'Outgoing'))
        rows = a._make_rule_rows({}, set(), a.global_blocks, {})
        self.assertEqual(rows[0]['direction'], 'Inbound')

    def test_incoming_rule_single_creation_only_creates_inbound(self):
        a = self.a
        target = '192.0.2.1'
        base = a.global_rule_base(target, False)
        a.get_firewall_rules = Mock(side_effect=[[], [{'name': base + '_In', 'action': 'Block',
                                                      'direction': 'Inbound'}]])
        a._replace_rule_records = lambda old, names, create: create()
        a.run_netsh = Mock()
        a.add_global_rule_sync(target, False, 'in')
        a.run_netsh.assert_called_once()
        self.assertIn('dir=in', a.run_netsh.call_args.args[0])

    def test_direction_survives_settings_and_startup_restore(self):
        a = self.a
        a.alerts = []
        a.default_column_orders = a.column_orders = {}
        a.settings_io_lock = threading.RLock()
        for field in ('rate_threshold', 'rate_window', 'upload_threshold', 'max_connections_alerts',
                      'log_alerts', 'auto_block', 'dark_mode'):
            setattr(a, field + '_var', Mock())
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'config.json'
            path.write_text(json.dumps({'global_ip_blocks': [{'target': '192.0.2.1', 'direction': 'Inbound'},
                                                             {'target': '192.0.2.2'}]}))
            with patch_dependencies(CONFIG_FILE=str(path)):
                a.load_settings()
                self.assertTrue(a.check_updates_on_startup)
                a.check_updates_on_startup_var.set.assert_called_with(True)
                self.assertTrue(App.save_settings(a))
                saved = json.loads(path.read_text())
                self.assertEqual([r['direction'] for r in saved['global_ip_blocks']], ['Inbound', 'Both'])
                a.global_blocks.clear()
                a.load_settings()
            a.get_firewall_rules = Mock(return_value=[])
            a._commit_rule_batch = Mock()
            a.restore_saved_rules_locked()
        requests = a._commit_rule_batch.call_args.args[0]
        self.assertIn(('192.0.2.1', False, 'Inbound', True), requests)
        self.assertIn(('192.0.2.2', False, 'Both', True), requests)

    def test_menus_group_combined_global_actions_and_removal(self):
        a = self.a
        a.colors = {'fg': '#eee'}
        a.tree = a.active_tree = a.alerts_tree = object()
        a._focus_menu_row = Mock(return_value='selected')
        a._show_header_menu = Mock(return_value=False)
        event = types.SimpleNamespace(x_root=10, y_root=20)
        for show in (lambda: a.show_connection_menu(event, a.tree),
                     lambda: a.show_connection_menu(event, a.active_tree),
                     lambda: a.show_alert_menu(event)):
            entries = []
            menu = Mock()
            menu.add_command.side_effect = lambda **kwargs: entries.append(kwargs['label'])
            menu.add_separator.side_effect = lambda: entries.append('|')
            a._context_menu = Mock(return_value=menu)
            show()
            self.assertEqual(entries[3:8], ['|', 'Allow IP Domain (Global)', 'Block IP Domain (Global)',
                                            'Block IP Domain (Global) Incoming', '|'])
            self.assertEqual(entries[-2:], ['|', 'Remove App Rule'])
            if 'Connection Details' in entries:
                self.assertEqual(entries[8:11], ['Allow Remote Port (Global)', 'Block Remote Port (Global)', '|'])
            else:
                self.assertFalse(any('Port (Global)' in label for label in entries))


if __name__ == '__main__':
    unittest.main()
