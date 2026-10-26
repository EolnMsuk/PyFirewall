"""Port lifecycle and precedence checks without changing the machine firewall."""
import copy
import json
import pathlib
import shutil
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
from support import patch_dependencies
from test_firewall_monitor import App, NS, app


def port(scope='remote', number=443, action='Allow'):
    return {'scope': scope, 'port': number, 'action': action}


def connection(**changes):
    return dict({'exe': 'C:\\demo.exe', 'lport': 51000, 'dport': 443, 'protocol': 'TCP',
                 'direction': 'Outgoing', 'dst_ip': '192.0.2.1'}, **changes)


class MemoryFirewall:
    """Implements native create/delete/snapshot only; all planning is production code."""
    def __init__(self, a, unrelated_count=0):
        self.rules = {}
        for i in range(unrelated_count):
            name = f'PyFirewall_Block_app{i}_In'
            self.rules[name] = {'name': name, 'action': 'Block', 'direction': 'Inbound',
                                'path': f'C:\\app{i}.exe', 'normalized_path': f'c:\\app{i}.exe',
                                'is_hold': False, 'is_global': False, 'addresses': ['Any']}
        hold = 'PyFirewall_AutoHold_pending_In'
        self.rules[hold] = {'name': hold, 'action': 'Block', 'direction': 'Inbound',
                            'path': 'C:\\pending.exe', 'normalized_path': 'c:\\pending.exe',
                            'is_hold': True, 'is_global': False, 'addresses': ['Any']}
        a.get_firewall_rules = Mock(side_effect=lambda: copy.deepcopy(list(self.rules.values())))
        a.delete_rule_names = Mock(side_effect=self.delete)
        a._create_rule_batch = Mock(side_effect=self.create)
        a.run_ps = Mock(side_effect=AssertionError('Native firewall calls are forbidden in memory tests'))
        a.run_netsh = Mock(side_effect=AssertionError('Native firewall calls are forbidden in memory tests'))
        self.fail_once = False

    def delete(self, names):
        for name in list(names):
            self.rules.pop(name, None)

    def create(self, rules):
        for rule in rules:
            self.rules[rule['name']] = dict(copy.deepcopy(rule), normalized_path=NS['normalize_path'](rule.get('path')),
                                             is_global=rule.get('is_port', False) or not rule.get('path'),
                                             is_hold=False)
            if self.fail_once:
                self.fail_once = False
                raise RuntimeError('Simulated partial native creation failure')


class NativePortLifecycleTests(unittest.TestCase):
    def test_allow_block_repeat_and_remove_touch_only_four_rules_among_1000_apps(self):
        a = app()
        backend = MemoryFirewall(a, 1000)
        original = copy.deepcopy(backend.rules)
        a._invalidate_auto_prompts = Mock()
        a._cancel_app_prompt = Mock()
        a.global_blocks = {'192.0.2.1': {'addresses': ('192.0.2.1',), 'direction': 'Both'}}
        a.blocked_paths = {'c:\\demo.exe': {'path': 'C:\\demo.exe', 'in': True, 'out': True}}
        original_blocks = copy.deepcopy(a.blocked_paths)
        with patch.object(NS['messagebox'], 'showwarning'):
            for action in ('Allow', 'Allow', 'Block', 'Allow', 'Block'):
                self.assertTrue(a.apply_global_port_rules([port(action=action)]))
                self.assertEqual(len(backend.rules), len(original) + 4)
                self.assertEqual({n: backend.rules[n] for n in original}, original)
                self.assertTrue(all(len(call.args[0]) == 4 for call in a._create_rule_batch.call_args_list))
        self.assertEqual(a._create_rule_batch.call_count, 4)  # Duplicate Allow is a no-op.
        self.assertEqual(a.blocked_paths, original_blocks)
        a._invalidate_auto_prompts.assert_not_called()
        a._cancel_app_prompt.assert_not_called()
        self.assertTrue(a._remove_rule_batch([('Global Port Block', 'remote:443')]))
        self.assertEqual(backend.rules, original)
        self.assertEqual(a.global_ports, {})

    def test_local_and_remote_are_independent_four_rule_sets(self):
        a = app()
        backend = MemoryFirewall(a)
        baseline = copy.deepcopy(backend.rules)
        a._commit_rule_batch([], port_updates=[port(), port('local', 443, 'Block')])
        self.assertEqual(len(backend.rules), len(baseline) + 8)
        self.assertTrue(a._remove_rule_batch([('Global Port Allow', 'remote:443')]))
        self.assertEqual(len(backend.rules), len(baseline) + 4)
        self.assertEqual(set(a.global_ports), {'local:443'})
        self.assertTrue(all('local_443' in n for n in backend.rules if n not in baseline))

    def test_failure_restores_exact_previous_port_action_without_rewriting_apps(self):
        a = app()
        backend = MemoryFirewall(a, 20)
        a._commit_rule_batch([], port_updates=[port(action='Block')])
        before = copy.deepcopy(backend.rules)
        policy = copy.deepcopy(a.global_ports)
        backend.fail_once = True
        a.save_settings.reset_mock()
        with patch_dependencies(log_internal_error=Mock()):
            self.assertFalse(a._apply_rule_batch([], quiet=True, port_updates=[port(action='Allow')]))
        self.assertEqual(backend.rules, before)
        self.assertEqual(a.global_ports, policy)
        a.save_settings.assert_not_called()

    def test_restart_replaces_the_same_four_names(self):
        a = app()
        backend = MemoryFirewall(a, 3)
        a._commit_rule_batch([], port_updates=[port()])
        before = copy.deepcopy(backend.rules)
        a.pending_rules = []
        for _ in range(3):
            a.restore_saved_rules_locked()
            self.assertEqual(backend.rules, before)

    def test_mixed_import_touches_only_explicit_targets(self):
        a = app()
        backend = MemoryFirewall(a, 100)
        old_apps = {n: copy.deepcopy(r) for n, r in backend.rules.items() if not r['is_hold']}
        a._commit_rule_batch([('C:/new.exe', False, 'both', False), ('192.0.2.1', False, 'in', True)],
                             port_updates=[port()])
        planned = a._create_rule_batch.call_args.args[0]
        self.assertEqual(len(planned), 7)
        self.assertEqual({n: backend.rules[n] for n in old_apps}, old_apps)
        self.assertEqual(sum(bool(r.get('is_port')) for r in planned), 4)

    def test_new_app_block_still_creates_only_two_unrestricted_rules(self):
        a = app()
        backend = MemoryFirewall(a)
        a._commit_rule_batch([], port_updates=[port()])
        a._commit_rule_batch([('C:/new.exe', False, 'both', False)])
        rules = a._create_rule_batch.call_args.args[0]
        self.assertEqual(len(rules), 2)
        self.assertTrue(all('protocol' not in r and not r.get('is_port') for r in rules))

    def test_port_validation_rejects_invalid_input_before_native_operations(self):
        a = app()
        backend = MemoryFirewall(a)
        for bad in [port(number=0), port(number=65536), port(number=True), port(number=1.5),
                    port(number='443;bad'), port(scope='both'), port(action='ignore'), None]:
            with self.subTest(bad=bad):
                self.assertFalse(a._apply_rule_batch([], quiet=True, port_updates=[bad]))
        a.get_firewall_rules.assert_not_called()
        a._create_rule_batch.assert_not_called()

    def test_rule_shape_and_names_are_independent_of_action(self):
        a = app()
        for scope in ('local', 'remote'):
            allow = a._port_firewall_rules(a._parse_port_rules([port(scope=scope)]))
            block = a._port_firewall_rules(a._parse_port_rules([port(scope=scope, action='Block')]))
            self.assertEqual([r['name'] for r in allow], [r['name'] for r in block])
            self.assertEqual(len(allow), 4)
            self.assertEqual({r['protocol'] for r in allow}, {'TCP', 'UDP'})
            self.assertEqual({r['direction'] for r in allow}, {'Inbound', 'Outbound'})
            for rule in allow:
                self.assertEqual(rule['path'], '')
                self.assertEqual(rule[scope + '_ports'], ['443'])
                self.assertEqual(rule[('remote' if scope == 'local' else 'local') + '_ports'], ['Any'])


class PortDisplayTests(unittest.TestCase):
    def test_application_blocks_keep_their_color_over_both_port_actions(self):
        a = app()
        for action in ('Allow', 'Block'):
            a.global_ports = a._parse_port_rules([port(action=action)])
            for inbound, outbound, color in ((True, True, 'blocked'), (True, False, 'blocked_in'), (False, True, 'blocked')):
                a.blocked_paths[NS['normalize_path']('C:\\demo.exe')] = {'in': inbound, 'out': outbound}
                self.assertEqual(a.connection_tag(connection()), color)
                self.assertNotIn('Global', a.connection_status(connection()))
                a.alert_context = Mock(return_value=(connection(), '192.0.2.1'))
                self.assertEqual(a.alert_tag(()), color)

    def test_pending_hold_is_not_colored_as_a_global_allow(self):
        a = app()
        a.global_ports = a._parse_port_rules([port()])
        a.auto_prompt_keys.add(NS['normalize_path']('C:\\demo.exe'))
        self.assertEqual(a.connection_tag(connection()), 'blocked')
        self.assertEqual(a.connection_status(connection()), 'Blocked (Pending)')

    def test_block_wins_between_ip_and_port_and_between_port_scopes(self):
        a = app()
        a.global_ports = a._parse_port_rules([port()])
        self.assertEqual(a.connection_tag(connection()), 'global_allow')
        a.global_blocks['192.0.2.1'] = {'direction': 'Both'}
        self.assertEqual(a.connection_tag(connection()), 'global_block')
        a.global_blocks['192.0.2.1']['direction'] = 'Inbound'
        self.assertEqual(a.connection_tag(connection(direction='Incoming')), 'global_block_in')
        a.global_blocks.clear()
        a.global_allows['192.0.2.1'] = {'direction': 'Both'}
        a.global_ports = a._parse_port_rules([port(action='Block')])
        self.assertEqual(a.connection_tag(connection()), 'global_block')
        a.global_ports = a._parse_port_rules([port(), port('local', 51000, 'Block')])
        self.assertEqual(a.connection_tag(connection()), 'global_block')

    def test_matching_is_local_remote_specific_tcp_udp_and_both_directions(self):
        a = app()
        a.global_ports = a._parse_port_rules([port()])
        for protocol in ('TCP', 'UDP'):
            for direction in ('Incoming', 'Outgoing'):
                self.assertEqual(a.global_port_action(connection(protocol=protocol, direction=direction)), 'Allow')
        self.assertIsNone(a.global_port_action(connection(lport=443, dport=123)))
        self.assertIsNone(a.global_port_action(connection(protocol='ICMPv4')))

    def test_threshold_with_port_policy_does_not_add_an_app_hold(self):
        a = app()
        a.global_ports = a._parse_port_rules([port()])
        a.active_connections = {'key': connection()}
        a.start_auto_block = Mock()
        a.handle_threshold('demo', 'C:\\demo.exe', 1, '192.0.2.1', '', 'Outgoing', 'key', 'connection', '')
        a.start_auto_block.assert_not_called()
        a.install_auto_hold = Mock()
        a._start_auto_block_locked('demo', 'C:\\demo.exe', 1, '192.0.2.1', '', 'Outgoing', 'key', 'connection', '')
        a.install_auto_hold.assert_not_called()

    def test_context_uses_remote_port_and_deduplicates_multiple_connections(self):
        a = app()
        a.selected_connection_data = Mock(return_value=[connection(), connection(protocol='UDP'), connection(dport=80)])
        a._apply_rule_batch = Mock()
        a.bulk_remote_ports(object(), False)
        a._apply_rule_batch.assert_called_once_with([], port_updates=[port(number=80, action='Block'), port(action='Block')], report=True)

    def test_dialog_local_remote_and_cancel_paths(self):
        a = app()
        a.root = Mock()
        a._apply_rule_batch = Mock()
        for scope in ('local', 'remote'):
            for action in ('Allow', 'Block', 'Block Incoming', None):
                a._apply_rule_batch.reset_mock()
                a._ask_global_rule_fields = Mock(return_value=('', 53, scope, 'TCP/UDP', action) if action else None)
                a.add_global_rule_dialog()
                if action:
                    expected = dict(port(scope, 53, 'Allow' if action == 'Allow' else 'Block'), target='', protocol='TCP/UDP', addresses=[])
                    if action == 'Block Incoming':
                        expected['direction'] = 'Inbound'
                    a._apply_rule_batch.assert_called_once_with([], port_updates=[expected], replace_rule=None, report=True)
                else:
                    a._apply_rule_batch.assert_not_called()
        a._ask_global_rule_fields = Mock(return_value=None)
        a._apply_rule_batch.reset_mock()
        a.add_global_rule_dialog()
        a._apply_rule_batch.assert_not_called()


class NativePortPowerShellTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('powershell'), 'Windows PowerShell required')
    def test_native_script_creates_verifies_and_enumerates_four_global_rules(self):
        a = app()
        a.run_ps = Mock(return_value=types.SimpleNamespace(stdout='[]'))
        stub = r'''
$ErrorActionPreference='Stop'
$script:store=@{}
function New-NetFirewallRule {
    [CmdletBinding()] param([string]$Name, [string]$DisplayName, [string]$Direction,
        [string]$Action, [string]$Enabled, [string]$Profile, [string]$Program='Any',
        [string[]]$RemoteAddress=@('Any'), [ValidateSet('TCP','UDP')][string]$Protocol,
        [string[]]$LocalPort=@('Any'), [string[]]$RemotePort=@('Any'))
    if ($script:store.ContainsKey($Name)) { throw 'Duplicate native name' }
    $script:store[$Name]=[PSCustomObject]@{Name=$Name; DisplayName=$DisplayName; Direction=$Direction;
        Action=$Action; Enabled=$Enabled; Program=$Program; RemoteAddress=$RemoteAddress; LocalAddress=@('Any');
        Protocol=$(if($Protocol -eq 'TCP'){'6'}else{'17'}); LocalPort=$LocalPort; RemotePort=$RemotePort}
}
function Get-NetFirewallRule {
    [CmdletBinding()] param([string]$Name)
    if ($Name) { if (-not $script:store.ContainsKey($Name)) { throw 'Missing rule' }; $script:store[$Name] }
    else { @($script:store.Values) }
}
function Get-NetFirewallApplicationFilter {
    [CmdletBinding()] param($AssociatedNetFirewallRule)
    $AssociatedNetFirewallRule
}
function Get-NetFirewallAddressFilter {
    [CmdletBinding()] param($AssociatedNetFirewallRule)
    $AssociatedNetFirewallRule
}
function Get-NetFirewallPortFilter {
    [CmdletBinding()] param($AssociatedNetFirewallRule)
    $AssociatedNetFirewallRule
}
'''
        cases = [port('local', 53), port('remote', 53, 'Block'),
                 dict(port('local', 53, 'Block'), direction='Inbound'),
                 dict(port('remote', 53, 'Block'), target='example.test',
                      addresses=['192.0.2.1', '2001:db8::1'], direction='Inbound'),
                 dict(port('local', 53), target='192.0.2.0/24', addresses=['192.0.2.0/24'])]
        for entry in cases:
            scope, action = entry['scope'], entry['action']
            count = 2 if entry.get('direction') == 'Inbound' else 4
            with self.subTest(entry=entry):
                a._create_rule_batch(a._port_firewall_rules(a._parse_port_rules([entry])))
                creation = a.run_ps.call_args.args[0]
                a.get_firewall_rules()
                enumeration = a.run_ps.call_args.args[0]
                script = stub + creation + f"\nif ($script:store.Count -ne {count}) {{ throw 'Wrong native rule count' }}\n" + enumeration
                with tempfile.TemporaryDirectory() as directory:
                    path = pathlib.Path(directory) / 'verify.ps1'
                    path.write_text(script, encoding='utf-8-sig')
                    result = NS['subprocess'].run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(path)],
                                                  capture_output=True, text=True, timeout=30,
                                                  creationflags=NS['CREATE_NO_WINDOW'])
                self.assertEqual(result.returncode, 0, result.stderr)
                snapshot = json.loads(result.stdout)
                self.assertEqual(len(snapshot), count)
                self.assertTrue(all(r['Program'] == 'Any' and r['Action'] == action for r in snapshot))
                self.assertTrue(all(r['Addresses'] == entry.get('addresses', ['Any']) for r in snapshot))
                if count == 2:
                    self.assertTrue(all(r['Direction'] == 'Inbound' for r in snapshot))
                a.run_ps.return_value.stdout = result.stdout
                records = a.get_firewall_rules()
                self.assertTrue(all(r['is_port'] and r['is_global'] and r['path'] == '' for r in records))
                self.assertTrue(all(r[scope + '_ports'] == ['53'] for r in records))
                a.run_ps.return_value.stdout = '[]'


if __name__ == '__main__':
    unittest.main()
