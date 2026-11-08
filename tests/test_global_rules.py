"""Global rule lifecycle, matching, dialogs and persistence using mocked firewalls."""
import copy
import json
import pathlib
import shutil
import socket
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from support import App, NS, patch_dependencies
from fixtures import MemoryFirewall, app, connection, port


class NativePortLifecycleTests(unittest.TestCase):
    def test_allow_block_coexist_and_duplicates_do_not_rewrite_1000_apps(self):
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
                self.assertEqual(len(backend.rules), len(original) + 4 * len(a.global_ports))
                self.assertEqual({n: backend.rules[n] for n in original}, original)
                self.assertTrue(all(len(call.args[0]) == 4 for call in a._create_rule_batch.call_args_list))
        self.assertEqual(a._create_rule_batch.call_count, 2)  # Exact duplicates are a no-op.
        self.assertEqual(a.blocked_paths, original_blocks)
        a._invalidate_auto_prompts.assert_not_called()
        a._cancel_app_prompt.assert_not_called()
        self.assertTrue(a._remove_rule_batch([('Global Port Block', 'remote:443:Block:Both')]))
        self.assertEqual(len(backend.rules), len(original) + 4)
        self.assertEqual({r['action'] for r in backend.rules.values() if r.get('is_port')}, {'Allow'})
        self.assertTrue(a._remove_rule_batch([('Global Port Allow', 'remote:443:Allow:Both')]))
        self.assertEqual(backend.rules, original)
        self.assertEqual(a.global_ports, {})

    def test_local_and_remote_are_independent_four_rule_sets(self):
        a = app()
        backend = MemoryFirewall(a)
        baseline = copy.deepcopy(backend.rules)
        a._commit_rule_batch([], port_updates=[port(), port('local', 443, 'Block')])
        self.assertEqual(len(backend.rules), len(baseline) + 8)
        self.assertTrue(a._remove_rule_batch([('Global Port Allow', 'remote:443:Allow:Both')]))
        self.assertEqual(len(backend.rules), len(baseline) + 4)
        self.assertEqual(set(a.global_ports), {'local:443:Block:Both'})
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

    def test_actions_have_distinct_native_names_with_the_same_filters(self):
        a = app()
        for scope in ('local', 'remote'):
            allow = a._port_firewall_rules(a._parse_port_rules([port(scope=scope)]))
            block = a._port_firewall_rules(a._parse_port_rules([port(scope=scope, action='Block')]))
            self.assertTrue({r['name'] for r in allow}.isdisjoint(r['name'] for r in block))
            self.assertEqual(len(allow), 4)
            self.assertEqual({r['protocol'] for r in allow}, {'TCP', 'UDP'})
            self.assertEqual({r['direction'] for r in allow}, {'Inbound', 'Outbound'})
            for rule in allow:
                self.assertEqual(rule['path'], '')
                self.assertEqual(rule[scope + '_ports'], ['443'])
                self.assertEqual(rule[('remote' if scope == 'local' else 'local') + '_ports'], ['Any'])


class IndependentGlobalPolicyTests(unittest.TestCase):
    def test_editor_checks_protocol_overlap_in_both_orders(self):
        for existing_protocol in ('TCP', 'UDP', 'TCP/UDP'):
            a = app()
            a.global_ports = a._parse_port_rules([dict(port(number=44), protocol=existing_protocol)])
            key = next(iter(a.global_ports))
            for proposed in ('TCP', 'UDP', 'TCP/UDP'):
                for action in ('Allow Incoming', 'Block Incoming'):
                    with self.subTest(existing=existing_protocol, proposed=proposed, action=action):
                        fields = ('', 44, 'remote', proposed, action)
                        reason = a._global_editor_conflict(fields)
                        overlaps = existing_protocol == proposed or 'TCP/UDP' in (existing_protocol, proposed)
                        self.assertEqual(bool(reason), overlaps)
                        if overlaps and existing_protocol != proposed:
                            self.assertIn('Overlapping protocol', reason)
                        self.assertIsNone(a._global_editor_conflict(fields, ('port', key)))
            a.global_ports = a._parse_port_rules([dict(port(number=44), protocol=existing_protocol, direction='Inbound')])
            self.assertIsNone(a._global_editor_conflict(('', 44, 'remote', 'TCP/UDP', 'Block Outgoing')))

    def test_editor_rejects_duplicates_and_overlapping_directions_but_allows_separate_sides(self):
        for existing_action in ('Allow', 'Block'):
            for existing_direction in ('Both', 'Inbound', 'Outbound'):
                a = app()
                a.global_ports = a._parse_port_rules([dict(port(number=43, action=existing_action),
                    protocol='TCP', direction=existing_direction)])
                key = next(iter(a.global_ports))
                for action, direction in self.actions:
                    with self.subTest(existing=(existing_action, existing_direction), proposed=action):
                        fields = ('', 43, 'remote', 'TCP', action)
                        reason = a._global_editor_conflict(fields)
                        overlap = bool(NS['direction_set'](direction) & NS['direction_set'](existing_direction))
                        self.assertEqual(bool(reason), overlap)
                        if overlap:
                            expected = ('Conflicting direction' if direction != existing_direction else
                                        'already exists' if action.split()[0] == existing_action else 'Conflicting rule')
                            self.assertIn(expected, reason)
                        self.assertIsNone(a._global_editor_conflict(fields, ('port', key)))
                        self.assertIsNone(a._global_editor_conflict(('', 44, 'remote', 'TCP', action)))

    actions = (('Allow', 'Both'), ('Allow Incoming', 'Inbound'), ('Allow Outgoing', 'Outbound'),
               ('Block', 'Both'), ('Block Incoming', 'Inbound'), ('Block Outgoing', 'Outbound'))

    def test_all_six_actions_coexist_for_identical_targets_ports_and_protocols(self):
        for scope in ('local', 'remote'):
            for number in (None, '80,443'):
                for target in ('', '192.0.2.1, 198.51.100.1'):
                    with self.subTest(scope=scope, port=number, target=target):
                        a = app()
                        backend = MemoryFirewall(a)
                        baseline = copy.deepcopy(backend.rules)
                        for index, (action, direction) in enumerate(self.actions, 1):
                            previous = copy.deepcopy(backend.rules)
                            a._ask_global_rule_fields = Mock(return_value=(target, number, scope, 'TCP/UDP', action))
                            a.add_global_rule_dialog()
                            self.assertEqual(len(a.global_ports), index)
                            self.assertEqual({name: backend.rules[name] for name in previous}, previous)
                            self.assertEqual(len(a._make_rule_rows({}, set(), {}, {})), index)
                        native = [r for r in backend.rules.values() if r.get('is_port')]
                        self.assertEqual(len(native), 16)
                        self.assertEqual({(r['action'], r.get('direction', 'Both')) for r in a.global_ports.values()},
                                         {(action.split()[0], direction) for action, direction in self.actions})
                        before = copy.deepcopy(backend.rules)
                        a.add_global_rule_dialog()  # An exact duplicate is still a no-op.
                        self.assertEqual(len(a.global_ports), 6)
                        self.assertEqual(backend.rules, before)
                        a.global_ports = a._parse_port_rules(json.loads(json.dumps(list(a.global_ports.values()))))
                        a.pending_rules = []
                        a.restore_saved_rules_locked()
                        self.assertEqual(backend.rules, before)
                        for key, policy in list(a.global_ports.items()):
                            sibling_names = {r['name'] for r in a._port_firewall_rules(
                                {k: p for k, p in a.global_ports.items() if k != key})}
                            siblings = {name: copy.deepcopy(backend.rules[name]) for name in sibling_names}
                            self.assertTrue(a._remove_rule_batch([('Global Port ' + policy['action'], key)]))
                            self.assertEqual({name: backend.rules[name] for name in sibling_names}, siblings)
                        self.assertEqual(backend.rules, baseline)

    def test_edit_and_failed_edit_touch_only_the_selected_policy(self):
        a = app()
        backend = MemoryFirewall(a)
        a._commit_rule_batch([], port_updates=[port(), port(action='Block'),
                                              dict(port(action='Block'), direction='Inbound')])
        key = next(k for k, p in a.global_ports.items() if p['action'] == 'Block' and 'direction' not in p)
        siblings = {k: copy.deepcopy(p) for k, p in a.global_ports.items() if k != key}
        sibling_names = {r['name'] for r in a._port_firewall_rules(siblings)}
        before = copy.deepcopy(backend.rules)
        replacement = dict(port(), direction='Outbound')
        backend.fail_once = True
        with patch_dependencies(log_internal_error=Mock()):
            self.assertFalse(a._apply_rule_batch([], quiet=True, port_updates=[replacement], replace_rule=('port', key)))
        self.assertEqual(backend.rules, before)
        self.assertIn(key, a.global_ports)
        a._ask_global_rule_fields = Mock(return_value=('', 443, 'remote', 'TCP/UDP', 'Allow Outgoing'))
        a.edit_global_rule(('port', key, a.global_ports[key]))
        self.assertEqual(len(a.global_ports), 3)
        self.assertNotIn(key, a.global_ports)
        self.assertEqual({k: a.global_ports[k] for k in siblings}, siblings)
        self.assertEqual({name: backend.rules[name] for name in sibling_names},
                         {name: before[name] for name in sibling_names})

    def test_old_native_names_migrate_on_restart_and_roll_back_on_failure(self):
        for action in ('Allow', 'Block'):
            for direction in ('Both', 'Inbound', 'Outbound'):
                with self.subTest(action=action, direction=direction):
                    a = app()
                    backend = MemoryFirewall(a)
                    a.global_ports = a._parse_port_rules([dict(port(action=action), direction=direction)])
                    backend.create(a._port_firewall_rules(a.global_ports, legacy_names=True))
                    old_names = {r['name'] for r in a._port_firewall_rules(a.global_ports, legacy_names=True)}
                    before = copy.deepcopy(backend.rules)
                    a.pending_rules = []
                    backend.fail_once = True
                    with self.assertRaises(RuntimeError):
                        a.restore_saved_rules_locked()
                    self.assertEqual(backend.rules, before)
                    a.restore_saved_rules_locked()
                    self.assertTrue(old_names.isdisjoint(backend.rules))
                    expected_names = {r['name'] for r in a._port_firewall_rules(a.global_ports)}
                    self.assertEqual({r['name'] for r in backend.rules.values() if r.get('is_port')}, expected_names)
                    migrated = copy.deepcopy(backend.rules)
                    sibling = dict(port(action=action), direction='Inbound' if direction == 'Both' else 'Both')
                    a._commit_rule_batch([], port_updates=[sibling])
                    self.assertEqual(len(a.global_ports), 2)
                    self.assertEqual({name: backend.rules[name] for name in migrated}, migrated)


class PortDisplayTests(unittest.TestCase):
    def test_matching_blocks_win_and_global_wins_block_ties(self):
        a = app()
        for action in ('Allow', 'Block'):
            a.global_ports = a._parse_port_rules([port(action=action)])
            for inbound, outbound in ((True, True), (True, False), (False, True)):
                a.blocked_paths[NS['normalize_path'](r'C:\demo.exe')] = {'in': inbound, 'out': outbound}
                color = 'global_block' if action == 'Block' else 'blocked' if outbound else 'global_allow'
                self.assertEqual(a.connection_tag(connection()), color)
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
        Action=$Action; Enabled=$Enabled; Profile=$Profile; Program=$Program; RemoteAddress=$RemoteAddress; LocalAddress=@('Any');
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
        cases = [dict(port('remote', 53, 'Block'), exe=r'C:\demo.exe'), port('local', 53), port('remote', 53, 'Block'),
                 dict(port('remote', 53, 'Block'), exes=[r'C:\First Folder\demo.exe', r'C:\Second, Folder\demo.exe']),
                 dict(port('local', 53, 'Block'), direction='Inbound'),
                 dict(port('remote', 53, 'Block'), target='example.test',
                      addresses=['192.0.2.1', '2001:db8::1'], direction='Inbound'),
                 dict(port('local', 53), target='192.0.2.0/24', addresses=['192.0.2.0/24']),
                 dict(port('local', 53), restore_disabled=True)]
        for entry in cases:
            scope, action = entry['scope'], entry['action']
            programs = entry.get('exes', [entry.get('exe', 'Any')])
            count = (2 if entry.get('direction') == 'Inbound' else 4) * len(programs)
            with self.subTest(entry=entry):
                planned = a._port_firewall_rules(a._parse_port_rules([entry]))
                if entry.get('restore_disabled'):
                    planned = [dict(rule, enabled=False) for rule in planned]
                a._create_rule_batch(planned)
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
                self.assertEqual({r['Program'] for r in snapshot}, set(programs))
                self.assertTrue(all(r['Action'] == action for r in snapshot))
                self.assertTrue(all(r['Addresses'] == entry.get('addresses', ['Any']) for r in snapshot))
                if count == 2:
                    self.assertTrue(all(r['Direction'] == 'Inbound' for r in snapshot))
                a.run_ps.return_value.stdout = result.stdout
                records = a.get_firewall_rules()
                self.assertTrue(all(r['enabled'] is (not entry.get('restore_disabled', False)) for r in records))
                self.assertTrue(all(r['is_port'] and r['is_global'] for r in records))
                self.assertEqual({r['path'] for r in records}, {path if path != 'Any' else '' for path in programs})
                self.assertTrue(all(r[scope + '_ports'] == ['53'] for r in records))
                a.run_ps.return_value.stdout = '[]'


class CombinedGlobalRuleTests(unittest.TestCase):
    def test_combined_policy_requires_address_port_protocol_and_direction(self):
        a = app()
        backend = MemoryFirewall(a)
        baseline = copy.deepcopy(backend.rules)
        entry = dict(port(action='Block'), target='192.0.2.0/24', direction='Inbound')
        self.assertTrue(a.apply_global_port_rules([entry]))
        created = [rule for name, rule in backend.rules.items() if name not in baseline]
        self.assertEqual(len(created), 2)
        self.assertEqual({r['protocol'] for r in created}, {'TCP', 'UDP'})
        self.assertTrue(all(r['addresses'] == ['192.0.2.0/24'] and r['direction'] == 'Inbound' for r in created))
        row = connection(direction='Incoming')
        self.assertEqual(a.connection_tag(row), 'global_block_in')
        self.assertTrue(a.connection_has_rule(row['exe'], row['dst_ip'], '', row['direction'], row['lport'], row['dport']))
        for changes in ({'dst_ip': '198.51.100.1'}, {'dport': 80}, {'protocol': 'ICMP'}, {'direction': 'Outgoing'}):
            other = dict(row, **changes)
            self.assertIsNone(a.global_port_action(other))
            self.assertEqual(a.connection_tag(other), 'even')
            self.assertFalse(a.connection_has_rule(other['exe'], other['dst_ip'], '', other['direction'],
                                                  other['lport'], other['dport'], other['protocol']))
        rows = a._make_rule_rows({}, set(), {}, {})
        self.assertEqual(len(rows), 1)
        self.assertIn('192.0.2.0/24', rows[0]['rule'])
        self.assertEqual(rows[0]['direction'], 'Inbound')

    def test_direction_replacement_rollback_and_independent_targets(self):
        a = app()
        backend = MemoryFirewall(a)
        entries = [port(), dict(port(), target='192.0.2.1'), dict(port(), target='192.0.2.2')]
        a._commit_rule_batch([], port_updates=entries)
        baseline = copy.deepcopy(backend.rules)
        incoming = dict(entries[1], action='Block', direction='Inbound')
        old_key = next(key for key, rule in a.global_ports.items() if rule.get('target') == '192.0.2.1')
        backend.fail_once = True
        with patch_dependencies(log_internal_error=Mock()):
            self.assertFalse(a._apply_rule_batch([], quiet=True, port_updates=[incoming], replace_rule=('port', old_key)))
        self.assertEqual(backend.rules, baseline)
        self.assertTrue(a._apply_rule_batch([], port_updates=[incoming], replace_rule=('port', old_key)))
        self.assertEqual(len(backend.rules), len(baseline) - 2)
        self.assertEqual(len(a.global_ports), 3)
        self.assertTrue(a._remove_rule_batch([('Global Port Block', 'remote:443:192.0.2.1:Block:Inbound')]))
        self.assertEqual(len(backend.rules), len(baseline) - 4)
        self.assertEqual(set(a.global_ports), {'remote:443:Allow:Both', 'remote:443:192.0.2.2:Allow:Both'})

    def test_domain_backup_import_and_restart_keep_one_combined_rule(self):
        a = app()
        MemoryFirewall(a)
        a.resolve_global_target = Mock(return_value=('192.0.2.10', '2001:db8::1'))
        entry = dict(port('local', 53, 'Block'), target='Example.Test.', direction='Inbound')
        a._commit_rule_batch([], port_updates=[entry])
        saved = list(a.global_ports.values())
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'rules.json'
            with patch.object(NS['filedialog'], 'asksaveasfilename', return_value=str(path)), \
                 patch.object(NS['messagebox'], 'showinfo'):
                a.export_rules()
            self.assertEqual(json.loads(path.read_text())['global_port_rules'], saved)
            b = app()
            backend = MemoryFirewall(b)
            b.resolve_global_target = Mock(return_value=('192.0.2.10', '2001:db8::1'))
            with patch.object(NS['filedialog'], 'askopenfilename', return_value=str(path)), \
                 patch.object(NS['messagebox'], 'askyesno', return_value=True), \
                 patch.object(NS['messagebox'], 'showinfo'), patch.object(NS['messagebox'], 'showerror') as errors:
                b.import_rules()
            errors.assert_not_called()
            self.assertEqual(a.global_ports, b.global_ports)
            b.pending_rules = []
            before = copy.deepcopy(backend.rules)
            b.restore_saved_rules_locked()
            self.assertEqual(backend.rules, before)
            self.assertEqual(b.global_blocks, {})
            self.assertEqual(b.global_allows, {})
            self.assertEqual(b.connection_tag(connection(lport=53, dst_ip='2001:db8::1', direction='Incoming')), 'global_block_in')

    def test_failed_domain_resolution_never_creates_unrestricted_port_rule(self):
        a = app()
        backend = MemoryFirewall(a)
        baseline = copy.deepcopy(backend.rules)
        with patch.object(NS['socket'], 'getaddrinfo', side_effect=socket.gaierror('No DNS')), \
             patch_dependencies(log_internal_error=Mock()):
            self.assertFalse(a._apply_rule_batch([], quiet=True, port_updates=[dict(port(), target='example.test')]))
        self.assertEqual(backend.rules, baseline)
        self.assertEqual(a.global_ports, {})

    def test_incoming_port_colors_and_full_blocks_take_precedence(self):
        a = app()
        a.global_ports = a._parse_port_rules([dict(port(action='Block'), direction='Inbound')])
        self.assertEqual(a.connection_tag(connection(direction='Incoming')), 'global_block_in')
        self.assertEqual(a.connection_tag(connection()), 'even')
        a.global_blocks['192.0.2.1'] = {'direction': 'Both'}
        self.assertEqual(a.connection_tag(connection(direction='Incoming')), 'global_block')


class GlobalDialogAndMenuTests(unittest.TestCase):
    def test_real_dialog_defaults_validation_and_cancel(self):
        tk, ttk = NS['tk'], NS['ttk']
        root = tk.Tk()
        root.withdraw()
        a = app()
        a.root = root
        a._theme_dialog = lambda dialog: dialog.attributes('-alpha', 0)
        a._center_dialog = Mock()
        errors = []

        def widgets(parent):
            return [child for item in parent.winfo_children() for child in [item, *widgets(item)]]

        def interact(mode):
            dialog = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel))
            try:
                children = widgets(dialog)
                combos = [w for w in children if isinstance(w, ttk.Combobox)]
                action, scope, protocol = combos
                entries = [w for w in children if isinstance(w, ttk.Entry) and not isinstance(w, ttk.Combobox)]
                self.assertEqual(entries[0].get(), '')
                entries = entries[1:]
                buttons = {w.cget('text'): w for w in children if isinstance(w, ttk.Button)}
                self.assertEqual(scope.get(), 'Remote')
                self.assertEqual(tuple(scope['values']), ('Remote', 'Local'))
                self.assertEqual(action.get(), 'Allow')
                self.assertEqual(protocol.get(), 'TCP/UDP')
                self.assertEqual(tuple(protocol['values']), ('TCP/UDP', 'TCP', 'UDP'))
                if mode == 'cancel':
                    buttons['Cancel'].invoke()
                    return
                entries[1].insert(0, '0')
                with patch.object(NS['messagebox'], 'askokcancel', return_value=mode != 'validation_cancel') as prompt:
                    buttons['Save'].invoke()
                self.assertIn('Port numbers must be integers', prompt.call_args.args[1])
                if mode == 'validation_cancel':
                    return
                self.assertTrue(dialog.winfo_exists())
                entries[0].insert(0, 'example.test, second.test')
                entries[1].delete(0, tk.END)
                entries[1].insert(0, '443')
                scope.set('Local')
                buttons['Save'].invoke()
            except Exception as exc:
                errors.append(exc)
                if dialog.winfo_exists():
                    dialog.destroy()

        try:
            for mode in ('cancel', 'validation_cancel', 'submit'):
                root.after(20, lambda mode=mode: interact(mode))
                result = a._ask_global_rule_fields()
                if errors:
                    raise errors[0]
                self.assertEqual(result, ('example.test, second.test', 443, 'local', 'TCP/UDP', 'Allow') if mode == 'submit' else None)
        finally:
            root.destroy()

    def test_validation_and_combined_actions(self):
        a = app()
        for target, number in (('example.test', '0'), ('', '65536'), ('', 'abc'), ('C:\\x.exe', '443')):
            with self.subTest(target=target, number=number), self.assertRaises(ValueError):
                a._validate_global_rule_fields(target, number, 'Remote')
        self.assertEqual(a._validate_global_rule_fields(' example.test ', ' 443 ', 'Local'), ('example.test', 443, 'local'))
        for action in ('Allow', 'Block', 'Block Incoming', None):
            a._ask_global_rule_fields = Mock(return_value=('example.test', 443, 'remote', 'TCP/UDP', action) if action else None)
            a.resolve_global_target = Mock(return_value=['192.0.2.1'])
            a._apply_rule_batch = Mock()
            a.add_global_rule = Mock()
            a.add_global_rule_dialog()
            a.add_global_rule.assert_not_called()
            if action:
                expected = dict(port(action='Allow' if action == 'Allow' else 'Block'), target='example.test', protocol='TCP/UDP', addresses=['192.0.2.1'])
                if action == 'Block Incoming':
                    expected['direction'] = 'Inbound'
                a._apply_rule_batch.assert_called_once_with([], port_updates=[expected], replace_rule=None, report=True)
            else:
                a._apply_rule_batch.assert_not_called()

    def test_multiple_targets_validate_normalize_and_deduplicate(self):
        a = app()
        self.assertEqual(a._validate_global_rule_fields(
            ' Example.Test., second.test, EXAMPLE.TEST, 192.0.2.1, [2001:db8::1] ', '443', 'Remote'),
            ('example.test, second.test, 192.0.2.1, 2001:db8::1', 443, 'remote'))
        for target in (',', 'example.test,', ',example.test', 'example.test,,second.test',
                       'example.test, https://second.test', 'example.test, C:\\demo.exe'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                a._validate_global_rule_fields(target, '443', 'Remote')

    def test_multiple_targets_share_action_and_optional_port_in_one_transaction(self):
        for number in (None, 443):
            for scope in ('remote', 'local'):
                for action in ('Allow', 'Block', 'Block Incoming'):
                    with self.subTest(port=number, scope=scope, action=action):
                        a = app()
                        backend = MemoryFirewall(a)
                        a._invalidate_auto_prompts = Mock()
                        a.resolve_global_target = Mock(side_effect=lambda target, *args:
                            ('192.0.2.1',) if target == 'example.test' else ('198.51.100.1',))
                        a._ask_global_rule_fields = Mock(return_value=('example.test, second.test', number, scope, 'TCP/UDP', action))
                        a._choose_option = Mock()
                        a.add_global_rule_dialog()
                        a._choose_option.assert_not_called()
                        a._create_rule_batch.assert_called_once()
                        a.save_settings.assert_called_once()
                        a.rules_changed.assert_called_once()
                        planned = a._create_rule_batch.call_args.args[0]
                        self.assertEqual({r['action'] for r in planned}, {'Allow' if action == 'Allow' else 'Block'})
                        self.assertEqual({r['direction'] for r in planned},
                                         {'Inbound'} if action == 'Block Incoming' else {'Inbound', 'Outbound'})
                        self.assertEqual({r['target'] for r in a.global_ports.values()}, {'example.test, second.test'})
                        self.assertTrue(all(r[scope + '_ports'] == (['443'] if number else ['Any']) for r in planned))
                        self.assertFalse(a.global_blocks or a.global_allows)
                        self.assertEqual({tuple(r['addresses']) for r in planned}, {('192.0.2.1', '198.51.100.1')})

    def test_multiple_targets_cancel_and_partial_resolution_failure(self):
        for number in (None, 443):
            a = app()
            backend = MemoryFirewall(a)
            before = copy.deepcopy(backend.rules)
            a._ask_global_rule_fields = Mock(return_value=None)
            def resolve(target, *args):
                if target == 'missing.test':
                    raise ValueError('DNS failed')
                return ('192.0.2.1',)
            a.resolve_global_target = Mock(side_effect=resolve)
            a.add_global_rule_dialog()
            a.resolve_global_target.assert_not_called()
            a._ask_global_rule_fields.return_value = ('example.test, missing.test', number, 'remote', 'TCP/UDP', 'Block')
            with patch.object(NS['messagebox'], 'showwarning') as warning:
                a.add_global_rule_dialog()
            warning.assert_called_once()
            self.assertIn('missing.test: DNS failed', warning.call_args.args[1])
            a._create_rule_batch.assert_called_once()
            a.save_settings.assert_called_once()
            self.assertEqual({r['target'] for r in a.global_ports.values()}, {'example.test'})
            self.assertNotEqual(backend.rules, before)

    def test_menu_removal_visibility_and_order_for_both_connection_views(self):
        for tree in (object(), object()):
            for has_app, has_global in ((False, False), (True, False), (False, True), (True, True)):
                a = app()
                a.colors = {'fg': '#eee'}
                if has_app:
                    a.allowed_apps.add(NS['normalize_path']('C:\\demo.exe'))
                if has_global:
                    a.global_ports = a._parse_port_rules([port()])
                a.selected_connection_data = Mock(return_value=[connection()])
                a._show_header_menu = Mock(return_value=False)
                a._focus_menu_row = Mock(return_value='selected')
                menu = Mock()
                a._context_menu = Mock(return_value=menu)
                a.show_connection_menu(types.SimpleNamespace(x_root=1, y_root=1), tree)
                labels = [call.kwargs['label'] for call in menu.add_command.call_args_list]
                self.assertEqual('Remove App Rule' in labels, has_app)
                self.assertEqual('Remove Global Rule' in labels, has_global)
                if has_app and has_global:
                    self.assertLess(labels.index('Remove Global Rule'), labels.index('Open file location'))
                    self.assertLess(labels.index('Remove App Rule'), labels.index('Open file location'))
                    self.assertEqual(labels[-4:], ['Copy IP Domain', 'Copy details', 'Connection details', 'Open file location'])

    def test_removal_finds_saved_domain_and_cidr_and_keeps_app_rule(self):
        a = app()
        backend = MemoryFirewall(a)
        a.allowed_apps.add(NS['normalize_path']('C:\\demo.exe'))
        a.resolve_global_target = Mock(return_value=('192.0.2.1',))
        a._commit_rule_batch([('example.test', False, 'in', True), ('192.0.2.0/24', True, 'both', True)],
                             port_updates=[dict(port(action='Block'), target='example.test', direction='Inbound'),
                                           dict(port(), target='unrelated.test', addresses=['198.51.100.1'])])
        # Give the unrelated rule its own resolved endpoint.
        a.global_ports['remote:443:unrelated.test:Allow:Both']['addresses'] = ['198.51.100.1']
        a.selected_connection_data = Mock(return_value=[connection(direction='Incoming', domain='different-ptr.test')])
        a.remove_selected_connection_global_rules(object())
        self.assertEqual(a.global_blocks, {})
        self.assertEqual(a.global_allows, {})
        self.assertEqual(set(a.global_ports), {'remote:443:unrelated.test:Allow:Both'})
        self.assertTrue(a.application_has_rule('C:\\demo.exe'))
        a._remove_rule_batch = Mock()
        a.allowed_apps.clear()
        a.remove_selected_connection_rules(object())
        a._remove_rule_batch.assert_not_called()


class GlobalRuleOptionsTests(unittest.TestCase):
    def test_comma_ports_validate_and_match_each_endpoint(self):
        a = app()
        backend = MemoryFirewall(a)
        for invalid in ('80,', ',443', '80,,443', '80,0', '80,65536', '80,no'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                a._validate_global_rule_fields('', invalid, 'Remote')
        fields = a._validate_global_rule_fields('', ' 443, 80, 443 ', 'Remote')
        self.assertEqual(fields, ('', '80,443', 'remote'))
        for scope in ('local', 'remote'):
            a._commit_rule_batch([], port_updates=[dict(scope=scope, port=fields[1], action='Allow')])
            native = [r for r in backend.rules.values() if r.get('is_port') and r[f'{scope}_ports'] != ['Any']]
            self.assertEqual(len(native), 4)
            self.assertTrue(all(r[f'{scope}_ports'] == ['80', '443'] for r in native))
            for number in (80, 443, 81):
                row = connection(lport=number, dport=number)
                self.assertEqual(bool(a.matching_global_port_rules(row)), number != 81)

    def test_all_six_actions_preserve_direction_and_status_when_edited(self):
        for action, direction, suffix in (
                ('Allow', 'Both', ''), ('Allow Outgoing', 'Outbound', ' (out)'),
                ('Allow Incoming', 'Inbound', ' (in)'), ('Block Incoming', 'Inbound', ' (in)'),
                ('Block Outgoing', 'Outbound', ' (out)'), ('Block', 'Both', '')):
            with self.subTest(action=action):
                a = app()
                backend = MemoryFirewall(a)
                a._ask_global_rule_fields = Mock(return_value=('', '80,443', 'remote', 'TCP', action))
                a.add_global_rule_dialog()
                rule = next(iter(a.global_ports.values()))
                key = next(iter(a.global_ports))
                expected_sides = {'Inbound', 'Outbound'} if direction == 'Both' else {direction}
                self.assertEqual({r['direction'] for r in backend.rules.values() if r.get('is_port')}, expected_sides)
                expected_status = action.split()[0] + 'ed' + suffix + ' (Global)'
                managed = a._make_rule_rows({}, set(), {}, {})[0]
                self.assertEqual(managed['status'], expected_status)
                for side in ('Inbound', 'Outbound'):
                    row = connection(direction=side)
                    self.assertEqual(bool(a.matching_global_port_rules(row)), side in expected_sides)
                    if side in expected_sides:
                        self.assertEqual(a.connection_status(row), expected_status)
                        self.assertEqual(a.effective_connection_rule(row)[:2], ('port', key))
                a.add_global_rule_dialog = Mock()
                a.edit_global_rule(('port', key, rule))
                self.assertEqual(a.add_global_rule_dialog.call_args.args[0]['action'], action)
                self.assertTrue(a._remove_rule_batch([(managed['status'], key)]))
                self.assertFalse(a.global_ports)

    def test_unrestricted_rules_round_trip_restart_and_display(self):
        for scope in ('local', 'remote'):
            for protocol in ('TCP/UDP', 'TCP', 'UDP'):
                with self.subTest(scope=scope, protocol=protocol):
                    a = app()
                    backend = MemoryFirewall(a)
                    self.assertEqual(a._validate_global_rule_fields(' ', ' ', scope.title()), ('', None, scope))
                    a._ask_global_rule_fields = Mock(return_value=('', None, scope, protocol, 'Allow Incoming'))
                    a.add_global_rule_dialog()
                    rules = [r for r in backend.rules.values() if r.get('is_port')]
                    self.assertEqual(len(rules), 2 if protocol == 'TCP/UDP' else 1)
                    self.assertTrue(all(r['addresses'] == ['Any'] and r['local_ports'] == ['Any']
                                        and r['remote_ports'] == ['Any'] for r in rules))
                    managed = a._make_rule_rows({}, set(), {}, {})[0]
                    self.assertEqual(managed['rule'],
                                     f'All domains/IPs | Remote ports: All | Local ports: All | Protocol: {protocol}')
                    self.assertEqual((managed['remote_port'], managed['local_port']), ('All', 'All'))
                    self.assertEqual(managed['rule'], managed['display_path'])
                    self.assertNotIn('None', managed['rule'])
                    saved = json.loads(json.dumps(list(a.global_ports.values())))
                    self.assertEqual(a._parse_port_rules(saved), a.global_ports)
                    before = copy.deepcopy(backend.rules)
                    a.pending_rules = []
                    a.restore_saved_rules_locked()
                    self.assertEqual(backend.rules, before)
                    for candidate in ('TCP', 'UDP', 'ICMP'):
                        self.assertEqual(bool(a.matching_global_port_rules(connection(
                            direction='Incoming', dst_ip='2001:db8::1', dport=65535, protocol=candidate))),
                            candidate in ({'TCP', 'UDP'} if protocol == 'TCP/UDP' else {protocol}))

    def test_edit_replaces_ports_and_removes_previous_direction(self):
        a = app()
        backend = MemoryFirewall(a)
        a._commit_rule_batch([], port_updates=[dict(scope='remote', port='80,443', action='Allow')])
        old_key = next(iter(a.global_ports))
        replacement = dict(scope='local', port='53,5353', protocol='UDP', action='Block', direction='Outbound')
        a._commit_rule_batch([], port_updates=[replacement], replace_rule=('port', old_key))
        native = [r for r in backend.rules.values() if r.get('is_port')]
        self.assertEqual(len(native), 1)
        self.assertEqual(native[0]['direction'], 'Outbound')
        self.assertEqual(native[0]['local_ports'], ['53', '5353'])
        self.assertNotIn(old_key, a.global_ports)


    def test_edit_clearing_ports_restores_both_endpoints_to_all(self):
        for scope in ('local', 'remote'):
            with self.subTest(scope=scope):
                a = app()
                backend = MemoryFirewall(a)
                a._commit_rule_batch([], port_updates=[dict(scope=scope, port=443, action='Block')])
                key, policy = next(iter(a.global_ports.items()))
                a._ask_global_rule_fields = Mock(return_value=('', None, scope, 'TCP/UDP', 'Block'))
                a.edit_global_rule(('port', key, policy))
                native = [r for r in backend.rules.values() if r.get('is_port')]
                self.assertEqual(len(native), 4)
                self.assertTrue(all(r['local_ports'] == ['Any'] and r['remote_ports'] == ['Any']
                                    for r in native))
                managed, = a._make_rule_rows({}, set(), {}, {})
                self.assertEqual(managed['rule'],
                                 'All domains/IPs | Remote ports: All | Local ports: All | Protocol: TCP/UDP')
                self.assertEqual(managed['rule'], managed['display_path'])
                self.assertNotIn(key, a.global_ports)


if __name__ == '__main__':
    unittest.main()
