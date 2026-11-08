"""Executable-scoped policies use mocked firewall operations only."""
import copy
import json
import types
import unittest
from unittest.mock import Mock

from fixtures import MemoryFirewall, app, connection
from helpers import rule_executables


class ProcessGlobalTests(unittest.TestCase):
    def test_scope_identity_matching_restart_and_app_removal(self):
        a = app()
        backend = MemoryFirewall(a)
        a._cancel_app_prompt = Mock()
        policy = dict(scope='remote', port=443, action='Block', exe=r'C:\one\demo.exe')
        sibling = dict(policy, exe=r'C:\two\demo.exe')
        a._commit_rule_batch([], port_updates=[policy, sibling, dict(policy, exe='')])
        self.assertEqual(len(a.global_ports), 3)
        scoped = a.matching_global_port_rules(connection(exe=r'C:\ONE\demo.exe'))
        self.assertEqual(len(scoped), 2)
        self.assertEqual(len(a.matching_global_port_rules(connection(exe=''))), 1)
        self.assertEqual(a._parse_port_rules(json.loads(json.dumps(list(a.global_ports.values())))), a.global_ports)
        a.pending_rules = []
        before = copy.deepcopy(backend.rules)
        a.restore_saved_rules_locked()
        self.assertEqual(backend.rules, before)
        a._commit_rule_batch([(policy['exe'], False, 'both', False)])
        a._remove_rule_batch([('Blocked', policy['exe'])])
        self.assertEqual(backend.rules, before)
        key = next(k for k, v in a.global_ports.items() if v.get('exe') == policy['exe'])
        a._remove_rule_batch([('Blocked (Global)', key)])
        self.assertEqual(len(a.global_ports), 2)
        self.assertFalse(any(r.get('path') == policy['exe'] for r in backend.rules.values()))

    def test_block_precedence_is_directional_and_global_wins_ties(self):
        a = app()
        a.global_ports = a._parse_port_rules([dict(scope='remote', port=443, action='Block',
                                                 direction='Outbound', exe=r'C:\demo.exe')])
        a.blocked_paths = {r'c:\demo.exe': dict(path=r'C:\demo.exe', **{'in': True, 'out': True})}
        out = connection()
        self.assertEqual(a.connection_tag(out), 'global_block_out')
        self.assertEqual(a.effective_connection_rule(out)[0], 'port')
        self.assertEqual(a.connection_tag(connection(direction='Incoming')), 'blocked')
        a.blocked_paths[r'c:\demo.exe']['out'] = False
        a.global_ports = a._parse_port_rules([dict(scope='remote', port=443, action='Allow', exe=r'C:\demo.exe')])
        self.assertEqual(a.connection_tag(out), 'global_allow')
        self.assertEqual(a.connection_tag(connection(direction='Incoming')), 'blocked_in')
        self.assertEqual(a.connection_tag(connection(exe=r'C:\other\demo.exe')), 'even')
        self.assertTrue(a.connection_has_rule(r'C:\demo.exe', '192.0.2.1', '', 'Outgoing', 51000, 443))
        self.assertFalse(a.connection_has_rule(r'C:\other.exe', '192.0.2.1', '', 'Outgoing', 51000, 443))

    def test_failed_scoped_edit_restores_program_and_preserves_sibling(self):
        a = app()
        backend = MemoryFirewall(a)
        policy = dict(scope='remote', port=443, action='Block', exe=r'C:\demo.exe')
        a._commit_rule_batch([], port_updates=[policy, dict(policy, exe=r'C:\other.exe')])
        key = next(iter(a.global_ports))
        before = copy.deepcopy(backend.rules)
        backend.fail_once = True
        with self.assertRaises(RuntimeError):
            a._commit_rule_batch([], port_updates=[dict(policy, action='Allow')], replace_rule=('port', key))
        self.assertEqual(backend.rules, before)
        self.assertEqual(len(a.global_ports), 2)

    def test_native_payload_combines_program_with_filters_and_readback(self):
        a = app()
        policy = dict(scope='remote', port=443, action='Block', exe=r'C:\demo.exe', protocol='TCP')
        native = a._port_firewall_rules(a._parse_port_rules([policy]))
        a.run_ps = Mock()
        a._create_rule_batch(native)
        script = a.run_ps.call_args.args[0]
        self.assertIn('if ($rule.path) { $params.Program=', script)
        self.assertIn('$expectedProgram = [string]$rule.path', script)
        self.assertTrue(all(r['path'] == policy['exe'] and r['remote_ports'] == ['443'] for r in native))
        a.run_ps.return_value.stdout = json.dumps([dict(DisplayName=native[0]['name'], Action='Block',
            Direction='Inbound', Program=policy['exe'], Protocol='TCP', LocalPorts=['Any'], RemotePorts=['443'])])
        record, = a.get_firewall_rules()
        self.assertEqual(record['path'], policy['exe'])
        self.assertEqual(record['normalized_path'], '')
        self.assertTrue(record['is_global'])


class MultiExecutableGlobalTests(unittest.TestCase):
    paths = [r'C:\First Folder\demo.exe', r'C:\Second, Folder\demo.exe']

    def policy(self, **changes):
        return dict(dict(scope='remote', port=443, action='Block', exes=list(self.paths)), **changes)

    def test_normalization_deduplicates_full_paths_and_rejects_invalid_scopes(self):
        a = app()
        entry = self.policy(exes=[self.paths[0], self.paths[0].upper(), self.paths[1]])
        parsed, = a._parse_port_rules([entry]).values()
        self.assertEqual(parsed['exes'], self.paths)
        self.assertNotIn('exe', parsed)
        unrestricted, = a._parse_port_rules([self.policy(exe=self.paths[0], exes=[])]).values()
        self.assertNotIn('exe', unrestricted)
        self.assertNotIn('exes', unrestricted)
        singleton, = a._parse_port_rules([self.policy(exes=[self.paths[0]])]).values()
        self.assertEqual(singleton['exe'], self.paths[0])
        for value in ('C:\\a.exe', None, [None], [''], ['relative.exe'], [r'C:relative.exe'],
                      [r'\rooted.exe'], [r'C:\valid.exe', r'C:\invalid.txt']):
            with self.subTest(value=value), self.assertRaises(ValueError):
                a._parse_port_rules([self.policy(exes=value)])

    def test_set_identity_native_filters_and_matching(self):
        a = app()
        policy = self.policy(protocol='TCP', direction='Outbound', target='192.0.2.1')
        policies = a._parse_port_rules([policy])
        reordered = a._parse_port_rules([dict(policy, exes=self.paths[::-1])])
        self.assertEqual(set(policies), set(reordered))
        native = a._port_firewall_rules(policies)
        self.assertEqual(len(native), 2)
        self.assertEqual({r['path'] for r in native}, set(self.paths))
        self.assertTrue(all(r['protocol'] == 'TCP' and r['direction'] == 'Outbound'
                            and r['remote_ports'] == ['443'] for r in native))
        names = {r['name'] for r in native}
        self.assertEqual(names, {r['name'] for r in a._port_firewall_rules(reordered)})
        for other in (self.policy(exes=[self.paths[0]]), self.policy(exes=[self.paths[0], r'C:\third.exe'])):
            self.assertFalse(names & {r['name'] for r in a._port_firewall_rules(a._parse_port_rules([other]))})
        a.global_ports = policies
        for path in self.paths:
            self.assertEqual(len(a.matching_global_port_rules(connection(exe=path.upper()))), 1)
        for changes in (dict(exe=r'C:\unrelated.exe'), dict(exe=''), dict(protocol='UDP'),
                        dict(direction='Incoming'), dict(dport=80), dict(dst_ip='192.0.2.2')):
            row = connection(exe=self.paths[0])
            row.update(changes)
            self.assertEqual(a.matching_global_port_rules(row), {})

    def test_group_replacement_rollback_removal_and_restart_keep_siblings(self):
        a = app()
        backend = MemoryFirewall(a)
        group = self.policy()
        singleton = self.policy(exes=[self.paths[0]])
        overlap = self.policy(exes=[self.paths[0], r'C:\third.exe'])
        a._commit_rule_batch([], port_updates=[group, singleton, overlap])
        key = next(key for key, value in a.global_ports.items() if value.get('exes') == self.paths)
        saved, native = copy.deepcopy(a.global_ports), copy.deepcopy(backend.rules)
        a.pending_rules = []
        a.restore_saved_rules_locked()
        self.assertEqual(backend.rules, native)
        # Reordered paths are a duplicate, without any native rewrite.
        a._create_rule_batch.reset_mock()
        self.assertTrue(a._apply_rule_batch([], port_updates=[self.policy(exes=self.paths[::-1])]))
        a._create_rule_batch.assert_not_called()
        backend.fail_once = True
        replacement = self.policy(exes=[self.paths[1], r'C:\fourth.exe'], action='Allow', direction='Inbound')
        with self.assertRaises(RuntimeError):
            a._commit_rule_batch([], port_updates=[replacement], replace_rule=('port', key))
        self.assertEqual(a.global_ports, saved)
        self.assertEqual(backend.rules, native)
        old_names = {r['name'] for r in a._port_firewall_rules({key: saved[key]})}
        a._commit_rule_batch([], port_updates=[replacement], replace_rule=('port', key))
        new_key = next(key for key, rule in a.global_ports.items() if rule['action'] == 'Allow')
        self.assertTrue(old_names.isdisjoint(backend.rules))
        self.assertTrue(a._remove_rule_batch([('Allowed (in) (Global)', new_key)]))
        self.assertEqual(a.global_ports, {k: v for k, v in saved.items() if k != key})
        self.assertEqual(backend.rules, {k: v for k, v in native.items() if k not in old_names})

    def test_editor_conflicts_compare_sets_and_connection_edits_keep_all_paths(self):
        a = app()
        a.global_ports = a._parse_port_rules([self.policy()])
        key = next(iter(a.global_ports))
        fields = ('', 443, 'remote', 'TCP/UDP', 'Block', self.paths[::-1])
        self.assertIn('already exists', a._global_editor_conflict(fields))
        self.assertIsNone(a._global_editor_conflict(fields, ('port', key)))
        a.add_global_rule_dialog = Mock()
        a.prompt_connection_globals([connection(exe=self.paths[0])], True)
        initial, replacement = a.add_global_rule_dialog.call_args.args
        self.assertEqual(rule_executables(initial), self.paths)
        self.assertNotIn('exe', initial)
        self.assertEqual(replacement, ('port', key))
        descriptions = a._connection_rule_descriptions(connection(exe=self.paths[1]))
        self.assertTrue(all(path in descriptions[0] for path in self.paths))

    def test_multiple_targets_and_executables_submit_as_one_policy(self):
        a = app()
        MemoryFirewall(a)
        a._ask_global_rule_fields = Mock(return_value=(
            '192.0.2.1, 192.0.2.2', None, 'remote', 'TCP', 'Block', self.paths))
        a.add_global_rule_dialog()
        policy, = a.global_ports.values()
        self.assertEqual(rule_executables(policy), self.paths)
        self.assertEqual(policy['target'], '192.0.2.1, 192.0.2.2')
        self.assertEqual(len(a._make_rule_rows({}, set(), {}, {})), 1)
        for path in self.paths:
            for target in ('192.0.2.1', '192.0.2.2'):
                self.assertEqual(a.connection_tag(connection(exe=path, dst_ip=target)), 'global_block')


class RowCopyTests(unittest.TestCase):
    def test_copy_uses_display_order_visible_columns_and_one_line_per_row(self):
        a = app()
        tree = Mock()
        tree.selection.return_value = ('second', 'first')
        tree.get_children.return_value = ('first', 'second', 'unselected')
        class Table:
            def __getitem__(self, key):
                return {'columns': ('hidden', 'name', 'status'), 'displaycolumns': ('status', 'name')}[key]
            selection = tree.selection
            get_children = tree.get_children
            def item(self, iid, option):
                return ('secret', 'A\nB' if iid == 'first' else 'C', 'Blocked')
        a.copy_text = Mock()
        self.assertEqual(a.copy_selected_rows(types.SimpleNamespace(widget=Table())), 'break')
        a.copy_text.assert_called_once_with('Blocked\tA B\nBlocked\tC')
        tree.selection.return_value = ()
        a.copy_text.reset_mock()
        a.copy_selected_rows(types.SimpleNamespace(widget=Table()))
        a.copy_text.assert_not_called()
