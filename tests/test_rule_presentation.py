"""Rule-table behavior and drafts using the current DNS display names."""
import json
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch

from support import App, NS
from fixtures import MemoryFirewall, app, connection
import test_ui_preferences as preferences


class GlobalDraftTests(unittest.TestCase):
    def test_all_menu_actions_use_passive_dns_name_and_preserve_observed_ip(self):
        a = app()
        a.dns_lock = threading.Lock()
        a.dns_cache = {'192.0.2.1': 'reverse.test'}
        a.dns_cache_times = {'192.0.2.1': time.monotonic()}
        a.dns_observed_names = {'192.0.2.1': ('friendly.test', time.monotonic() + 60)}
        row = connection(key='selected', domain='')
        a.colors = {'fg': '#ffffff'}
        a._show_header_menu = Mock(return_value=False)
        a._focus_menu_row = Mock(return_value='selected')
        a.selected_connection_data = Mock(return_value=[row])
        a.add_global_rule_dialog = Mock()
        menu = Mock()
        a._context_menu = Mock(return_value=menu)
        a.show_connection_menu(types.SimpleNamespace(x_root=0, y_root=0), object())
        commands = menu.add_command.call_args_list
        labels = [c.kwargs['label'] for c in commands]
        self.assertEqual(labels[:3], ['Allow Process', 'Block Incoming', 'Block Process'])
        start = labels.index('Allow Connection')
        self.assertEqual(labels[start:start + 6], ['Allow Connection', 'Allow Outgoing', 'Allow Incoming', 'Block Incoming', 'Block Outgoing', 'Block Connection'])
        self.assertEqual(labels[-2:], ['Connection details', 'Open file location'])
        with patch.object(NS['socket'], 'getaddrinfo') as resolve:
            for call, action in zip(commands[start:start + 6], ('Allow', 'Allow Outgoing', 'Allow Incoming', 'Block Incoming', 'Block Outgoing', 'Block')):
                call.kwargs['command']()
                draft = a.add_global_rule_dialog.call_args.args[0]
                self.assertEqual(draft['target'], 'friendly.test')
                self.assertEqual(draft['addresses'], ['192.0.2.1'])
                self.assertEqual(draft['action'], action)
                self.assertEqual(draft['exe'], row['exe'])
            resolve.assert_not_called()
        a.dns_observed_names['192.0.2.1'] = ('expired.test', time.monotonic() - 1)
        self.assertEqual(a._connection_global_draft(row, 'Allow')['target'], 'reverse.test')
        a.dns_cache.clear()
        self.assertEqual(a._connection_global_draft(row, 'Allow')['target'], '192.0.2.1')

    def test_inbound_status_removes_both_global_storage_types_without_touching_apps(self):
        a = app()
        backend = MemoryFirewall(a, unrelated_count=2)
        backend.rules = {name: rule for name, rule in backend.rules.items() if not rule['is_hold']}
        original = dict(backend.rules)
        a._commit_rule_batch([('192.0.2.1', False, 'in', True)])
        a._commit_rule_batch([], port_updates=[dict(scope='local', port=53, action='Block',
                                                  protocol='UDP', direction='Inbound')])
        rows = a._make_rule_rows({}, set(), a.global_blocks, {})
        self.assertEqual({r['status'] for r in rows}, {'Blocked (in) (Global)'})
        self.assertEqual(a.connection_status(connection(direction='Incoming')), 'Blocked (in) (Global)')
        self.assertEqual(a.connection_status(connection(direction='Incoming', lport=53, protocol='UDP',
                                                       dst_ip='198.51.100.1')), 'Blocked (in) (Global)')
        self.assertTrue(a._remove_rule_batch([(r['status'], r['path']) for r in rows]))
        self.assertEqual(a.global_blocks, {})
        self.assertEqual(a.global_ports, {})
        self.assertEqual(backend.rules, original)


class MonitorSortingTests(unittest.TestCase):
    def test_remote_ip_header_toggles_numeric_ipv4_order_without_changing_text(self):
        a = app()
        rows = [{'dst_ip': value} for value in ('192.168.0.127', '8.8.8.8', '10.0.0.10', '10.0.0.2', '2.0.0.9')]
        a.tree, a.rules_tree = object(), object()
        a.monitor_sort, a.rule_sort, a.alert_sort = ['#', True], ['Status', False], ['Time', True]
        a.render_monitor = lambda: a.sort_monitor_rows(rows, a.monitor_sort)
        a.render_rules = a.render_alerts = Mock()
        expected = ['2.0.0.9', '8.8.8.8', '10.0.0.2', '10.0.0.10', '192.168.0.127']
        a.sort_tree(a.tree, 'Remote IP')
        self.assertEqual([r['dst_ip'] for r in rows], expected)
        a.sort_tree(a.tree, 'Remote IP')
        self.assertEqual([r['dst_ip'] for r in rows], expected[::-1])
        a.render_rules.assert_not_called()

    def test_mixed_ipv4_ipv6_and_missing_addresses_sort_consistently(self):
        a = app()
        expected = ['', 'Unknown', '8.8.8.8', '192.168.0.127', '::1', '2001:db8::2',
                    '2001:db8::10', '[fe80::a%12]', 'fe80::a%3']
        rows = [{'dst_ip': value} for value in reversed(expected)]
        for reverse in (False, True):
            a.sort_monitor_rows(rows, ['Remote IP', reverse])
            self.assertEqual([r['dst_ip'] for r in rows], expected[::-1] if reverse else expected)


class RuleTableTests(unittest.TestCase):
    setUp = preferences.PreferenceWidgetTests.setUp
    destroy_root = preferences.PreferenceWidgetTests.destroy_root

    def test_executable_columns_details_and_search_preserve_group_identity(self):
        a = self.a
        paths = [r'C:\First Folder\demo.exe', r'C:\Second, Folder\demo.exe']
        for programs, prefix, path_column in (
                ({}, '192.0.2.1', None),
                ({'exe': paths[0]}, 'demo.exe | 192.0.2.1', paths[0]),
                ({'exes': paths}, 'demo.exe, demo.exe | 192.0.2.1', 'demo.exe, demo.exe')):
            with self.subTest(programs=programs):
                a.global_ports = a._parse_port_rules([dict(
                    scope='remote', port=443, action='Block', target='192.0.2.1', **programs)])
                key = next(iter(a.global_ports))
                a.rule_rows = a._make_rule_rows({}, set(), {}, {})
                a.rule_search_var.set('')
                a.render_rules()
                iid, = a.rules_tree.get_children()
                a.rules_tree.selection_set(iid)
                values = dict(zip(App.RULE_COLUMNS, a.rules_tree.item(iid, 'values')))
                self.assertTrue(values['Application & Global Rules'].startswith(prefix))
                self.assertEqual(values['Program Path'], path_column or values['Application & Global Rules'])
                self.assertEqual(a.selected_rows(a.rules_tree)[0][1][-1], key)
                details = a._rule_details_text(a.rules_tree)
                for path in programs.get('exes', [programs['exe']] if 'exe' in programs else []):
                    self.assertIn(path, details)
                if programs:
                    a.rule_search_var.set(paths[0].lower())
                    a.render_rules()
                    self.assertEqual(a.rules_tree.get_children(), (iid,))

    def test_executable_groups_roundtrip_settings_and_versioned_backups(self):
        a = self.a
        paths = [r'C:\First Folder\demo.exe', r'C:\Second, Folder\demo.exe']
        a.global_ports = a._parse_port_rules([
            dict(scope='remote', port=443, action='Block', exes=paths),
            dict(scope='local', port=None, action='Allow', exe=paths[0]),
            dict(scope='remote', port=80, action='Allow')])
        saved = dict(a.global_ports)
        self.assertTrue(a.save_settings())
        a.global_ports.clear()
        a.load_settings()
        self.assertEqual(a.global_ports, saved)
        backup = self.config.with_name('grouped-rules.json')
        with patch.object(NS['filedialog'], 'asksaveasfilename', return_value=str(backup)), \
             patch.object(NS['messagebox'], 'showinfo'):
            a.export_rules()
        data = json.loads(backup.read_text())
        self.assertEqual(data['version'], 7)
        self.assertEqual(data['global_port_rules'], list(saved.values()))
        backend = MemoryFirewall(a)
        a.global_ports.clear()
        with patch.object(NS['filedialog'], 'askopenfilename', return_value=str(backup)), \
             patch.object(NS['messagebox'], 'askyesno', return_value=True), \
             patch.object(NS['messagebox'], 'showerror') as errors:
            a.import_rules()
        errors.assert_not_called()
        self.assertEqual(a.global_ports, saved)
        self.assertEqual(len([r for r in backend.rules.values() if r.get('is_port')]), 16)

    def test_independent_global_policies_survive_settings_backup_and_table_removal(self):
        a = self.a
        backend = MemoryFirewall(a)
        a.rules_changed = Mock()
        entries = [dict(scope='remote', port=443, action=action, direction=direction,
                        target='192.0.2.1', addresses=['192.0.2.1'], exe=r'C:\demo.exe')
                   for action in ('Allow', 'Block') for direction in ('Both', 'Inbound', 'Outbound')]
        a.global_ports = a._parse_port_rules(entries)
        saved = dict(a.global_ports)
        self.assertEqual(len(saved), 6)
        self.assertTrue(a.save_settings())
        a.global_ports.clear()
        a.load_settings()
        self.assertEqual(a.global_ports, saved)
        backup = self.config.with_name('rules.json')
        with patch.object(NS['filedialog'], 'asksaveasfilename', return_value=str(backup)), \
             patch.object(NS['messagebox'], 'showinfo'):
            a.export_rules()
        a.global_ports.clear()
        with patch.object(NS['filedialog'], 'askopenfilename', return_value=str(backup)), \
             patch.object(NS['messagebox'], 'askyesno', return_value=True), \
             patch.object(NS['messagebox'], 'showinfo'), \
             patch.object(NS['messagebox'], 'showerror') as errors:
            a.import_rules()
        errors.assert_not_called()
        self.assertEqual(a.global_ports, saved)
        self.assertEqual(len([r for r in backend.rules.values() if r.get('is_port')]), 16)
        a.rule_rows = a._make_rule_rows({}, set(), {}, {})
        a.render_rules()
        self.assertEqual(len(a.rules_tree.get_children()), 6)
        selected_key = next(k for k, p in saved.items()
                            if p['action'] == 'Block' and p.get('direction') == 'Inbound')
        a.rules_tree.selection_set('port:' + selected_key)
        a.remove_selected_rule()
        self.assertEqual(a.global_ports, {k: p for k, p in saved.items() if k != selected_key})
        self.assertEqual(len([r for r in backend.rules.values() if r.get('is_port')]), 14)

    def test_legacy_address_rules_describe_all_ports_and_keep_target_identity(self):
        a = self.a
        target = '2001:db8::1'
        for kind in ('allow', 'block'):
            with self.subTest(kind=kind):
                a.global_allows = {target: {'addresses': [target]}} if kind == 'allow' else {}
                a.global_blocks = {target: {'addresses': [target]}} if kind == 'block' else {}
                a.rule_rows = a._make_rule_rows({}, set(), a.global_blocks, a.global_allows)
                a.render_rules()
                iid, = a.rules_tree.get_children()
                a.rules_tree.selection_set(iid)
                values = dict(zip(App.RULE_COLUMNS, a.rules_tree.item(iid, 'values')))
                description = f'{target} | Remote ports: All | Local ports: All | Protocol: Any'
                self.assertEqual(values['Application & Global Rules'], description)
                self.assertEqual(values['Program Path'], description)
                self.assertEqual(a.selected_rows(a.rules_tree)[0][1][-1], target)
                a.copy_text = Mock()
                a.copy_rule_endpoints(a.rules_tree)
                a.copy_text.assert_called_once_with(target)
                a.add_global_rule_dialog = Mock()
                a.edit_selected_managed_rule(iid)
                self.assertEqual(a.add_global_rule_dialog.call_args.args[1], (kind, target))
                a._remove_rules_with_feedback = Mock()
                a.remove_selected_rule()
                self.assertEqual(list(a._remove_rules_with_feedback.call_args.args[0]),
                                 [(values['Status'], target)])

    def test_columns_sort_search_copy_and_edit_keep_rule_identity(self):
        a = self.a
        a.global_ports = a._parse_port_rules([
            dict(scope='remote', port=443, action='Block', protocol='TCP', direction='Inbound',
                 target='example.test', addresses=['192.0.2.1']),
            dict(scope='local', port=53, action='Allow', protocol='UDP'),
            dict(scope='remote', port=80, action='Allow', protocol='TCP'),
            dict(scope='remote', port=None, action='Allow', protocol='TCP/UDP', target='198.51.100.1')])
        a.rule_rows = a._make_rule_rows({}, {'C:\\demo.exe'}, {}, {})
        a.rule_sort = ['Remote Port', False]
        a.render_rules()
        values = [dict(zip(App.RULE_COLUMNS, a.rules_tree.item(iid, 'values')))
                  for iid in a.rules_tree.get_children()]
        application = next(v for v in values if v['Status'] == 'Allowed')
        self.assertEqual([application[k] for k in ('Remote Port', 'Local Port', 'Protocol')],
                         ['All', 'All', 'TCP/UDP'])
        self.assertEqual([v['Remote Port'] for v in values if v['Remote Port'].isdigit()], ['80', '443'])
        self.assertIn('All domains/IPs | Remote ports: All | Local ports: 53 | Protocol: UDP',
                      [v['Application & Global Rules'] for v in values])
        self.assertIn('All domains/IPs | Remote ports: 80 | Local ports: All | Protocol: TCP',
                      [v['Application & Global Rules'] for v in values])
        no_port = next(v for v in values if v['Application & Global Rules'].startswith('198.51.100.1 |'))
        self.assertEqual((no_port['Remote Port'], no_port['Local Port']), ('All', 'All'))
        self.assertEqual(no_port['Program Path'],
                         '198.51.100.1 | Remote ports: All | Local ports: All | Protocol: TCP/UDP')
        a.rules_tree.selection_set('port:remote:None:198.51.100.1:Allow:Both')
        a._remove_rules_with_feedback = Mock()
        a.remove_selected_rule()
        self.assertEqual(list(a._remove_rules_with_feedback.call_args.args[0]),
                         [('Allowed (Global)', 'remote:None:198.51.100.1:Allow:Both')])
        a.rule_search_var.set('example.test')
        a.render_rules()
        iid, = a.rules_tree.get_children()
        a.rules_tree.selection_set(iid)
        mapping = dict(zip(App.RULE_COLUMNS, a.rules_tree.item(iid, 'values')))
        self.assertEqual(mapping['Application & Global Rules'],
                         'example.test (192.0.2.1) | Remote ports: 443 | Local ports: All | Protocol: TCP')
        self.assertEqual(mapping['Program Path'], mapping['Application & Global Rules'])
        self.assertEqual(mapping['Remote Port'], '443')
        self.assertEqual(mapping['Local Port'], 'All')
        self.assertIn('Remote Port: 443', a._rule_details_text(a.rules_tree))
        self.assertIn('Protocol: TCP', a._rule_details_text(a.rules_tree))
        self.assertIn('Path/Target: ' + mapping['Program Path'], a._rule_details_text(a.rules_tree))
        a.copy_text = Mock()
        a.copy_rule_endpoints(a.rules_tree)
        a.copy_text.assert_called_once_with('192.0.2.1\texample.test')
        a.add_global_rule_dialog = Mock()
        a.prompt_selected_global_rules(True)
        self.assertEqual(a.add_global_rule_dialog.call_args.args[0]['port'], 443)
        a.rule_search_var.set('UDP')
        a.render_rules()
        self.assertTrue(all('UDP' in a.rules_tree.set(iid, 'Protocol') for iid in a.rules_tree.get_children()))

    def test_saved_column_preferences_migrate_and_caret_tracks_theme(self):
        self.config.write_text(json.dumps({
            'column_orders': {'rules': ['Direction', 'Rule / Application', 'Status', 'Program Path']},
            'column_widths': {'rules': {'Application / Domain IP': 321}},
            'hidden_columns': {'rules': ['Rule / Application']}}))
        self.a.load_settings()
        self.assertEqual(self.a.column_orders['rules'][1], 'Application & Global Rules')
        self.assertEqual(self.a.column_widths['rules']['Application & Global Rules'], 321)
        self.assertIn('Application & Global Rules', self.a.hidden_columns['rules'])
        style = NS['ttk'].Style(self.root)
        for dark in (True, False, True):
            self.a.dark_mode_var.set(dark)
            self.a.apply_theme()
            expected = '#ffffff' if dark else self.a.colors['fg']
            for name in ('TEntry', 'Settings.TEntry'):
                self.assertEqual(style.lookup(name, 'insertcolor'), expected)
