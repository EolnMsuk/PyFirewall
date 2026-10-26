"""Rule-table behavior and drafts using the current DNS display names."""
import json
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch

from support import App, NS
from test_firewall_monitor import app
from test_native_port_rules import MemoryFirewall, connection
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
        self.assertEqual(labels[start:start + 3], ['Allow Connection', 'Block Incoming', 'Block Connection'])
        self.assertEqual(labels[-2:], ['Connection details', 'Open file location'])
        with patch.object(NS['socket'], 'getaddrinfo') as resolve:
            for call, action in zip(commands[start:start + 3], ('Allow', 'Block Incoming', 'Block')):
                call.kwargs['command']()
                draft = a.add_global_rule_dialog.call_args.args[0]
                self.assertEqual(draft['target'], 'friendly.test')
                self.assertEqual(draft['addresses'], ['192.0.2.1'])
                self.assertEqual(draft['action'], action)
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


class RuleTableTests(unittest.TestCase):
    setUp = preferences.PreferenceWidgetTests.setUp
    destroy_root = preferences.PreferenceWidgetTests.destroy_root

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
        a.rule_search_var.set('example.test')
        a.render_rules()
        iid, = a.rules_tree.get_children()
        a.rules_tree.selection_set(iid)
        mapping = dict(zip(App.RULE_COLUMNS, a.rules_tree.item(iid, 'values')))
        self.assertEqual(mapping['Application / Domain IP'], 'example.test (192.0.2.1)')
        self.assertEqual(mapping['Remote Port'], '443')
        self.assertEqual(mapping['Local Port'], '')
        self.assertIn('Remote Port: 443', a._rule_details_text(a.rules_tree))
        self.assertIn('Protocol: TCP', a._rule_details_text(a.rules_tree))
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
            'column_widths': {'rules': {'Rule / Application': 321}},
            'hidden_columns': {'rules': ['Rule / Application']}}))
        self.a.load_settings()
        self.assertEqual(self.a.column_orders['rules'][1], 'Application / Domain IP')
        self.assertEqual(self.a.column_widths['rules']['Application / Domain IP'], 321)
        self.assertIn('Application / Domain IP', self.a.hidden_columns['rules'])
        style = NS['ttk'].Style(self.root)
        for dark in (True, False, True):
            self.a.dark_mode_var.set(dark)
            self.a.apply_theme()
            expected = '#ffffff' if dark else self.a.colors['fg']
            for name in ('TEntry', 'Settings.TEntry'):
                self.assertEqual(style.lookup(name, 'insertcolor'), expected)
