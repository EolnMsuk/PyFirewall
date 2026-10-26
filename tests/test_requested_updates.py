"""Grouped targets, passive DNS labels, themes and multi-selection regressions."""
import copy
import json
import socket
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch

from support import App, NS, patch_dependencies
from test_firewall_monitor import app
from test_native_port_rules import MemoryFirewall, connection
import test_ui_preferences as preferences


class GroupedTargetsTests(unittest.TestCase):
    def test_range_validation_and_boundaries(self):
        a = app()
        self.assertTrue(NS['is_global_target']('host-123'))
        self.assertTrue(NS['is_global_target']('edge-192.0.2.1'))
        for target in ('192.0.2.8-192.0.2.1', '192.0.2.1-2001:db8::1', '192.0.2.1-nope'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                a._validate_global_rule_fields(target, '', 'Remote')
        self.assertEqual(a._validate_global_rule_fields(
            ' [2001:db8::1] - [2001:db8::ff], 192.0.2.6 - 192.0.2.110 ', '', 'Remote')[0],
            '2001:db8::1-2001:db8::ff, 192.0.2.6-192.0.2.110')
        MemoryFirewall(a)
        a._commit_rule_batch([], port_updates=[dict(scope='remote', port=None, action='Block',
            target='192.0.2.6-192.0.2.110, 2001:db8::1-2001:db8::ff')])
        for ip, matches in [('192.0.2.5', False), ('192.0.2.6', True), ('192.0.2.110', True),
                            ('192.0.2.111', False), ('2001:db8::ff', True), ('2001:db8::100', False)]:
            self.assertEqual(bool(a.matching_global_port_rules(connection(dst_ip=ip))), matches)
        self.assertEqual(len(a.global_ports), 1)
        self.assertTrue(all(len(r['addresses']) == 2 for r in a._create_rule_batch.call_args.args[0]))

    def test_group_dialog_keeps_existing_independent_rule_and_deduplicates(self):
        a = app()
        MemoryFirewall(a)
        a._commit_rule_batch([], port_updates=[dict(scope='remote', port=None, action='Allow', target='192.0.2.1')])
        old = copy.deepcopy(a.global_ports)
        a._ask_global_rule_fields = Mock(return_value=(
            'example.test, 192.0.2.1, 192.0.2.6-192.0.2.110, EXAMPLE.TEST', None, 'remote', 'TCP/UDP', 'Allow'))
        with patch.object(socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('198.51.100.1', 0))]):
            a.add_global_rule_dialog()
        self.assertEqual(len(a.global_ports), 2)
        self.assertEqual(a.global_ports[next(iter(old))], next(iter(old.values())))
        group = next(r for r in a.global_ports.values() if ',' in r['target'])
        self.assertEqual(group['target'], 'example.test, 192.0.2.1, 192.0.2.6-192.0.2.110')
        self.assertEqual(set(group['addresses']), {'198.51.100.1', '192.0.2.1', '192.0.2.6-192.0.2.110'})
        planned = a._create_rule_batch.call_args.args[0]
        self.assertEqual(len(planned), 4)  # TCP/UDP x inbound/outbound, one address group each.
        self.assertTrue(all(set(r['addresses']) == set(group['addresses']) for r in planned))

    def test_group_roundtrip_offline_restart_edit_and_rollback(self):
        a = app()
        backend = MemoryFirewall(a)
        entry = dict(scope='remote', port=443, action='Block', target='one.test, two.test',
                     target_addresses={'one.test': ['192.0.2.1'], 'two.test': ['198.51.100.1']})
        with patch.object(socket, 'getaddrinfo', side_effect=socket.gaierror('offline')):
            a._commit_rule_batch([], port_updates=[entry])
            original = copy.deepcopy(backend.rules)
            a.global_ports = a._parse_port_rules(json.loads(json.dumps(list(a.global_ports.values()))))
            a.pending_rules = []
            a.restore_saved_rules_locked()
            self.assertEqual(backend.rules, original)
            key = next(iter(a.global_ports))
            before = copy.deepcopy(a.global_ports)
            backend.fail_once = True
            with patch_dependencies(log_internal_error=Mock()):
                self.assertFalse(a._apply_rule_batch([], quiet=True, port_updates=[dict(entry, action='Allow')], replace_rule=('port', key)))
            self.assertEqual(a.global_ports, before)
            self.assertEqual(backend.rules, original)
            a._ask_global_rule_fields = Mock(return_value=('one.test', 443, 'remote', 'TCP/UDP', 'Allow'))
            a.add_global_rule_dialog(dict(entry, addresses=['192.0.2.1', '198.51.100.1']), ('port', key))
            self.assertEqual(len(a.global_ports), 1)
            self.assertEqual(next(iter(a.global_ports.values()))['addresses'], ['192.0.2.1'])
            self.assertFalse(a.matching_global_port_rules(connection(dst_ip='198.51.100.1')))

    def test_context_action_preserves_group(self):
        a = app()
        a.global_ports = a._parse_port_rules([dict(scope='remote', port=443, action='Allow',
            target='192.0.2.1, 192.0.2.2', addresses=['192.0.2.1', '192.0.2.2'])])
        a.add_global_rule_dialog = Mock()
        a.prompt_connection_globals([connection()], False)
        self.assertEqual(a.add_global_rule_dialog.call_args.args[0]['target'], '192.0.2.1, 192.0.2.2')

    def test_range_traffic_does_not_double_count_overlap(self):
        a = app()
        a.ip_traffic = {'192.0.2.6': {'download': 7, 'upload': 3}, '192.0.2.110': {'download': 2, 'upload': 1}}
        self.assertEqual(a.target_traffic('192.0.2.6-192.0.2.110, 192.0.2.6'), (9, 4))


class CopyAndMenuTests(unittest.TestCase):
    def test_all_selected_connection_details_and_endpoints(self):
        for section in ('live', 'alerts'):
            with self.subTest(section=section):
                a = app()
                a.alerts_tree = object()
                tree = a.alerts_tree if section == 'alerts' else object()
                rows = [connection(name='one', pid=1, domain='one.test', signal=''),
                        connection(name='two', pid=2, dst_ip='2001:db8::2', domain='', signal='')]
                if section == 'alerts':
                    a.selected_rows = Mock(return_value=[('alert_1', ('', '', 'one', 1, '192.0.2.1', 'one.test')),
                                                        ('alert_2', ('', '', 'two', 2, '2001:db8::2', '—'))])
                    a.alert_connection_row = Mock(side_effect=lambda values, iid: dict(rows[int(iid[-1]) - 1]))
                else:
                    a.selected_connection_data = Mock(return_value=rows)
                a.active_connections = {}
                a.proc_traffic = {}
                a.copy_connection_details(tree)
                text = a.root.clipboard_append.call_args.args[0]
                self.assertIn('Process: one', text)
                self.assertIn('Process: two', text)
                a.copy_connection_endpoints(tree)
                self.assertEqual(a.root.clipboard_append.call_args.args[0], '192.0.2.1\tone.test\n2001:db8::2')

    def test_copy_all_selected_rules(self):
        a = app()
        a.selected_rows = Mock(return_value=[('one', ('Allowed', 'one.exe', 'Both', '0', '0', 'C:\\one.exe')),
                                            ('two', ('Blocked', 'two.exe', 'Both', '0', '0', 'C:\\two.exe'))])
        a.copy_rule_details(object())
        text = a.root.clipboard_append.call_args.args[0]
        self.assertIn('one.exe', text)
        self.assertIn('two.exe', text)

    def test_copy_endpoints_from_all_selected_global_rules(self):
        a = app()
        a.global_ports = a._parse_port_rules([dict(scope='remote', port=None, action='Allow',
            target='example.test, 192.0.2.6-192.0.2.110', addresses=['198.51.100.1', '192.0.2.6-192.0.2.110'])])
        key = next(iter(a.global_ports))
        a.global_allows['other.test'] = {'addresses': ['2001:db8::1']}
        a.selected_rows = Mock(return_value=[('one', ('Allowed (Global)', '', 'Both', '', '', key)),
                                            ('two', ('Global Allow', '', 'Both', '', '', 'other.test')),
                                            ('three', ('Allowed', '', 'Both', '', '', 'C:\\app.exe'))])
        a.copy_rule_endpoints(object())
        lines = a.root.clipboard_append.call_args.args[0].splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn('192.0.2.6-192.0.2.110', lines[0])
        self.assertTrue(lines[0].endswith('\texample.test'))
        self.assertEqual(lines[1], '2001:db8::1\tother.test')

    def test_app_and_all_global_menu_rows_highlight_independently(self):
        for dark in (False, True):
            for section in ('live', 'alerts'):
                with self.subTest(dark=dark, section=section):
                    a = app()
                    a.dark_mode = dark
                    a.colors = {'fg': '#333333'}
                    row = connection(key='selected')
                    a.allowed_apps.add(NS['normalize_path'](row['exe']))
                    a.global_ports = a._parse_port_rules([
                        dict(scope='remote', port=443, action='Allow'),
                        dict(scope='remote', port=None, action='Block', target='192.0.2.0/24', direction='Inbound')])
                    row['direction'] = 'Incoming'
                    a._show_header_menu = Mock(return_value=False)
                    a._focus_menu_row = Mock(return_value='selected')
                    menu = Mock()
                    a._context_menu = Mock(return_value=menu)
                    event = types.SimpleNamespace(x_root=1, y_root=1)
                    if section == 'alerts':
                        a.alerts_tree = Mock()
                        a.alert_connection_row = Mock(return_value=row)
                        a.selected_rows = Mock(return_value=[('selected', ())])
                        a.show_alert_menu(event)
                    else:
                        a.selected_connection_data = Mock(return_value=[row])
                        a.show_connection_menu(event, object())
                    entries = {call.kwargs['label']: call.kwargs for call in menu.add_command.call_args_list}
                    for label in ('Allow Process', 'Allow Connection', 'Block Incoming'):
                        self.assertIn('background', entries[label])
                        self.assertEqual(entries[label]['foreground'], '#ffffff' if dark else '#000000')
                        self.assertEqual(entries[label]['activeforeground'], '#ffffff' if dark else '#000000')
                    self.assertNotIn('background', entries['Block Process'])
                    labels = list(entries)
                    self.assertEqual(labels[labels.index('Copy details') - 1], 'Copy IP Domain')

    def test_advanced_firewall_launcher(self):
        with patch.object(NS['subprocess'], 'Popen') as launch:
            app().open_windows_firewall()
        self.assertEqual(launch.call_args.args[0], ['mmc.exe', 'wf.msc'])


class PassiveDnsTests(unittest.TestCase):
    def setUp(self):
        self.a = app()
        self.a.dns_lock = threading.Lock()
        self.a.dns_cache = {'192.0.2.1': 'edge.example.net'}
        self.a.dns_cache_times = {'192.0.2.1': time.monotonic()}

    def response(self, answers, **changes):
        dns = types.SimpleNamespace(qr=1, rcode=0, tc=0, qd=[types.SimpleNamespace(qname=b'www.example.test.', qtype=1)],
                                    an=answers, ancount=len(answers))
        vars(dns).update(changes)
        token = object()
        return token, {token: dns}

    def record(self, owner, kind, data, ttl=60):
        return types.SimpleNamespace(rrname=owner, type=kind, rdata=data, ttl=ttl)

    def test_cname_ipv4_ipv6_expiry_and_no_network_lookups(self):
        token, packet = self.response([
            self.record(b'www.example.test.', 5, b'edge.example.net.', 20),
            self.record(b'edge.example.net.', 1, '192.0.2.1'),
            self.record(b'edge.example.net.', 28, '2001:db8::1'),
            self.record(b'unrelated.test.', 1, '198.51.100.1')])
        with patch_dependencies(DNS=token), patch.object(socket, 'gethostbyaddr') as reverse, patch.object(socket, 'getaddrinfo') as forward:
            self.a.observe_dns_response(packet)
            self.assertEqual(self.a.remote_host(connection()), 'www.example.test (edge.example.net)')
            self.assertEqual(self.a.remote_host(connection(dst_ip='2001:db8::1')), 'www.example.test')
            self.assertNotIn('198.51.100.1', self.a.dns_observed_names)
            reverse.assert_not_called()
            forward.assert_not_called()
        with patch.object(NS['time'], 'monotonic', return_value=time.monotonic() + 21):
            self.assertEqual(self.a.remote_host(connection()), 'edge.example.net')

    def test_failed_truncated_query_and_zero_ttl_are_ignored(self):
        for changes in ({'qr': 0}, {'rcode': 3}, {'tc': 1}, {}):
            token, packet = self.response([self.record(b'www.example.test.', 1, '192.0.2.1', 0)], **changes)
            with patch_dependencies(DNS=token):
                self.a.observe_dns_response(packet)
        self.assertFalse(getattr(self.a, 'dns_observed_names', {}))


class LightThemeTests(unittest.TestCase):
    setUp = preferences.PreferenceWidgetTests.setUp
    destroy_root = preferences.PreferenceWidgetTests.destroy_root

    def test_settings_links_status_and_dynamic_buttons_across_themes(self):
        a = self.a
        def descendants(parent):
            for widget in parent.winfo_children():
                yield widget
                yield from descendants(widget)
        for dark in (False, True, False):
            a.dark_mode_var.set(dark)
            a.apply_theme()
            for widget in descendants(a.tab_settings):
                if isinstance(widget, (NS['tk'].Label, NS['tk'].LabelFrame)):
                    expected = a.colors[getattr(widget, '_theme_foreground_key', 'text')]
                    self.assertEqual(widget.cget('fg'), expected)
                if isinstance(widget, NS['tk'].Button) and hasattr(widget, '_pyfirewall_source_bg'):
                    self.assertEqual(widget.cget('fg'), '#ffffff' if dark else '#333333')
                    if not dark:
                        self.assertEqual(widget.master.cget('bg'), '#333333')
            a.startup_complete = a.capture_healthy = True
            a.is_paused = False
            a.update_status()
            self.assertEqual(a.status_state.cget('fg'), '#4CAF50')
            for attr in ('status_firewall', 'status_connections', 'status_rules', 'status_capture', 'status_traffic'):
                self.assertEqual(getattr(a, attr).cget('fg'), '#e8e8e8' if dark else '#202020')
            a.is_paused = True
            a.update_status()
            self.assertEqual(a.status_state.cget('fg'), '#ff9800')


if __name__ == '__main__':
    unittest.main()
