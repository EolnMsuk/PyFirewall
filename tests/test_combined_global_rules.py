"""Combined global policies and contextual removal without touching Windows Firewall."""
import copy
import json
import pathlib
import socket
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from support import patch_dependencies
from test_firewall_monitor import App, NS, app
from test_native_port_rules import MemoryFirewall, connection, port


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
        backend.fail_once = True
        with patch_dependencies(log_internal_error=Mock()):
            self.assertFalse(a._apply_rule_batch([], quiet=True, port_updates=[incoming]))
        self.assertEqual(backend.rules, baseline)
        self.assertTrue(a.apply_global_port_rules([incoming]))
        self.assertEqual(len(backend.rules), len(baseline) - 2)
        self.assertEqual(len(a.global_ports), 3)
        self.assertTrue(a._remove_rule_batch([('Global Port Block', 'remote:443:192.0.2.1')]))
        self.assertEqual(len(backend.rules), len(baseline) - 4)
        self.assertEqual(set(a.global_ports), {'remote:443', 'remote:443:192.0.2.2'})

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
                buttons = {w.cget('text'): w for w in children if isinstance(w, ttk.Button)}
                self.assertEqual(scope.get(), 'Remote')
                self.assertEqual(tuple(scope['values']), ('Remote', 'Local'))
                self.assertEqual(action.get(), 'Allow')
                self.assertEqual(protocol.get(), 'TCP/UDP')
                self.assertEqual(tuple(protocol['values']), ('TCP/UDP', 'TCP', 'UDP'))
                if mode == 'cancel':
                    buttons['Cancel'].invoke()
                    return
                with patch.object(NS['messagebox'], 'askokcancel', return_value=mode != 'validation_cancel') as prompt:
                    buttons['Save'].invoke()
                self.assertIn('At least one value', prompt.call_args.args[1])
                if mode == 'validation_cancel':
                    return
                self.assertTrue(dialog.winfo_exists())
                entries[0].insert(0, 'example.test, second.test')
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
        for target, number in (('', ''), ('  ', '  '), ('example.test', '0'), ('', '65536'), ('', 'abc'), ('C:\\x.exe', '443')):
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
        a.global_ports['remote:443:unrelated.test']['addresses'] = ['198.51.100.1']
        a.selected_connection_data = Mock(return_value=[connection(direction='Incoming', domain='different-ptr.test')])
        a.remove_selected_connection_global_rules(object())
        self.assertEqual(a.global_blocks, {})
        self.assertEqual(a.global_allows, {})
        self.assertEqual(set(a.global_ports), {'remote:443:unrelated.test'})
        self.assertTrue(a.application_has_rule('C:\\demo.exe'))
        a._remove_rule_batch = Mock()
        a.allowed_apps.clear()
        a.remove_selected_connection_rules(object())
        a._remove_rule_batch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
