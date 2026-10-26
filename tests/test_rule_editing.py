"""Rule editing, protocol selection and context actions with a simulated firewall."""
import copy
import types
import unittest
from unittest.mock import Mock, patch

from support import NS, patch_dependencies
from test_firewall_monitor import app
from test_native_port_rules import MemoryFirewall, connection, port


class ProtocolAndReplacementTests(unittest.TestCase):
    def test_protocol_matching_native_rules_and_restart(self):
        for protocol in ('TCP/UDP', 'TCP', 'UDP'):
            for number in (None, 443):
                with self.subTest(protocol=protocol, port=number):
                    a = app()
                    backend = MemoryFirewall(a)
                    a._commit_rule_batch([], port_updates=[dict(port(number=number), target='192.0.2.1', protocol=protocol)])
                    rules = [r for r in backend.rules.values() if r.get('is_port')]
                    expected = {'TCP', 'UDP'} if protocol == 'TCP/UDP' else {protocol}
                    self.assertEqual({r['protocol'] for r in rules}, expected)
                    self.assertEqual(len(rules), 2 * len(expected))
                    for candidate in ('TCP', 'UDP', 'ICMP'):
                        self.assertEqual(bool(a.matching_global_port_rules(connection(protocol=candidate))), candidate in expected)
                    self.assertEqual(bool(a.matching_global_port_rules(connection(protocol=next(iter(expected)), dport=80))), number is None)
                    a.pending_rules = []
                    before = copy.deepcopy(backend.rules)
                    a.restore_saved_rules_locked()
                    self.assertEqual(before, backend.rules)

    def test_overlapping_protocol_policies_have_independent_names(self):
        a = app()
        backend = MemoryFirewall(a)
        entries = [dict(port(), protocol=p) for p in ('TCP/UDP', 'TCP', 'UDP')]
        a._commit_rule_batch([], port_updates=entries)
        self.assertEqual(len([r for r in backend.rules.values() if r.get('is_port')]), 8)
        a._remove_rule_batch([('Global Port Allow', 'remote:443:TCP')])
        self.assertEqual(len([r for r in backend.rules.values() if r.get('is_port')]), 6)
        self.assertEqual(set(a.global_ports), {'remote:443', 'remote:443:UDP'})

    def test_edit_changes_all_fields_atomically_and_rolls_back_on_failure(self):
        a = app()
        backend = MemoryFirewall(a)
        original = dict(port(action='Block'), target='192.0.2.1')
        a._commit_rule_batch([], port_updates=[original, port(number=80)])
        old_key = next(k for k, r in a.global_ports.items() if r.get('target'))
        before = copy.deepcopy(backend.rules)
        cache = copy.deepcopy(a.global_ports)
        replacement = dict(port('local', 53), protocol='UDP', target='198.51.100.1', direction='Inbound')
        backend.fail_once = True
        with patch_dependencies(log_internal_error=Mock()):
            self.assertFalse(a._apply_rule_batch([], port_updates=[replacement], replace_rule=('port', old_key), quiet=True))
        self.assertEqual(backend.rules, before)
        self.assertEqual(a.global_ports, cache)
        self.assertTrue(a._apply_rule_batch([], port_updates=[replacement], replace_rule=('port', old_key), quiet=True))
        self.assertNotIn(old_key, a.global_ports)
        self.assertEqual(set(a.global_ports), {'remote:80', 'local:53:UDP:198.51.100.1'})
        native = [r for r in backend.rules.values() if r.get('is_port')]
        self.assertEqual(len(native), 5)
        self.assertEqual(sum(r['protocol'] == 'UDP' and r['direction'] == 'Inbound' and r['local_ports'] == ['53'] for r in native), 1)

    def test_legacy_address_rule_edit_removes_old_policy_only_after_success(self):
        a = app()
        backend = MemoryFirewall(a)
        a._restore_app_rule_records = Mock(side_effect=backend.create)
        a._commit_rule_batch([('192.0.2.1', False, 'both', True)])
        before = copy.deepcopy(backend.rules)
        replacement = dict(port(number=None), target='192.0.2.1', protocol='TCP')
        backend.fail_once = True
        with patch_dependencies(log_internal_error=Mock()):
            self.assertFalse(a._apply_rule_batch([], port_updates=[replacement], replace_rule=('block', '192.0.2.1'), quiet=True))
        self.assertEqual(backend.rules, before)
        self.assertIn('192.0.2.1', a.global_blocks)
        self.assertTrue(a._apply_rule_batch([], port_updates=[replacement], replace_rule=('block', '192.0.2.1'), quiet=True))
        self.assertEqual(a.global_blocks, {})
        self.assertEqual(a.connection_tag(connection()), 'global_allow')
        self.assertEqual(a.connection_tag(connection(protocol='UDP')), 'even')

    def test_invalid_protocol_and_unrestricted_empty_rule_rejected(self):
        a = app()
        for entry in (dict(port(), protocol='ICMP'), dict(port(), protocol=''), port(number=None),
                      dict(port(number=None), target='  ')):
            with self.assertRaises(ValueError):
                a._parse_port_rules([entry])

    def test_partial_invalid_and_unresolved_targets_report_each_failure(self):
        a = app()
        MemoryFirewall(a)
        a._ask_global_rule_fields = Mock(return_value=('192.0.2.1, missing.test, https://bad.test', None, 'remote', 'UDP', 'Allow'))
        def resolve(target, *args):
            if target == 'missing.test':
                raise ValueError('DNS lookup failed')
            return ('192.0.2.1',)
        a.resolve_global_target = Mock(side_effect=resolve)
        with patch.object(NS['messagebox'], 'showwarning') as warning:
            a.add_global_rule_dialog()
        self.assertEqual(len(a.global_ports), 1)
        text = warning.call_args.args[1]
        self.assertIn('1 valid target(s) processed', text)
        self.assertIn('missing.test: DNS lookup failed', text)
        self.assertIn('https://bad.test: Not a valid', text)

    def test_no_resolved_targets_keeps_original_rule(self):
        a = app()
        backend = MemoryFirewall(a)
        a._commit_rule_batch([], port_updates=[port()])
        before = copy.deepcopy(backend.rules)
        a._ask_global_rule_fields = Mock(return_value=('missing.test', 53, 'local', 'TCP', 'Block'))
        a.resolve_global_target = Mock(side_effect=ValueError('DNS failed'))
        with patch.object(NS['messagebox'], 'showwarning') as warning:
            a.add_global_rule_dialog({}, ('port', 'remote:443'))
        self.assertEqual(backend.rules, before)
        self.assertIn('existing rule was kept', warning.call_args.args[1])


class EditingAndMenuTests(unittest.TestCase):
    def test_domain_rows_show_saved_addresses_and_keep_edit_identity(self):
        for action, direction in (('Allow', 'Both'), ('Block', 'Both'), ('Block', 'Inbound')):
            for number in (None, 443):
                with self.subTest(action=action, direction=direction, port=number):
                    a = app()
                    addresses = ['192.0.2.1', '2001:db8::1']
                    a.global_ports = a._parse_port_rules([dict(
                        port(number=number, action=action), target='example.test',
                        addresses=addresses, direction=direction)])
                    key = next(iter(a.global_ports))
                    a.rule_rows = a._make_rule_rows({}, set(), {}, {})
                    row = a.rule_rows[0]
                    self.assertIn('example.test (192.0.2.1, 2001:db8::1)', row['rule'])
                    self.assertEqual(row['direction'], direction)
                    self.assertEqual(row['path'], key)
                    self.assertEqual(row['normalized_path'], key)
                    a.add_global_rule_dialog = Mock()
                    a.edit_selected_managed_rule(row['iid'])
                    initial, identity = a.add_global_rule_dialog.call_args.args
                    self.assertEqual(identity, ('port', key))
                    self.assertEqual(initial['target'], 'example.test')
                    self.assertEqual(initial['addresses'], addresses)

    def test_editor_follows_displayed_priority(self):
        a = app()
        row = connection()
        a.global_ports = a._parse_port_rules([dict(port(action='Block'), protocol='TCP')])
        a.allowed_apps.add(NS['normalize_path'](row['exe']))
        a.edit_global_rule = Mock()
        a.edit_app_rule = Mock()
        a.edit_connection_rule(row)
        self.assertEqual(a.edit_global_rule.call_args.args[0][0], 'port')
        a.edit_app_rule.assert_not_called()
        a.allowed_apps.clear()
        a.blocked_paths[NS['normalize_path'](row['exe'])] = {'path': row['exe'], 'in': True, 'out': True}
        a.edit_global_rule.reset_mock()
        a.edit_connection_rule(row)
        a.edit_app_rule.assert_called_once()
        a.edit_global_rule.assert_not_called()

    def test_new_connection_type_selection_and_cancel(self):
        for choice in ('app', 'global', None):
            a = app()
            a._choose_option = Mock(return_value=choice)
            a.edit_app_rule = Mock()
            a.add_global_rule_dialog = Mock()
            a.edit_connection_rule(connection())
            self.assertEqual(a.edit_app_rule.called, choice == 'app')
            self.assertEqual(a.add_global_rule_dialog.called, choice == 'global')
            if choice == 'global':
                self.assertEqual(a.add_global_rule_dialog.call_args.args[0]['action'], 'Allow')

    def test_global_edit_prefills_policy(self):
        a = app()
        a.add_global_rule_dialog = Mock()
        entry = dict(port('local', 53, 'Block'), target='example.test', protocol='UDP', direction='Inbound')
        a.edit_global_rule(('port', 'saved-key', entry))
        initial, old = a.add_global_rule_dialog.call_args.args
        self.assertEqual(initial, dict(entry, editing=True, action='Block Incoming'))
        self.assertEqual(old, ('port', 'saved-key'))

    def test_connection_menu_collapses_globals_and_highlights_effective_policy(self):
        a = app()
        MemoryFirewall(a)
        a.colors = {'fg': '#e8e8e8', 'global_block': '#593570'}
        a.global_ports = a._parse_port_rules([port(action='Block')])
        a.selected_connection_data = Mock(return_value=[connection(key='selected')])
        a._show_header_menu = Mock(return_value=False)
        a._focus_menu_row = Mock(return_value='selected')
        menu = Mock()
        a._context_menu = Mock(return_value=menu)
        a.show_connection_menu(types.SimpleNamespace(x_root=1, y_root=1), object())
        entries = {c.kwargs['label']: c.kwargs for c in menu.add_command.call_args_list}
        self.assertTrue({'Allow Connection', 'Block Connection', 'Block Incoming'} <= set(entries))
        self.assertFalse(any('Port (Global)' in k for k in entries))
        selected = entries['Block Connection']
        self.assertEqual(selected['foreground'], '#ffffff')
        self.assertEqual(selected['background'], '#4b2d5f')
        a.add_global_rule_dialog = Mock()
        entries['Allow Connection']['command']()
        initial, old = a.add_global_rule_dialog.call_args.args
        self.assertEqual(initial['action'], 'Allow')
        self.assertEqual(initial['port'], 443)
        self.assertEqual(old, ('port', 'remote:443'))

    def test_details_actions_capture_connection_and_copy_full_text(self):
        a = app()
        row = connection(name='demo', pid=1, domain='', signal='')
        a.active_connections = {'selected': row}
        a.proc_traffic = {}
        a.selected_connection_data = Mock(return_value=[row])
        a._show_details_dialog = Mock()
        a.open_file_location = Mock()
        a.remove_connection_rule = Mock()
        a.show_connection_details(object())
        call = a._show_details_dialog.call_args
        actions = {label: (callback, color) for label, callback, color in call.kwargs['actions']}
        self.assertEqual(set(actions), {'Copy Info', 'Open File Location'})
        actions['Copy Info'][0]()
        a.root.clipboard_append.assert_called_once_with(call.args[1])
        actions['Open File Location'][0]()
        a.open_file_location.assert_called_once_with(row['exe'])
        a.remove_connection_rule.assert_not_called()

    def test_context_copy_uses_the_same_details_text(self):
        a = app()
        row = connection(name='demo', pid=1)
        a.colors = {'fg': '#e8e8e8', 'muted': '#a8a8a8'}
        a.tree = Mock()
        a._show_header_menu = Mock(return_value=False)
        a._focus_menu_row = Mock(return_value='selected')
        a.selected_connection_data = Mock(return_value=[row])
        a.connection_tag = Mock(return_value='even')
        a.application_has_rule = Mock(return_value=False)
        a.connection_global_rules = Mock(return_value=[])
        menu = Mock()
        a._context_menu = Mock(return_value=menu)
        a.copy_connection_details = Mock()
        event = types.SimpleNamespace(x_root=1, y_root=1)
        a.show_connection_menu(event, a.tree)
        entries = {call.kwargs['label']: call.kwargs['command'] for call in menu.add_command.call_args_list}
        entries['Copy details']()
        a.copy_connection_details.assert_called_once_with(a.tree)

        a.rules_tree = Mock()
        a.rules_tree.item.return_value = ('Allowed', 'demo.exe', 'Both', '0.00 MB', '0.00 MB', 'C:\\demo.exe')
        a._focus_menu_row = Mock(return_value='selected')
        a.copy_rule_details = Mock()
        menu = Mock()
        a._context_menu = Mock(return_value=menu)
        a.show_rules_menu(event)
        entries = {call.kwargs['label']: call.kwargs['command'] for call in menu.add_command.call_args_list}
        entries['Copy details']()
        a.copy_rule_details.assert_called_once_with(a.rules_tree)

    def test_rule_actions_form_a_separate_section_before_details(self):
        a = app()
        a.colors = {'fg': '#e8e8e8', 'muted': '#a8a8a8'}
        a.rules_tree = Mock()
        a.rules_tree.item.return_value = ('Allowed', 'demo.exe', 'Both', '0.00 MB', '0.00 MB', 'C:\\demo.exe')
        a._show_header_menu = Mock(return_value=False)
        a._focus_menu_row = Mock(return_value='selected')
        menu = Mock()
        items = []
        menu.add_command.side_effect = lambda **kwargs: items.append(kwargs['label'])
        menu.add_separator.side_effect = lambda: items.append('|')
        a._context_menu = Mock(return_value=menu)
        a.show_rules_menu(types.SimpleNamespace(x_root=1, y_root=1))
        edit = items.index('Edit App Rule')
        remove = items.index('Remove Rule')
        self.assertEqual(items[edit - 1], '|')
        self.assertEqual(items[remove + 1], '|')
        self.assertEqual(items[-4:], ['Copy IP Domain', 'Copy details', 'Rule details', 'Open file location'])

    def test_rule_details_and_copy_share_the_same_full_text(self):
        a = app()
        tree = Mock()
        values = ('Global Allow', 'Global IP Allow', 'Both', '1.00 MB', '2.00 MB', 'example.test (192.0.2.1)')
        a.selected_rows = Mock(return_value=[('global:allow:example.test', values)])
        a.global_allows['example.test'] = {'addresses': ['192.0.2.1'], 'direction': 'Both'}
        a._show_details_dialog = Mock()
        a.show_rule_details(tree)
        text = a._show_details_dialog.call_args.args[1]
        actions = a._show_details_dialog.call_args.kwargs['actions']
        self.assertEqual(actions[0][0], 'Copy Info')
        actions[0][1]()
        a.root.clipboard_append.assert_called_once_with(text)
        a.root.clipboard_clear.reset_mock()
        a.root.clipboard_append.reset_mock()
        a.copy_rule_details(tree)
        a.root.clipboard_append.assert_called_once_with(text)

    def test_global_port_rows_use_global_status_labels(self):
        a = app()
        a.global_ports = a._parse_port_rules([port(action='Allow'), port(number=80, action='Block')])
        rows = a._make_rule_rows({}, set(), {}, {})
        self.assertEqual({row['status'] for row in rows}, {'Allowed (Global)', 'Blocked (Global)'})

    def test_details_include_overridden_and_combined_global_rules(self):
        a = app()
        row = connection(name='demo', pid=1, domain='example.test', direction='Incoming')
        norm = NS['normalize_path'](row['exe'])
        a.blocked_paths[norm] = {'in': True, 'out': True, 'path': row['exe']}
        a.global_allows['example.test'] = {'addresses': ['192.0.2.1'], 'direction': 'Both'}
        a.global_blocks['192.0.2.0/24'] = {'direction': 'Inbound'}
        a.global_ports = a._parse_port_rules([
            port(), dict(port('local', 51000, 'Block'), protocol='TCP'),
            dict(port(number=None), target='example.test', addresses=['192.0.2.1']),
            dict(port(number=443), target='192.0.2.1', protocol='TCP', direction='Inbound'),
            dict(port(number=443), protocol='UDP'), port(number=80),
            dict(port(), target='198.51.100.1'),
        ])
        a.active_connections = {'selected': row}
        a.proc_traffic = {}
        a.selected_connection_data = Mock(return_value=[row])
        a._show_details_dialog = Mock()
        a.show_connection_details(object())
        text = a._show_details_dialog.call_args.args[1]
        rules = a._connection_rule_descriptions(row)
        self.assertEqual(len(rules), 7)
        self.assertIn('Displayed Status: Blocked', text)
        for expected in ('App Rule: Block', 'Global Rule: Allow | Target: example.test',
                         'Global Rule: Block | Target: 192.0.2.0/24', 'Remote Port: 443',
                         'Local Port: 51000', 'Ports: Any', 'Protocol: TCP',
                         'Direction: Inbound', 'Addresses: 192.0.2.1'):
            self.assertIn(expected, text)
        self.assertNotIn('198.51.100.1', text)
        self.assertNotIn('Remote Port: 80', text)
        self.assertNotIn('Protocol: UDP', text)
        a.auto_prompt_keys.add(norm)
        self.assertTrue(any('Auto-Block: Temporary Block' in rule for rule in a._connection_rule_descriptions(row)))

    def test_double_click_routes_each_view_and_header_stays_autosize(self):
        a = app()
        a._autosize_header = Mock(return_value=False)
        a._remember_selection_anchor = Mock()
        origins = []
        a.edit_connection_rule = Mock(side_effect=lambda *_: origins.append(a._dialog_origin))
        a.edit_selected_managed_rule = Mock(side_effect=lambda *_: origins.append(a._dialog_origin))
        row = connection()
        a.selected_connection_data = Mock(return_value=[row])
        a.alert_connection_row = Mock(return_value=row)
        event = types.SimpleNamespace(y=1, x_root=211, y_root=133)
        for _ in range(2):
            tree = Mock()
            tree.identify_row.return_value = 'selected'
            a.tree_details_from_event(event, tree)
        a.alerts_tree = Mock()
        a.alert_details_from_event(event)
        self.assertEqual(a.edit_connection_rule.call_count, 3)
        a.rules_tree = Mock()
        a.rules_tree.identify_row.return_value = 'rule'
        a.rule_details_from_event(event)
        a.edit_selected_managed_rule.assert_called_once_with('rule')
        self.assertEqual(origins, [(211, 133)] * 4)
        self.assertIsNone(a._dialog_origin)
        a._autosize_header.return_value = True
        a.tree_details_from_event(event, tree)
        self.assertEqual(a.edit_connection_rule.call_count, 3)

    def test_success_and_duplicates_are_silent_but_no_selection_is_reported(self):
        a = app()
        MemoryFirewall(a)
        a._apply_rule_batch([], port_updates=[port()], report=True)
        a._show_rule_result.assert_not_called()
        a._apply_rule_batch([], port_updates=[port()], report=True)
        a._show_rule_result.assert_not_called()
        a._apply_rule_batch([], report=True)
        self.assertIn('No rules were changed', a._show_rule_result.call_args.args[1])

    def test_alert_and_managed_menus_highlight_current_global_rule(self):
        for section in ('alerts', 'managed'):
            a = app()
            a.colors = {'fg': '#e8e8e8', 'global_allow': '#17665f'}
            a.global_ports = a._parse_port_rules([port()])
            a._focus_menu_row = Mock(return_value='selected')
            a._show_header_menu = Mock(return_value=False)
            menu = Mock()
            a._context_menu = Mock(return_value=menu)
            event = types.SimpleNamespace(x_root=1, y_root=1)
            if section == 'alerts':
                a.alerts_tree = Mock()
                a.alert_connection_row = Mock(return_value=connection())
                a.selected_rows = Mock(return_value=[('selected', ())])
                a.show_alert_menu(event)
            else:
                a.rules_tree = Mock()
                a.rules_tree.item.return_value = ('Global Port Allow', '', 'Both', '', '', 'remote:443')
                a.show_rules_menu(event)
            entries = {c.kwargs['label']: c.kwargs for c in menu.add_command.call_args_list}
            self.assertEqual(entries['Allow Connection']['foreground'], '#ffffff')
            self.assertEqual(entries['Allow Connection']['background'], '#135650')
            self.assertNotIn('background', entries['Block Connection'])


class ContextRuleEditorTests(unittest.TestCase):
    def menu_for(self, a, section, row, rule_key=None):
        a.colors = {'fg': '#e8e8e8', 'muted': '#a8a8a8'}
        a._show_header_menu = Mock(return_value=False)
        a._focus_menu_row = Mock(return_value='selected')
        menu = Mock()
        a._context_menu = Mock(return_value=menu)
        event = types.SimpleNamespace(x_root=1, y_root=1)
        if section == 'live':
            a.selected_connection_data = Mock(return_value=[row])
            a.show_connection_menu(event, object())
        elif section == 'alerts':
            a.alerts_tree = Mock()
            a.alert_connection_row = Mock(return_value=row)
            a.selected_rows = Mock(return_value=[('selected', ())])
            a.show_alert_menu(event)
        else:
            a.rules_tree = Mock()
            a.rule_rows = a._make_rule_rows(a.blocked_paths, a.allowed_apps, a.global_blocks, a.global_allows)
            rule_row = next(r for r in a.rule_rows if r['normalized_path'] == rule_key)
            rule_row['iid'] = 'selected'
            values = (rule_row['status'], rule_row['rule'], rule_row['direction'], '', '', rule_row['path'])
            a.rules_tree.item.return_value = values
            a.selected_rows = Mock(return_value=[('selected', values)])
            a.show_rules_menu(event)
        return {c.kwargs['label']: c.kwargs for c in menu.add_command.call_args_list}

    def test_existing_global_actions_and_edit_preserve_all_fields_across_views(self):
        for section in ('live', 'alerts', 'managed'):
            with self.subTest(section=section):
                a = app()
                entry = dict(port('local', 53, 'Block'), protocol='UDP', target='example.test',
                             addresses=['192.0.2.1'], direction='Inbound')
                a.global_ports = a._parse_port_rules([entry])
                key = next(iter(a.global_ports))
                a.add_global_rule_dialog = Mock()
                a._apply_rule_batch = Mock()
                row = connection(lport=53, protocol='UDP', direction='Incoming')
                # Even an app block must not hide the independent global edit command.
                a.blocked_paths[NS['normalize_path'](row['exe'])] = {'path': row['exe'], 'in': True, 'out': True}
                a.edit_app_rule = Mock()
                menu = self.menu_for(a, section, row, key)
                actions = [('Allow Connection', 'Allow'), ('Block Connection', 'Block'),
                           ('Block Incoming', 'Block Incoming')]
                if section == 'managed':
                    actions.append(('Edit Global Rule', 'Block Incoming'))
                for label, action in actions:
                    menu[label]['command']()
                    initial, old = a.add_global_rule_dialog.call_args.args
                    expected = dict(entry, action=action, editing=True)
                    if section != 'managed' and label != 'Edit Global Rule':
                        expected['target'] = row['dst_ip']
                    self.assertEqual(initial, expected)
                    self.assertEqual(old, ('port', key))
                labels = list(menu)
                remove_label = 'Remove Rule' if section == 'managed' else 'Remove Global Rule'
                self.assertEqual(menu[remove_label]['foreground'], '#a8a8a8')
                if section == 'managed':
                    self.assertEqual(menu['Edit Global Rule']['foreground'], '#a8a8a8')
                    self.assertLess(labels.index('Edit Global Rule'), labels.index(remove_label))
                else:
                    self.assertLess(labels.index('Remove App Rule'), labels.index('Remove Global Rule'))
                a._apply_rule_batch.assert_not_called()

    def test_new_context_actions_prefill_drafts_and_cancel_without_writes(self):
        for section in ('live', 'alerts'):
            a = app()
            row = connection(domain='example.test')
            a._ask_global_rule_fields = Mock(return_value=None)
            a._apply_rule_batch = Mock()
            a.resolve_global_target = Mock()
            menu = self.menu_for(a, section, row)
            menu['Block Incoming']['command']()
            initial = a._ask_global_rule_fields.call_args.args[0]
            self.assertEqual(initial['target'], 'example.test')
            self.assertEqual(initial['action'], 'Block Incoming')
            self.assertEqual(initial['protocol'], 'TCP')
            self.assertEqual(initial['port'], 443)
            self.assertEqual(initial['scope'], 'remote')
            self.assertEqual(initial['addresses'], ['192.0.2.1'])
            self.assertFalse(any('Port (Global)' in label for label in menu))
            menu['Allow Connection']['command']()
            initial = a._ask_global_rule_fields.call_args.args[0]
            self.assertEqual(initial['port'], 443)
            self.assertEqual(initial['target'], 'example.test')
            self.assertEqual(initial['action'], 'Allow')
            a.resolve_global_target.assert_not_called()
            a._apply_rule_batch.assert_not_called()

    def test_managed_app_and_legacy_global_edit_commands(self):
        a = app()
        row = connection()
        key = NS['normalize_path'](row['exe'])
        a.allowed_apps.add(key)
        a.edit_app_rule = Mock()
        menu = self.menu_for(a, 'managed', row, key)
        menu['Edit App Rule']['command']()
        a.edit_app_rule.assert_called_once()
        a.global_blocks['example.test'] = {'addresses': ['192.0.2.1'], 'direction': 'Inbound'}
        a.add_global_rule_dialog = Mock()
        menu = self.menu_for(a, 'managed', row, 'example.test')
        menu['Allow Connection']['command']()
        initial, old = a.add_global_rule_dialog.call_args.args
        self.assertEqual(initial['action'], 'Allow')
        self.assertEqual(initial['target'], 'example.test')
        self.assertEqual(initial['addresses'], ['192.0.2.1'])
        self.assertEqual(old, ('block', 'example.test'))

    def test_duplicate_connections_open_each_saved_rule_once(self):
        a = app()
        a.global_ports = a._parse_port_rules([port()])
        a.add_global_rule_dialog = Mock()
        a.prompt_connection_globals([connection(), connection()], False, 'in')
        a.add_global_rule_dialog.assert_called_once()

    def test_successful_updates_and_removals_are_silent_but_errors_are_visible(self):
        a = app()
        backend = MemoryFirewall(a)
        with patch.object(NS['messagebox'], 'showinfo') as info, \
             patch.object(NS['messagebox'], 'showwarning') as warning, \
             patch.object(NS['messagebox'], 'showerror') as error, \
             patch_dependencies(log_internal_error=Mock()):
            self.assertTrue(a._apply_rule_batch([], port_updates=[port()], report=True))
            self.assertTrue(a._apply_rule_batch([], port_updates=[port()], report=True))
            self.assertTrue(a._remove_rules_with_feedback([('Global Port Allow', 'remote:443')]))
            info.assert_not_called()
            warning.assert_not_called()
            error.assert_not_called()
            a._show_rule_result.assert_not_called()
            backend.fail_once = True
            self.assertFalse(a._apply_rule_batch([], port_updates=[port()]))
            error.assert_called_once()
            error.reset_mock()
            a.get_firewall_rules.side_effect = RuntimeError('Access denied')
            self.assertFalse(a._remove_rules_with_feedback([('Global Port Allow', 'remote:443')]))
            self.assertIn('Access denied', error.call_args.args[1])

    def test_settings_write_failure_is_reported_for_updates_and_removals(self):
        for remove in (False, True):
            a = app()
            MemoryFirewall(a)
            a._commit_rule_batch([], port_updates=[port()])
            a.save_settings.return_value = False
            a.settings_save_error = 'Disk full'
            with patch.object(NS['messagebox'], 'showerror') as error, patch_dependencies(log_internal_error=Mock()):
                if remove:
                    result = a._remove_rules_with_feedback([('Global Port Allow', 'remote:443')])
                else:
                    result = a._apply_rule_batch([], port_updates=[port(action='Block')])
            self.assertFalse(result)
            self.assertIn('could not be saved', error.call_args.args[1])
            self.assertIn('Disk full', error.call_args.args[1])
            a.rules_changed.assert_called_once()

    def test_retry_after_settings_failure_does_not_silently_skip_saving(self):
        a = app()
        MemoryFirewall(a)
        a._commit_rule_batch([], port_updates=[port()])
        a.settings_save_error = 'Disk full'
        a.save_settings.return_value = False
        with patch.object(NS['messagebox'], 'showerror') as error, patch_dependencies(log_internal_error=Mock()):
            self.assertFalse(a._apply_rule_batch([], port_updates=[port()]))
        a.save_settings.assert_called_once()
        self.assertIn('Disk full', error.call_args.args[1])
        a._show_rule_result.assert_not_called()


class RealWidgetTests(unittest.TestCase):
    def setUp(self):
        self.root = NS['tk'].Tk()
        self.root.withdraw()
        self.a = app()
        self.a.root = self.root
        self.a.colors = {'frame': '#1e1e1e', 'fg': '#e8e8e8', 'button': '#757575',
                         'head': '#2d2d30', 'sub': '#242424', 'select': '#3b78c8', 'allowed': '#294f31'}
        self.a._theme_dialog = lambda dialog: dialog.attributes('-alpha', 0)

    def tearDown(self):
        self.root.destroy()

    @staticmethod
    def descendants(parent):
        return [child for widget in parent.winfo_children() for child in [widget, *RealWidgetTests.descendants(widget)]]

    def test_manual_editors_share_one_slot_and_release_on_close(self):
        a = self.a
        openers = [
            lambda: a._choose_option('Create Rule', 'Choose', [('App Rule', 'app', '#4CAF50')]),
            lambda: a._choose_option('App Rule', 'Choose', [('Allow', 'allow', '#4CAF50')]),
            lambda: a._ask_global_rule_fields(),
            lambda: a._ask_global_rule_fields({'editing': True}),
        ]
        errors = []

        def inspect():
            dialog = a.rule_editor_dialog
            try:
                # Destroying an editor child must not release the editor itself.
                child = NS['tk'].Frame(dialog)
                child.destroy()
                self.assertIs(a.rule_editor_dialog, dialog)
                with patch.object(NS['tk'], 'Toplevel', side_effect=AssertionError('Second editor created')), \
                     patch.object(NS['filedialog'], 'askopenfilename') as picker:
                    for open_editor in openers:
                        self.assertIsNone(open_editor())
                    a.add_custom_rule()
                    picker.assert_not_called()
                self.assertIs(a.rule_editor_dialog, dialog)
                self.assertIsNone(dialog.grab_current())
            except Exception as exc:
                errors.append(exc)
            finally:
                dialog.destroy()

        for open_editor in openers:
            self.root.after(20, inspect)
            self.assertIsNone(open_editor())
            if errors:
                raise errors[0]
            self.assertIsNone(a.rule_editor_dialog)

    def test_auto_block_decision_works_while_manual_editor_stays_open(self):
        a = self.a
        a.rules_generation = 0
        errors = []
        completed = []

        def worker(*args):
            args[-1].put(True)

        def check_decision():
            try:
                self.assertIsNone(a.auto_prompt_dialog)
                self.assertTrue(a.rule_editor_dialog.winfo_exists())
                completed.append(True)
            except Exception as exc:
                errors.append(exc)
            finally:
                a.rule_editor_dialog.destroy()

        def interact():
            try:
                editor = a.rule_editor_dialog
                a.show_auto_prompt(0, 'demo', 'demo', 'C:\\demo.exe', 12, '192.0.2.1', 'connection', '')
                prompt = a.auto_prompt_dialog
                self.assertIs(a.rule_editor_dialog, editor)
                self.assertIsNone(prompt.grab_current())
                self.assertTrue(prompt.attributes('-topmost'))
                self.assertIsNone(a._ask_global_rule_fields())
                button = next(w for w in self.descendants(prompt)
                              if isinstance(w, NS['tk'].Button) and w.cget('text') == 'Allow All')
                self.root.after(300, button.invoke)
                self.root.after(450, check_decision)
            except Exception as exc:
                errors.append(exc)
                a.rule_editor_dialog.destroy()

        with patch.object(a, '_auto_decision_worker', side_effect=worker) as decision:
            self.root.after(20, interact)
            a._ask_global_rule_fields()
        if errors:
            raise errors[0]
        self.assertEqual(completed, [True])
        self.assertEqual(decision.call_args.args[4], 'allow')
        self.assertIsNone(a.rule_editor_dialog)

    def test_edit_dialog_prefills_all_fields(self):
        initial = {'editing': True, 'action': 'Block Incoming', 'target': 'example.test',
                   'port': 53, 'scope': 'local', 'protocol': 'UDP'}
        observed = {}
        def inspect():
            dialog = next(w for w in self.root.winfo_children() if isinstance(w, NS['tk'].Toplevel))
            widgets = self.descendants(dialog)
            observed['combos'] = [w.get() for w in widgets if isinstance(w, NS['ttk'].Combobox)]
            observed['entries'] = [w.get() for w in widgets if isinstance(w, NS['ttk'].Entry) and not isinstance(w, NS['ttk'].Combobox)]
            labels = {w.cget('text'): w for w in widgets if isinstance(w, NS['ttk'].Label)}
            combos = [w for w in widgets if isinstance(w, NS['ttk'].Combobox)]
            entries = [w for w in widgets if isinstance(w, NS['ttk'].Entry) and not isinstance(w, NS['ttk'].Combobox)]
            observed['aligned_label'] = labels['Port Number:'].winfo_rootx() == labels['Action:'].winfo_rootx()
            observed['aligned_input'] = entries[0].winfo_rootx() == entries[1].winfo_rootx()
            observed['aligned_right'] = len({w.winfo_rootx() + w.winfo_width() for w in combos + entries[:1]}) == 1
            observed['range_between'] = (entries[1].winfo_rootx() + entries[1].winfo_width()
                                         <= labels['(1-65535)'].winfo_rootx()
                                         < combos[1].winfo_rootx())
            next(w for w in widgets if isinstance(w, NS['ttk'].Button) and w.cget('text') == 'Save').invoke()
        self.root.after(20, inspect)
        result = self.a._ask_global_rule_fields(initial)
        self.assertEqual(observed['combos'], ['Block Incoming', 'Local', 'UDP'])
        self.assertEqual(observed['entries'], ['example.test', '53'])
        self.assertEqual(result, ('example.test', 53, 'local', 'UDP', 'Block Incoming'))
        for key in ('aligned_label', 'aligned_input', 'aligned_right', 'range_between'):
            self.assertTrue(observed[key], key)

    def test_details_buttons_share_style_and_hover_restores_background(self):
        self.root.attributes('-alpha', 0)
        self.root.deiconify()
        self.root.update()
        callbacks = [Mock(), Mock()]
        actions = tuple(zip(('Copy Info', 'Open File Location'), callbacks, (None, None)))
        self.a._show_details_dialog('Connection details', 'Connection info', 'Close', actions=actions)
        dialog = next(w for w in self.root.winfo_children() if isinstance(w, NS['tk'].Toplevel))
        self.root.update()
        buttons = {w.cget('text'): w for w in self.descendants(dialog) if isinstance(w, NS['tk'].Button)}
        self.assertEqual(set(buttons), {'Copy Info', 'Open File Location', 'Close'})
        close = buttons['Close']
        for name, button in buttons.items():
            for option in ('font', 'padx', 'pady', 'relief'):
                self.assertEqual(button.cget(option), close.cget(option))
            source = '#757575'
            self.assertEqual(button._pyfirewall_source_bg, source)
            expected = button._pyfirewall_base_bg
            self.assertEqual(button.cget('bg'), expected)
            button.event_generate('<Enter>')
            self.assertNotEqual(button.cget('bg'), expected)
            button.event_generate('<Leave>')
            self.assertEqual(button.cget('bg'), expected)
        buttons['Copy Info'].invoke()
        callbacks[0].assert_called_once()
        self.assertTrue(dialog.winfo_exists())
        buttons['Close'].invoke()
        self.assertFalse(dialog.winfo_exists())

    def test_menu_highlight_survives_pointer_and_keyboard_movement(self):
        menu = self.a._context_menu()
        menu.rule_tag = 'allowed'
        self.a._menu_rule_command(menu, 'Allow Process', Mock(), 'allowed')
        self.a._menu_rule_command(menu, 'Block Process', Mock(), 'blocked')
        selected = menu.items[0][0]
        base = selected.cget('bg')
        menu._select(0)
        self.assertNotEqual(selected.cget('bg'), base)
        menu._move(1)
        self.assertEqual(selected.cget('bg'), base)
        self.assertEqual(selected.cget('fg'), '#ffffff')
        menu._close()

    def test_light_theme_current_rule_text_stays_readable_on_hover(self):
        self.a.dark_mode = False
        self.a.colors['allowed'] = '#cce8d2'
        menu = self.a._context_menu()
        menu.rule_tag = 'allowed'
        self.a._menu_rule_command(menu, 'Allow Process', Mock(), 'allowed')
        self.a._menu_rule_command(menu, 'Block Process', Mock(), 'blocked')
        selected = menu.items[0][0]
        self.assertEqual(selected.cget('fg'), '#000000')
        menu._select(0)
        self.assertEqual(selected.cget('fg'), '#000000')
        menu._move(1)
        self.assertEqual(selected.cget('fg'), '#000000')
        menu._close()

    def test_menus_fit_work_area_on_each_edge_and_negative_monitor(self):
        for area, point in (((0, 0, 1920, 1032), (1900, 1070)),
                            ((48, 0, 1920, 1080), (0, 40)),
                            ((0, 48, 1920, 1080), (20, 0)),
                            ((0, 0, 1872, 1080), (1910, 200)),
                            ((-1920, 0, 0, 1032), (-10, 1060))):
            with self.subTest(area=area), patch_dependencies(screen_work_area=Mock(return_value=area)):
                menu = self.a._context_menu()
                for index in range(10):
                    menu.add_command(label=f'Action {index}', command=Mock())
                menu.post(*point)
                menu.window.update_idletasks()
                x, y = menu.window.winfo_x(), menu.window.winfo_y()
                self.assertGreaterEqual(x, area[0])
                self.assertGreaterEqual(y, area[1])
                self.assertLessEqual(x + menu.window.winfo_width(), area[2])
                self.assertLessEqual(y + menu.window.winfo_height(), area[3])
                self.assertEqual(menu.origin, point)
                menu._close()

    def test_rule_dialog_sequence_keeps_initial_context_menu_position(self):
        a = self.a
        self.root.attributes('-alpha', 0)
        self.root.deiconify()
        self.root.update()
        a._apply_rule_batch = Mock()
        observed, errors = [], []

        def inspect():
            dialog = a.rule_editor_dialog
            try:
                observed.append((dialog.title(), dialog.winfo_x(), dialog.winfo_y()))
                self.assertEqual((dialog.winfo_x(), dialog.winfo_y()), (300, 180))
                widgets = self.descendants(dialog)
                if dialog.title() == 'Create Rule':
                    self.root.after(20, inspect)
                    next(w for w in widgets if isinstance(w, NS['tk'].Button)
                         and w.cget('text') == 'Global Rule').invoke()
                else:
                    next(w for w in widgets if isinstance(w, NS['ttk'].Button)
                         and w.cget('text') == 'Cancel').invoke()
            except Exception as exc:
                errors.append(exc)
                dialog.destroy()

        with patch_dependencies(screen_work_area=Mock(return_value=(0, 0, 1920, 1032))), \
             patch.object(self.root, 'winfo_pointerxy', return_value=(900, 800)):
            menu = a._context_menu()
            menu.add_command(label='Create Rule', command=lambda: a.edit_connection_rule(connection()))
            menu.post(300, 180)
            self.root.after(20, inspect)
            menu._invoke(index=0)
        if errors:
            raise errors[0]
        self.assertEqual([item[0] for item in observed], ['Create Rule', 'Add Global Rule'])
        self.assertIsNone(a._dialog_origin)
        a._apply_rule_batch.assert_not_called()

    def test_long_details_are_scrollable_and_stay_above_taskbar(self):
        self.root.attributes('-alpha', 0)
        self.root.deiconify()
        self.root.update()
        text = '\n'.join(f'Rule {index}: Allow' for index in range(100))
        self.a._dialog_origin = (1900, 1060)
        with patch_dependencies(screen_work_area=Mock(return_value=(0, 0, 1920, 1032))):
            self.a._show_details_dialog('Connection details', text, 'Close')
        dialog = next(w for w in self.root.winfo_children() if isinstance(w, NS['tk'].Toplevel))
        dialog.update_idletasks()
        contents = next(w for w in self.descendants(dialog) if isinstance(w, NS['tk'].Text))
        self.assertEqual(contents.get('1.0', 'end-1c'), text)
        self.assertLess(contents.yview()[1], 1)
        self.assertLessEqual(dialog.winfo_rooty() + dialog.winfo_height(), 1032)
        self.assertLessEqual(dialog.winfo_rootx() + dialog.winfo_width(), 1920)
        self.assertGreaterEqual(dialog.winfo_y(), 0)

    def test_details_expand_for_wrapped_text_when_the_monitor_has_room(self):
        self.root.attributes('-alpha', 0)
        self.root.deiconify()
        self.root.update()
        text = 'A long detail line. ' * 90
        with patch_dependencies(screen_work_area=Mock(return_value=(0, 0, 1920, 1400))):
            self.a._show_details_dialog('Connection details', text, 'Close')
        dialog = next(w for w in self.root.winfo_children() if isinstance(w, NS['tk'].Toplevel))
        dialog.update_idletasks()
        contents = next(w for w in self.descendants(dialog) if isinstance(w, NS['tk'].Text))
        self.assertEqual(contents.yview()[1], 1)
        scrollbar = next(w for w in self.descendants(dialog) if isinstance(w, NS['ttk'].Scrollbar))
        self.assertFalse(scrollbar.winfo_ismapped())

    def test_work_area_uses_monitor_nearest_activation(self):
        def get_info(monitor, pointer):
            info = pointer._obj
            info.work.left, info.work.top = -1920, 0
            info.work.right, info.work.bottom = 0, 1032
            return True
        user32 = types.SimpleNamespace(MonitorFromPoint=Mock(return_value=123),
                                       GetMonitorInfoW=Mock(side_effect=get_info))
        with patch.object(NS['ctypes'], 'windll', types.SimpleNamespace(user32=user32)):
            self.assertEqual(NS['screen_work_area'](self.root, -10, 1070), (-1920, 0, 0, 1032))
        point, flag = user32.MonitorFromPoint.call_args.args
        self.assertEqual((point.x, point.y, flag), (-10, 1070, 2))


if __name__ == '__main__':
    unittest.main()
