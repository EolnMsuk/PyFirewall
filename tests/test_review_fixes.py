"""DNS, context-rule and real Tk regressions; no live firewall changes."""
import socket
import types
import unittest
from unittest.mock import Mock, patch

from support import patch_dependencies
from test_firewall_monitor import App, NS, app


class ProcessGlobalRuleTests(unittest.TestCase):
    def setUp(self):
        self.a = app()
        self.a.get_firewall_rules = Mock(return_value=[])
        self.a._replace_rule_records = Mock(side_effect=lambda old, names, create, **kw: create())
        self.a._create_rule_batch = Mock()
        self.a._invalidate_auto_prompts = Mock()
        self.a.selected_connection_data = Mock(return_value=[
            {'dst_ip': '34.104.35.123', 'domain': '123.35.104.34.bc.googleusercontent.com'},
            {'dst_ip': '34.104.35.123', 'domain': '123.35.104.34.bc.googleusercontent.com'}])
        self.host = '123.35.104.34.bc.googleusercontent.com'

    def test_unresolvable_ptr_falls_back_and_creates_one_labeled_incoming_rule(self):
        for failure in (socket.gaierror(11001, 'No such host'), ValueError('Invalid DNS result')):
            with self.subTest(failure=failure):
                self.a.global_blocks.clear()
                with patch.object(socket, 'getaddrinfo', side_effect=failure), \
                     patch.object(NS['messagebox'], 'askyesno', return_value=True), \
                     patch.object(NS['messagebox'], 'showerror') as error:
                    self.a.bulk_global(object(), False, direction='in')
                error.assert_not_called()
                rules = self.a._create_rule_batch.call_args.args[0]
                self.assertEqual(len(rules), 1)
                self.assertIn(self.host, rules[0]['name'])
                self.assertEqual(rules[0]['addresses'], ['34.104.35.123'])
                self.assertEqual(rules[0]['direction'], 'Inbound')
                self.assertEqual(list(self.a.global_blocks), [self.host])
                rows = self.a._make_rule_rows({}, set(), self.a.global_blocks, {})
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['path'], self.host + ' (34.104.35.123)')

    def test_resolved_ipv4_ipv6_and_observed_addresses_share_one_entry(self):
        resolved = [(socket.AF_INET, 1, 6, '', ('192.0.2.1', 0)),
                    (socket.AF_INET6, 1, 6, '', ('2001:db8::1', 0, 0, 0))]
        with patch.object(socket, 'getaddrinfo', return_value=resolved), \
             patch.object(NS['messagebox'], 'askyesno', return_value=True):
            self.a.bulk_global(object(), True)
        rules = self.a._create_rule_batch.call_args.args[0]
        # Windows needs one physical rule per direction, one logical managed entry.
        self.assertEqual(len(rules), 2)
        self.assertEqual({r['direction'] for r in rules}, {'Inbound', 'Outbound'})
        for rule in rules:
            self.assertEqual(set(rule['addresses']), {'34.104.35.123', '192.0.2.1', '2001:db8::1'})
        self.assertEqual(list(self.a.global_allows), [self.host])

    def test_new_observed_ip_updates_existing_rule_without_losing_previous_ip(self):
        self.a.global_blocks[self.host] = {'addresses': ('192.0.2.1',), 'direction': 'Inbound'}
        with patch.object(socket, 'getaddrinfo', side_effect=socket.gaierror('unresolvable')), \
             patch.object(NS['messagebox'], 'askyesno', return_value=True):
            self.a.bulk_global(object(), False, direction='in')
        self.assertEqual(set(self.a.global_blocks[self.host]['addresses']), {'34.104.35.123', '192.0.2.1'})
        self.a._create_rule_batch.reset_mock()
        with patch.object(NS['messagebox'], 'askyesno', return_value=True), \
             patch.object(NS['messagebox'], 'showwarning'):
            self.a.bulk_global(object(), False, direction='in')
        self.a._create_rule_batch.assert_not_called()

    def test_saved_ptr_rule_can_be_reapplied_without_dns(self):
        self.a.global_blocks[self.host] = {'addresses': ('34.104.35.123',), 'direction': 'Inbound'}
        with patch.object(socket, 'getaddrinfo', side_effect=socket.gaierror('unresolvable')):
            self.a._commit_rule_batch([(self.host, False, 'in', True)])
        self.assertEqual(self.a._create_rule_batch.call_args.args[0][0]['addresses'], ['34.104.35.123'])

    def test_ip_only_selection_is_covered_by_the_selected_domain_entry(self):
        self.a.selected_connection_data.return_value.append({'dst_ip': '34.104.35.123', 'domain': ''})
        with patch.object(socket, 'getaddrinfo', return_value=[]), \
             patch.object(NS['messagebox'], 'askyesno', return_value=True):
            self.a.bulk_global(object(), False, direction='in')
        self.assertEqual(len(self.a._create_rule_batch.call_args.args[0]), 1)
        self.assertEqual(list(self.a.global_blocks), [self.host])

    def test_manual_addition_keeps_original_identifier_and_resolved_addresses(self):
        addresses = ('192.0.2.1', '2001:db8::1')
        name = self.a.global_rule_base(self.host, True) + '_In'
        self.assertNotIn(self.host, name)
        self.a.run_netsh = Mock()
        self.a.get_firewall_rules.side_effect = [[], [
            {'name': name, 'action': 'Allow', 'direction': 'Inbound', 'addresses': addresses}]]
        with patch.object(self.a, 'resolve_global_target', return_value=addresses):
            self.assertEqual(self.a.add_global_rule_sync(self.host, True, 'in'), (self.host, addresses))
        self.a.run_netsh.assert_called_once_with([
            'add', 'rule', 'name=' + name, 'dir=in', 'action=allow',
            'remoteip=192.0.2.1,2001:db8::1', 'enable=yes'])

    def test_unresolvable_domain_without_ip_reports_error_before_any_mutation(self):
        self.a.selected_connection_data.return_value = [{'dst_ip': '', 'domain': self.host}]
        with patch.object(socket, 'getaddrinfo', side_effect=socket.gaierror('unresolvable')), \
             patch.object(NS['messagebox'], 'askyesno', return_value=True), \
             patch.object(NS['messagebox'], 'showerror') as error, patch_dependencies(log_internal_error=Mock()):
            self.a.bulk_global(object(), False)
        error.assert_called_once()
        self.a._replace_rule_records.assert_not_called()

    def test_empty_dns_answers_use_observed_ip_but_manual_entry_still_reports_error(self):
        with patch.object(socket, 'getaddrinfo', return_value=[]):
            self.assertEqual(self.a.resolve_global_target(self.host, ['192.0.2.1']), ('192.0.2.1',))
            with self.assertRaisesRegex(ValueError, 'DNS returned no addresses'):
                self.a.resolve_global_target(self.host)

    def test_hash_only_rules_are_recognized_and_replaced(self):
        digest = NS['hashlib'].sha1(self.host.encode()).hexdigest()[:12]
        old_name = NS['GLOBAL_BLOCK_PREFIX'] + digest + '_In'
        self.a.global_blocks[self.host] = {'addresses': ('192.0.2.1',), 'direction': 'Inbound'}
        self.a.get_firewall_rules.return_value = [
            {'name': old_name, 'is_global': True, 'is_hold': False, 'normalized_path': ''}]
        self.a.sync_rule_cache()
        self.assertIn(self.host, self.a.global_blocks)
        with patch.object(socket, 'getaddrinfo', return_value=[]):
            self.a._commit_rule_batch([(self.host, True, 'in', True)])
        previous = self.a._replace_rule_records.call_args.args[0]
        self.assertEqual([r['name'] for r in previous], [old_name])


class TreeAndPopupTests(unittest.TestCase):
    def setUp(self):
        self.root = NS['tk'].Tk()
        self.root.attributes('-alpha', 0)
        self.root.geometry('700x300')
        self.errors = []
        self.root.report_callback_exception = lambda *args: self.errors.append(args)
        self.a = app()
        self.a.root = self.root
        self.a.header_drag = {}
        self.a.default_column_orders = App.DEFAULT_COLUMN_ORDERS
        self.a.column_orders = {k: list(v) for k, v in App.DEFAULT_COLUMN_ORDERS.items()}
        self.a.hidden_columns = {}
        self.a.selection_anchors = {}

    def tearDown(self):
        self.root.destroy()
        self.assertEqual(self.errors, [])

    def test_drag_does_not_extend_selection_and_click_modifiers_still_work(self):
        for key, columns in App.DEFAULT_COLUMN_ORDERS.items():
            with self.subTest(tree=key):
                tree = self.a._make_tree(self.root, columns, {}, key)
                self.a._bind_tree_selection(tree)
                for i in range(4):
                    tree.insert('', 'end', iid=str(i), values=[str(i)] * len(columns))
                self.root.update()
                x = 20
                ys = [tree.bbox(str(i))[1] + 5 for i in range(4)]

                def click(y, state=0):
                    tree.event_generate('<Button-1>', x=x, y=y, state=state)
                    tree.event_generate('<ButtonRelease-1>', x=x, y=y, state=state)

                tree.event_generate('<Button-1>', x=x, y=ys[0])
                tree.event_generate('<B1-Motion>', x=x, y=ys[3], state=256)
                tree.event_generate('<ButtonRelease-1>', x=x, y=ys[3])
                self.assertEqual(tree.selection(), ('0',))
                click(ys[2], state=4)
                self.assertEqual(tree.selection(), ('0', '2'))
                click(ys[2], state=4)
                self.assertEqual(tree.selection(), ('0',))
                click(ys[0])
                click(ys[2], state=1)
                self.assertEqual(tree.selection(), ('0', '1', '2'))

                blank_y = ys[-1] + 35
                tree.event_generate('<Button-1>', x=x, y=blank_y)
                tree.event_generate('<B1-Motion>', x=x, y=ys[0], state=256)
                tree.event_generate('<ButtonRelease-1>', x=x, y=ys[0])
                self.assertEqual(tree.selection(), ())
                # The same motion event must still resize column separators.
                width = tree.column(columns[0], 'width')
                separator_x = next(px for px in range(width - 5, width + 6)
                                   if tree.identify_region(px, 10) == 'separator')
                tree.event_generate('<Button-1>', x=separator_x, y=10)
                tree.event_generate('<B1-Motion>', x=separator_x + 25, y=10, state=256)
                tree.event_generate('<ButtonRelease-1>', x=separator_x + 25, y=10)
                self.assertGreater(tree.column(columns[0], 'width'), width)
                tree.master.destroy() if tree.master is not self.root else tree.destroy()

    def test_all_trees_fill_last_visible_column_and_toggle_both_scrollbars(self):
        for key, columns in App.DEFAULT_COLUMN_ORDERS.items():
            with self.subTest(tree=key):
                frame = NS['ttk'].Frame(self.root)
                frame.pack(fill='both', expand=True)
                tree = self.a._make_tree(frame, columns, {c: (80, 'w', False) for c in columns}, key)
                self.a._set_visible_columns(tree, columns[:3])
                self.root.update()
                self.assertFalse(tree._horizontal_scrollbar.winfo_ismapped())
                self.assertFalse(tree._vertical_scrollbar.winfo_ismapped())
                self.assertAlmostEqual(sum(tree.column(c, 'width') for c in columns[:3]),
                                       tree.winfo_width() - 6, delta=2)
                # Shortening the last column still fills the viewport.
                tree.column(columns[2], width=35)
                self.root.update()
                self.assertGreater(tree.column(columns[2], 'width'), 400)
                # Hiding it restores its requested width and fills the new last column.
                self.a._hide_column(tree, columns[2])
                self.root.update()
                self.assertEqual(tree.column(columns[2], 'width'), 35)
                self.assertAlmostEqual(sum(tree.column(c, 'width') for c in columns[:2]),
                                       tree.winfo_width() - 6, delta=2)
                tree.column(columns[0], width=900)
                for i in range(100):
                    tree.insert('', 'end', iid=str(i), values=[str(i)] * len(columns))
                self.root.update()
                self.assertTrue(tree._horizontal_scrollbar.winfo_ismapped())
                self.assertTrue(tree._vertical_scrollbar.winfo_ismapped())
                tree.xview_moveto(1)
                tree.yview_moveto(1)
                tree.column(columns[0], width=80)
                tree.delete(*tree.get_children())
                self.root.update()
                self.assertFalse(tree._horizontal_scrollbar.winfo_ismapped())
                self.assertFalse(tree._vertical_scrollbar.winfo_ismapped())
                self.assertEqual(tree.xview(), (0.0, 1.0))
                frame.destroy()

    def test_hidden_columns_keep_slots_when_visible_headers_are_reordered(self):
        columns = App.MONITOR_COLUMNS
        tree = self.a._make_tree(self.root, columns, {}, 'monitor')
        hidden = columns[1]
        self.a._hide_column(tree, hidden)
        self.a.header_drag[str(tree)] = {'column': columns[0], 'dragging': True}
        self.a._tree_column_from_x = Mock(return_value=columns[3])
        self.a._tree_header_release(types.SimpleNamespace(widget=tree, x=30))
        self.assertEqual(self.a.column_orders['monitor'][1], hidden)
        saved = list(self.a.column_orders['monitor'])
        self.a._set_visible_columns(tree, columns)
        self.assertEqual(list(tree['displaycolumns']), saved)

    def test_clam_fill_fits_with_vertical_scrollbar_and_window_resizes(self):
        style = NS['ttk'].Style(self.root)
        style.theme_use('clam')
        columns = App.MONITOR_COLUMNS
        tree = self.a._make_tree(self.root, columns, {c: (70, 'w', False) for c in columns}, 'monitor')
        self.a._set_visible_columns(tree, columns[:3])
        for i in range(100):
            tree.insert('', 'end', values=[str(i)] * len(columns))
        for width in (700, 1100, 500, 900):
            self.root.geometry(f'{width}x300')
            self.root.update()
            self.assertTrue(tree._vertical_scrollbar.winfo_ismapped())
            self.assertFalse(tree._horizontal_scrollbar.winfo_ismapped())
            self.assertEqual(tree.xview(), (0.0, 1.0))
            self.assertLess(sum(tree.column(c, 'width') for c in columns[:3]), tree.winfo_width())
        tree.column(columns[0], width=1200)
        self.root.update()
        self.assertTrue(tree._horizontal_scrollbar.winfo_ismapped())

    def test_light_buttons_hover_theme_roundtrip_and_dynamic_state_colors(self):
        a = self.a
        a.dark_mode = False
        a.dark_mode_var = NS['tk'].BooleanVar(self.root, value=False)
        a.update_filter_ui = a.update_status = Mock()
        source_colors = ('#f44336', '#4CAF50', '#2196F3', NS['GLOBAL_PURPLE'], NS['GLOBAL_TEAL'], '#757575', '#9E9E9E')
        with patch_dependencies(add_tooltip=Mock()):
            buttons = [a._button(self.root, 'Action', Mock(), color) for color in source_colors]
        # Dialog buttons use the same helper even without a surrounding border.
        dialog_button = NS['tk'].Button(self.root, bg='#c62828', fg='white')
        a._bind_button_hover(dialog_button)
        dialog_button.pack()
        buttons.append(dialog_button)
        source_colors += ('#c62828',)
        self.root.update()
        light_colors = [button.cget('bg') for button in buttons]
        for button, source in zip(buttons, source_colors):
            self.assertNotEqual(button.cget('bg'), source)
            self.assertEqual(button.cget('fg'), '#000000')
            self.assertEqual(button.cget('activeforeground'), '#000000')
            self.assertTrue(all(channel >= 178 * 257 for channel in button.winfo_rgb(button.cget('bg'))))
            normal = button.cget('bg')
            button.event_generate('<Enter>')
            self.assertNotEqual(button.cget('bg'), normal)
            if button is not dialog_button:
                self.assertEqual(button.master.cget('bg'), '#555555')
            self.assertTrue(all(channel >= 165 * 257 for channel in button.winfo_rgb(button.cget('bg'))))
            button.event_generate('<Leave>')
            self.assertEqual(button.cget('bg'), normal)
            if button is not dialog_button:
                self.assertEqual(button.master.cget('bg'), '#555555')
        self.assertEqual(int(dialog_button.cget('highlightthickness')), 1)
        self.assertEqual(dialog_button.cget('highlightbackground'), '#555555')
        self.assertEqual(dialog_button.cget('highlightcolor'), '#555555')
        dark_colors = None
        for dark in (True, False, True, False):
            a.dark_mode_var.set(dark)
            a.apply_theme()
            if dark:
                actual = [b.cget('bg') for b in buttons]
                for button, source in zip(buttons, source_colors):
                    self.assertTrue(all(current < original for current, original in
                                        zip(button.winfo_rgb(button.cget('bg')), button.winfo_rgb(source))))
                if dark_colors is not None:
                    self.assertEqual(actual, dark_colors)
                dark_colors = actual
            else:
                self.assertEqual([b.cget('bg') for b in buttons], light_colors)
            for button in buttons:
                self.assertEqual(button.cget('fg'), '#ffffff' if dark else '#000000')
                self.assertEqual(button.cget('activeforeground'), '#ffffff' if dark else '#000000')
        a._set_button_colors(buttons[0], buttons[0].master, '#9E9E9E', state=NS['tk'].DISABLED)
        self.assertEqual(buttons[0].cget('state'), 'disabled')
        self.assertEqual(buttons[0].cget('fg'), '#000000')
        self.assertEqual(buttons[0].master.cget('bg'), '#555555')

    def test_context_menu_has_no_grab_and_does_not_swallow_outside_click(self):
        self.root.update()
        self.a.colors = {'head': '#333333', 'sub': '#222222', 'fg': 'white', 'select': '#555555'}
        for dark in (True, False):
            self.a.dark_mode = dark
            menu = self.a._context_menu()
            menu.add_command(label='Action', command=Mock())
            menu.post(10, 10)
            self.assertIsNone(self.root.grab_current())
            clicked = Mock()
            binding = self.root.bind('<ButtonPress-1>', clicked, add='+')
            self.root.event_generate('<ButtonPress-1>', x=5, y=5)
            clicked.assert_called_once()
            self.assertFalse(menu.window.winfo_exists())
            self.assertEqual(menu.root_bindings, [])
            self.root.unbind('<ButtonPress-1>', binding)

    def test_window_resize_and_withdraw_dismiss_popups(self):
        self.root.update()
        colors = {'head': '#333333', 'sub': '#222222', 'fg': 'white', 'select': '#555555'}
        for action in (lambda: self.root.geometry('800x400'), self.root.withdraw):
            menu = NS['ThemedContextMenu'](self.root, colors)
            menu.add_command(label='Action', command=Mock())
            menu.post(10, 10)
            action()
            self.root.update()
            self.assertFalse(menu.window.winfo_exists())
            self.assertEqual(menu.root_bindings, [])


if __name__ == '__main__':
    unittest.main()
