"""Isolated policy/GUI checks: never elevate, sniff, or change Windows Firewall."""
import json
import pathlib
import re
import shutil
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
from support import patch_dependencies
from test_firewall_monitor import App, NS, app


class ColumnAndDialogTests(unittest.TestCase):
    def setUp(self):
        self.a = app()
        self.a.default_column_orders = App.DEFAULT_COLUMN_ORDERS
        self.a.column_orders = {k: list(v) for k, v in App.DEFAULT_COLUMN_ORDERS.items()}
        self.a.hidden_columns = {}
        self.a.root = Mock()

    def test_global_dialog_uses_selected_action_without_second_prompt(self):
        a = self.a
        a._apply_rule_batch = Mock()
        a.resolve_global_target = Mock(return_value=['192.0.2.1'])
        a._choose_option = Mock()
        for action in ('Allow', 'Block', 'Block Incoming', None):
            a._apply_rule_batch.reset_mock()
            a._ask_global_rule_fields = Mock(return_value=('example.test', None, 'remote', 'TCP/UDP', action) if action else None)
            a.add_global_rule_dialog()
            if action:
                entry = a._apply_rule_batch.call_args.kwargs['port_updates'][0]
                self.assertEqual(entry['action'], 'Allow' if action == 'Allow' else 'Block')
                self.assertEqual(entry.get('direction', 'Both'), 'Inbound' if action == 'Block Incoming' else 'Both')
                self.assertIsNone(entry['port'])
            else:
                a._apply_rule_batch.assert_not_called()
        a._choose_option.assert_not_called()

    def test_incoming_global_block_retains_yellow_and_direction(self):
        a = self.a
        a.global_blocks['2001:db8::1'] = {'direction': 'Inbound'}
        row = {'dst_ip': '2001:db8::1', 'direction': 'Incoming'}
        self.assertEqual(a.connection_tag(row), 'global_block_in')
        row['direction'] = 'Outgoing'
        self.assertEqual(a.connection_tag(row), 'even')

    def test_legacy_port_only_import_uses_native_port_rules(self):
        a = self.a
        a._apply_rule_batch = Mock()
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'old.json'
            path.write_text(json.dumps({'version': 5, 'global_port_rules': [
                {'scope': 'remote', 'port': 443, 'action': 'Allow'}]}))
            with patch.object(NS['filedialog'], 'askopenfilename', return_value=str(path)), \
                 patch.object(NS['messagebox'], 'showerror') as error, \
                 patch.object(NS['messagebox'], 'askyesno', return_value=True), patch.object(NS['messagebox'], 'showinfo'):
                a.import_rules()
            a._apply_rule_batch.assert_called_once_with([], quiet=True, port_updates=[{'scope': 'remote', 'port': 443, 'action': 'Allow'}])
            error.assert_not_called()

    def test_legacy_mixed_backup_imports_and_exports_only_supported_rules(self):
        a = self.a
        a._apply_rule_batch = Mock(return_value=True)
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'old.json'
            path.write_text(json.dumps({'version': 5, 'global_port_rules': [
                {'scope': 'local', 'port': 53, 'action': 'Block'}],
                'global_ip_blocks': [{'target': '192.0.2.1', 'direction': 'Inbound'}]}))
            with patch.object(NS['filedialog'], 'askopenfilename', return_value=str(path)), \
                 patch.object(NS['messagebox'], 'askyesno', return_value=True), patch.object(NS['messagebox'], 'showinfo'):
                a.import_rules()
            a._apply_rule_batch.assert_called_once_with([('192.0.2.1', False, 'Inbound', True)], quiet=True,
                                                       port_updates=[{'scope': 'local', 'port': 53, 'action': 'Block'}])
            with patch.object(NS['filedialog'], 'asksaveasfilename', return_value=str(path)), patch.object(NS['messagebox'], 'showinfo'):
                a.export_rules()
            saved = json.loads(path.read_text())
            self.assertEqual(saved['version'], 6)
            self.assertEqual(saved['global_port_rules'], [])

    def test_rule_batch_stays_bounded_to_requested_directions(self):
        a = self.a
        a.get_firewall_rules = Mock(return_value=[])
        a.delete_rule_names = Mock()
        a.run_ps = Mock()
        a._commit_rule_batch([('C:/demo.exe', False, 'both', False), ('192.0.2.1', False, 'both', True)])
        command = a.run_ps.call_args.args[0]
        match = re.search(r"\$rules=ConvertFrom-Json '((?:[^']|'')*)'", command)
        planned = json.loads(match.group(1).replace("''", "'"))
        self.assertEqual(len(planned), 4)
        self.assertEqual([r['direction'] for r in planned].count('Inbound'), 2)
        self.assertEqual([r['direction'] for r in planned].count('Outbound'), 2)
        self.assertTrue(all(not r.get('is_port') for r in planned))
        self.assertTrue(all('__P' not in r['name'] and '__Txn' not in r['name'] for r in planned))

    def test_defaults_and_row_values_match_monitor(self):
        expected = ('#', 'Process Name', 'Status', 'Direction', 'Remote IP', 'Remote Host', 'Protocol',
                    'Remote Port', 'Local Port', 'Download (MB)', 'Upload (MB)', 'Signal', 'PID', 'Exe Path')
        self.assertEqual(App.DEFAULT_COLUMN_ORDERS['monitor'], expected)
        row = dict(number=1, name='demo', pid=5, direction='Incoming', protocol='UDP', lport=53,
                   dst_ip='192.0.2.1', dport=50000, exe='C:\\demo.exe')
        mapping = dict(zip(expected, self.a.connection_values(row)))
        self.assertEqual(mapping['PID'], 5)
        self.assertEqual(mapping['Local Port'], 53)
        self.assertEqual(mapping['Remote IP'], '192.0.2.1')


    def test_hide_select_preserves_full_order_and_guards_last_column(self):
        class Tree(dict):
            _column_order_key = 'monitor'
        tree = Tree(columns=App.MONITOR_COLUMNS, displaycolumns=App.MONITOR_COLUMNS)
        self.a._hide_column(tree, 'PID')
        self.assertNotIn('PID', tree['displaycolumns'])
        self.assertIn('PID', self.a.column_orders['monitor'])
        self.assertEqual(self.a.hidden_columns['monitor'], ['PID'])
        self.a._set_visible_columns(tree, ['PID'])
        with patch.object(NS['messagebox'], 'showinfo') as info:
            self.a._hide_column(tree, 'PID')
        self.assertEqual(tree['displaycolumns'], ('PID',))
        info.assert_called_once()


class TkHeaderTests(unittest.TestCase):
    def test_settings_monitor_controls_match_header_and_fit_content(self):
        root = NS['tk'].Tk()
        root.attributes('-alpha', 0)
        def capture_tooltip(widget, text, **kwargs):
            widget._test_tooltip = text
        def large_work_area(action, param, rect, flags):
            rect._obj.left = rect._obj.top = 0
            rect._obj.right, rect._obj.bottom = 2600, 1800
            return True
        with tempfile.TemporaryDirectory() as directory:
            try:
                with patch_dependencies(CONFIG_FILE=str(pathlib.Path(directory) / 'config.json'), PyFirewallSystemTray=Mock(),
                                add_tooltip=capture_tooltip), \
                     patch.object(App, '_start_dns_workers'), \
                     patch.object(App, '_start_background_initialization'), patch.object(App, 'update_loop'), \
                     patch.object(App, '_queue_settings_change'), patch.object(App, 'release_auto_holds'), \
                     patch.object(App, 'render_all'), \
                     patch.object(NS['ctypes'].windll.user32, 'SystemParametersInfoW', side_effect=large_work_area):
                    a = App(root)
                    a.notebook.select(a.tab_settings)
                    a.capture_healthy = True
                    root.update()
                    pairs = ((a.btn_filter, a.settings_btn_filter), (a.btn_pause, a.settings_btn_pause))
                    def assert_matching():
                        a.update_filter_ui()
                        a.update_status()
                        root.update()
                        for original, duplicate in pairs:
                            for option in ('text', 'font', 'bg', 'fg', 'activebackground',
                                           'activeforeground', 'padx', 'pady', 'state'):
                                self.assertEqual(original.cget(option), duplicate.cget(option), option)
                            self.assertEqual(original.winfo_reqwidth(), duplicate.winfo_reqwidth())
                            self.assertEqual(original.winfo_reqheight(), duplicate.winfo_reqheight())
                            self.assertEqual(original._test_tooltip(), duplicate._test_tooltip())
                            original.event_generate('<Enter>')
                            duplicate.event_generate('<Enter>')
                            self.assertEqual(original.cget('bg'), duplicate.cget('bg'))
                            original.event_generate('<Leave>')
                            duplicate.event_generate('<Leave>')
                    assert_matching()
                    self.assertEqual(a.settings_canvas.yview(), (0.0, 1.0))
                    content = a.settings_canvas.winfo_children()[0]
                    auto_block = content.pack_slaves()[1]
                    for row, button in enumerate((a.settings_pause_border, a.settings_filter_border)):
                        x, _, width, _ = a.settings_monitor_controls.grid_bbox(0, row)
                        self.assertEqual(button.winfo_x() + button.winfo_width(), x + width)
                    self.assertLess(a.pause_border.winfo_rootx(), a.filter_border.winfo_rootx())
                    self.assertGreater(a.settings_filter_border.winfo_rooty(),
                                       a.settings_pause_border.winfo_rooty() + a.settings_pause_border.winfo_height())
                    self.assertLess(a.settings_filter_border.winfo_rooty(), auto_block.winfo_rooty())
                    self.assertEqual(a.settings_monitor_controls.cget('text'), 'Monitor & Filter')
                    descriptions = [a.settings_monitor_controls.grid_slaves(row=i, column=1)[0] for i in range(2)]
                    self.assertEqual(descriptions[0].winfo_rootx(), descriptions[1].winfo_rootx())
                    for row, button in enumerate((a.settings_pause_border, a.settings_filter_border)):
                        description = descriptions[row]
                        self.assertGreater(description.winfo_rootx(), button.winfo_rootx() + button.winfo_width())
                        self.assertAlmostEqual(description.winfo_rooty() + description.winfo_height() / 2,
                                               button.winfo_rooty() + button.winfo_height() / 2, delta=1)
                    management = content.pack_slaves()[3]
                    for row in range(1, 6):
                        button = management.grid_slaves(row=row, column=0)[0]
                        x, _, width, _ = management.grid_bbox(0, row)
                        self.assertEqual(button.winfo_x() + button.winfo_width(), x + width)
                    for dark in (False, True):
                        a.dark_mode_var.set(dark)
                        a.on_theme_changed()
                        a.settings_btn_filter.invoke()
                        assert_matching()
                        a.settings_btn_pause.invoke()
                        self.assertTrue(a.is_paused)
                        assert_matching()
                        self.assertEqual(a.settings_btn_filter.cget('state'), 'disabled')
                        a.btn_pause.invoke()
                        self.assertFalse(a.is_paused)
                        assert_matching()
                    a.capture_healthy = False
                    a.capture_error = 'Capture unavailable'
                    assert_matching()
                    self.assertIn('Resume', a.settings_btn_pause.cget('text'))
            finally:
                for callback in root.tk.call('after', 'info'):
                    root.after_cancel(callback)
                root.destroy()

    def test_full_gui_settings_order_roundtrip_and_reset(self):
        root = NS['tk'].Tk()
        root.withdraw()
        with tempfile.TemporaryDirectory() as directory:
            config = pathlib.Path(directory) / 'config.json'
            try:
                with patch_dependencies(CONFIG_FILE=str(config), PyFirewallSystemTray=Mock(), add_tooltip=Mock()), \
                     patch.object(App, '_start_dns_workers'), patch.object(App, '_fit_initial_window') as fit_window, \
                     patch.object(NS['messagebox'], 'showerror') as settings_errors, \
                     patch.object(App, '_start_background_initialization'), patch.object(App, 'update_loop'):
                    a = App(root)
                    content = a.settings_canvas.winfo_children()[0]
                    self.assertIs(content.pack_slaves()[0], a.settings_monitor_controls)
                    sections = [widget.cget('text') for widget in content.pack_slaves()]
                    self.assertEqual(sections, ['Monitor & Filter', 'Auto-Block Protection', 'Appearance',
                                                'Manage Updates / Rules / Settings', 'Support PyFirewall'])
                    management = content.pack_slaves()[3]
                    self.assertEqual(a.chk_updates.grid_info()['row'], 0)
                    self.assertEqual(a.btn_check_updates.grid_info()['row'], 1)
                    for row, expected in ((2, ['Export Rules']), (3, ['Import Rules']),
                                          (4, ['Reset to Defaults']), (5, ['Uninstall PyFirewall'])):
                        def button_texts(widget):
                            if isinstance(widget, NS['tk'].Button):
                                return [widget.cget('text')]
                            return [text for child in widget.winfo_children() for text in button_texts(child)]
                        self.assertEqual(button_texts(management.grid_slaves(row=row, column=0)[0]), expected)
                    self.assertTrue(a.check_updates_on_startup_var.get())
                    self.assertTrue(a.check_updates_on_startup)
                    a.chk_updates.invoke()
                    settings_errors.assert_not_called()
                    self.assertFalse(json.loads(config.read_text())['check_updates_on_startup'])
                    a.load_settings()
                    self.assertFalse(a.check_updates_on_startup)
                    self.assertFalse(a.check_updates_on_startup_var.get())
                    for legacy_value in (None, False, 'false', 1):
                        legacy_config = json.loads(config.read_text())
                        if legacy_value is None:
                            legacy_config.pop('check_updates_on_startup')
                        else:
                            legacy_config['check_updates_on_startup'] = legacy_value
                        config.write_text(json.dumps(legacy_config))
                        a.load_settings()
                        self.assertEqual(a.check_updates_on_startup, legacy_value is None)
                        self.assertEqual(a.check_updates_on_startup_var.get(), legacy_value is None)
                    a.chk_updates.invoke()
                    settings_errors.assert_not_called()
                    for tree in (a.tree,):
                        self.assertEqual(tuple(tree['displaycolumns']), App.MONITOR_COLUMNS)
                    a._hide_column(a.tree, 'PID')
                    self.assertTrue(a.save_settings())
                    legacy = json.loads(config.read_text())
                    legacy['global_port_rules'] = [{'scope': 'remote', 'port': 443, 'action': 'Allow'}]
                    config.write_text(json.dumps(legacy))
                    a.hidden_columns.clear()
                    a.load_settings()
                    self.assertTrue(a.check_updates_on_startup_var.get())
                    self.assertEqual(a.hidden_columns['monitor'], ['PID'])
                    self.assertEqual(a.global_ports, {'remote:443': {'scope': 'remote', 'port': 443, 'action': 'Allow'}})
                    self.assertTrue(a.save_settings())
                    self.assertEqual(json.loads(config.read_text())['global_port_rules'], legacy['global_port_rules'])
                    a.get_firewall_rules = Mock(return_value=[])
                    a._replace_rule_records = Mock()
                    a.refresh_rules = Mock()
                    a.chk_updates.invoke()
                    settings_errors.assert_not_called()
                    self.assertFalse(a.check_updates_on_startup)
                    a.dark_mode_var.set(False)
                    a.on_theme_changed()
                    for variable in (a.search_var, a.rule_search_var, a.alert_search_var):
                        variable.set('test filter')
                    with patch.object(NS['messagebox'], 'askyesno', return_value=True), \
                         patch.object(NS['messagebox'], 'showinfo'), patch.object(NS['messagebox'], 'showerror') as errors:
                        a.reset_to_defaults()
                    errors.assert_not_called()
                    self.assertEqual(fit_window.call_count, 2)  # Initial launch and reset.
                    self.assertFalse(a.hidden_columns)
                    self.assertEqual(tuple(a.tree['displaycolumns']), App.MONITOR_COLUMNS)
                    saved = json.loads(config.read_text())
                    self.assertTrue(a.check_updates_on_startup_var.get())
                    self.assertTrue(saved['check_updates_on_startup'])
                    self.assertTrue(saved['dark_mode'])
                    self.assertTrue(a.dark_mode_var.get())
                    for variable in (a.search_var, a.rule_search_var, a.alert_search_var):
                        self.assertEqual(variable.get(), '')
                    self.assertEqual(saved['global_port_rules'], [])
                    self.assertEqual(saved['column_orders']['monitor'], list(App.MONITOR_COLUMNS))
            finally:
                for callback in root.tk.call('after', 'info'):
                    root.after_cancel(callback)
                root.destroy()

    def test_real_trees_header_menu_autosize_and_visibility(self):
        tk, ttk = NS['tk'], NS['ttk']
        root = tk.Tk()
        root.attributes('-alpha', 0)
        root.geometry('900x350')
        a = app()
        a.root = root
        a.header_drag = {}
        a.default_column_orders = App.DEFAULT_COLUMN_ORDERS
        a.column_orders = {k: list(v) for k, v in App.DEFAULT_COLUMN_ORDERS.items()}
        a.hidden_columns = {}
        try:
            for key, columns in App.DEFAULT_COLUMN_ORDERS.items():
                frame = ttk.Frame(root)
                frame.pack(fill=tk.BOTH, expand=True)
                tree = a._make_tree(frame, columns, {}, key)
                tree.insert('', 'end', iid='row', values=['x' * 80] + ['value'] * (len(columns) - 1))
                root.update()
                regions = [(x, y) for y in range(1, 45) for x in range(1, tree.winfo_width())
                           if tree.identify_region(x, y) == 'separator']
                self.assertTrue(regions, key)
                x, y = regions[0]
                event = types.SimpleNamespace(x=x, y=y, x_root=x, y_root=y, widget=tree)
                column = a._tree_column_from_x(tree, x)
                self.assertEqual(column, columns[0])
                before = tree.column(column, 'width')
                self.assertTrue(a._autosize_header(event, tree))
                self.assertGreater(tree.column(column, 'width'), before)
                menu = Mock()
                a._context_menu = Mock(return_value=menu)
                a._show_header_menu(types.SimpleNamespace(x=30, y=y, x_root=30, y_root=y), tree)
                self.assertEqual([call.kwargs['label'] for call in menu.add_command.call_args_list], ['Hide Column', 'Select Columns'])
                a._hide_column(tree, column)
                self.assertNotIn(column, tree['displaycolumns'])
                a._set_visible_columns(tree, columns)
                self.assertEqual(tuple(tree['displaycolumns']), columns)
                frame.destroy()
        finally:
            root.destroy()


class PowerShellScriptTests(unittest.TestCase):

    @unittest.skipUnless(shutil.which('powershell'), 'Windows PowerShell required')
    def test_install_and_uninstall_scripts_parse_without_execution(self):
        script = r'''
$ErrorActionPreference='Stop'
$sources=@((Get-Content -LiteralPath 'requirements.ps1' -Raw))
$uninstall=Get-Content -LiteralPath 'Uninstall-PyFirewall.cmd' -Raw
$sources+=($uninstall -split '# POWERSHELL START\r?\n', 2)[1]
foreach ($source in $sources) {
    $parseErrors=$null; $tokens=$null
    [void][System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$parseErrors)
    if ($parseErrors.Count) { throw ($parseErrors.Message -join '; ') }
}
'''
        result = NS['subprocess'].run(['powershell', '-NoProfile', '-Command', script],
                                      capture_output=True, text=True, timeout=30,
                                      creationflags=NS['CREATE_NO_WINDOW'])
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
