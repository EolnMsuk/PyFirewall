"""Connection drafts, foreground preference and saved window/table geometry."""
import csv
import json
import pathlib
import queue
import tempfile
import threading
import unittest
from collections import deque
from contextlib import ExitStack
from unittest.mock import Mock, patch

from support import App, NS, patch_dependencies
from fixtures import app, connection


class ConnectionDraftTests(unittest.TestCase):
    def test_protocol_and_port_distinguish_drafts(self):
        a = app()
        a.add_global_rule_dialog = Mock()
        rows = [connection(protocol='TCP'), connection(protocol='UDP'), connection(dport=8443)]
        a.prompt_connection_globals(rows + rows, False, 'in')
        drafts = [c.args[0] for c in a.add_global_rule_dialog.call_args_list]
        self.assertEqual({(d['port'], d['protocol']) for d in drafts}, {(443, 'TCP'), (443, 'UDP'), (8443, 'TCP')})
        self.assertTrue(all(d['action'] == 'Block Incoming' and d['scope'] == 'remote' for d in drafts))

    def test_alert_preserves_endpoint_after_connection_is_gone(self):
        a = app()
        a.alert_queue = queue.Queue()
        a.alerts = deque(maxlen=1)
        a.next_alert_id = 1
        a.render_alerts = Mock()
        row = connection(pid=12, domain='example.test', protocol='UDP', dport=53)
        App.queue_alert(a, 'High', 'demo', 12, row['dst_ip'], 'Threshold', connection=row)
        row['dport'] = 999
        a.drain_alerts()
        a.active_connections = {}
        values = ('', 'High', 'demo', 12, '192.0.2.1', 'example.test', 'Threshold')
        saved = a.alert_connection_row(values, 'alert_1')
        self.assertEqual(saved['dport'], 53)
        self.assertEqual(saved['protocol'], 'UDP')
        App.queue_alert(a, 'Info', '', '', '', 'Other')
        a.drain_alerts()
        self.assertEqual(a.alert_connections, {})


class PreferenceWidgetTests(unittest.TestCase):
    def test_shutdown_waits_for_native_cleanup_and_reports_unsaved_policy_on_tk(self):
        a = self.a
        entered, release = threading.Event(), threading.Event()
        a._start_native_worker()
        a._queue_native_job('Fake native transaction', lambda: entered.set() or release.wait(3))
        self.assertTrue(entered.wait(2))
        with patch.object(a, 'save_settings', return_value=False), \
             patch.object(NS['messagebox'], 'showerror') as error:
            try:
                for callback in self.root.tk.call('after', 'info'):
                    self.root.after_cancel(callback)
                a.on_closing()
                self.assertTrue(self.root.winfo_exists())
                heartbeat = []
                self.root.after_idle(lambda: heartbeat.append(True))
                self.root.update()
                self.assertEqual(heartbeat, [True])
            finally:
                release.set()
                a.native_worker.join(3)
            self.assertFalse(a.native_worker.is_alive())
            a._poll_shutdown()
            self.assertIn('unsaved changes', error.call_args.args[1])
            self.assertTrue(a.shutdown_finished)

    def test_apply_rejects_nonfinite_and_nonpositive_without_mutating_or_saving(self):
        a = self.a
        before = (a.rate_window, a.upload_threshold_mb, a.rate_threshold)
        with patch.object(NS['messagebox'], 'showerror') as error, patch.object(a, 'save_settings') as save:
            for field in (a.rate_window_var, a.upload_threshold_var):
                original = field.get()
                for value in ('nan', 'inf', '-inf', '1e309', '0', '-1'):
                    with self.subTest(value=value):
                        field.set(value)
                        self.assertFalse(a.apply_settings())
                        self.assertEqual((a.rate_window, a.upload_threshold_mb, a.rate_threshold), before)
                        save.assert_not_called()
                field.set(original)
            self.assertEqual(error.call_count, 12)
        a.rate_window_var.set('2.5')
        self.assertTrue(a.apply_settings())
        a._validate_settings(json.loads(self.config.read_text()))
        with patch.object(a, 'save_settings', return_value=False):
            self.assertFalse(a.apply_settings())
        self.assertEqual(a.ui_queue.get_nowait()[0], 'save_error')

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.config = pathlib.Path(directory) / 'settings.json'
        self.stack.enter_context(patch_dependencies(CONFIG_FILE=str(self.config), PyFirewallSystemTray=Mock()))
        for method in ('_start_dns_workers', '_start_background_initialization', 'update_loop', 'release_auto_holds'):
            self.stack.enter_context(patch.object(App, method))
        self.root = NS['tk'].Tk()
        self.root.attributes('-alpha', 0)
        self.addCleanup(self.destroy_root)
        self.a = App(self.root)
        self.root.update()

    def destroy_root(self):
        try:
            if self.root.winfo_exists():
                for callback in self.root.tk.call('after', 'info'):
                    self.root.after_cancel(callback)
                self.root.destroy()
        except NS['tk'].TclError:
            pass

    def test_close_hidden_window_roundtrips_all_table_widths_and_size(self):
        a = self.a
        for tree in (a.tree, a.rules_tree):
            self.assertEqual(tree.heading('Download (MB)', 'text'), 'Download')
            self.assertEqual(tree.heading('Upload (MB)', 'text'), 'Upload')
            def inspect_chooser(dialog):
                labels = [child.cget('text') for child in dialog.winfo_children()[0].winfo_children()
                          if isinstance(child, NS['ttk'].Checkbutton)]
                self.assertIn('Download', labels)
                self.assertIn('Upload', labels)
                self.assertNotIn('Upload (MB)', labels)
                dialog.destroy()
            with patch.object(self.root, 'wait_window', side_effect=inspect_chooser):
                a._select_columns(tree)
        a._hide_column(a.tree, 'Upload (MB)')
        self.root.geometry('1560x790+110+75')
        self.root.update()
        for tree in (a.tree, a.rules_tree, a.alerts_tree):
            tree.column(tree['columns'][0], width=237)
        a.tree.column('PID', width=149)
        a._hide_column(a.tree, 'PID')
        order = list(a.column_orders['monitor'])
        order[0], order[1] = order[1], order[0]
        a.column_orders['monitor'] = order
        a.tree['displaycolumns'] = tuple(c for c in order if c not in {'PID', 'Upload (MB)'})
        a.minimize_to_tray()
        for callback in self.root.tk.call('after', 'info'):
            self.root.after_cancel(callback)
        a.on_closing()
        saved = json.loads(self.config.read_text())
        self.assertEqual(saved['window_size'], [1560, 790])
        self.assertEqual(saved['window_position'], [110, 75])
        self.assertEqual(saved['column_widths']['monitor']['PID'], 149)
        for key, columns in a.DEFAULT_COLUMN_ORDERS.items():
            self.assertEqual(saved['column_widths'][key][columns[0]], 237)
        self.root = NS['tk'].Tk()
        self.root.attributes('-alpha', 0)
        restored = App(self.root)
        self.root.update()
        self.assertEqual((self.root.winfo_width(), self.root.winfo_height()), (1560, 790))
        self.assertEqual((self.root.winfo_x(), self.root.winfo_y()), (110, 75))
        self.assertEqual(restored.column_orders['monitor'], order)
        self.assertNotIn('PID', restored.tree['displaycolumns'])
        self.assertNotIn('Upload (MB)', restored.tree['displaycolumns'])
        self.assertEqual(restored.tree.heading('Upload (MB)', 'text'), 'Upload')
        self.assertEqual(restored.tree.column('PID', 'width'), 149)
        for tree in (restored.tree, restored.rules_tree, restored.alerts_tree):
            self.assertEqual(tree.column(tree['columns'][0], 'width'), 237)

    def test_failed_save_cleanup_and_result_stay_inside_io_lock(self):
        a = self.a
        entered, proceed = threading.Event(), threading.Event()
        dump, remove = NS['json'].dump, NS['os'].remove
        results = []
        calls = 0
        def write(config, stream, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                stream.write('partial')
                raise OSError('first writer failed')
            return dump(config, stream, **kwargs)
        def cleanup(path):
            self.assertTrue(a.settings_io_lock.locked())
            entered.set()
            if not proceed.wait(3):
                raise RuntimeError('test timeout')
            return remove(path)
        with patch('settings.json.dump', side_effect=write), patch('settings.os.remove', side_effect=cleanup):
            first = threading.Thread(target=lambda: results.append(a.save_settings()))
            second = threading.Thread(target=lambda: results.append(a.save_settings()))
            first.start()
            try:
                self.assertTrue(entered.wait(2))
                second.start()
            finally:
                proceed.set()
                first.join(3)
                if second.ident is not None:
                    second.join(3)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertCountEqual(results, [False, True])
        self.assertIsNone(a.settings_save_error)
        self.assertEqual(json.loads(self.config.read_text())['global_port_rules'], [])
        self.assertFalse(self.config.with_suffix('.json.tmp').exists())

    def test_saved_nested_preferences_and_port_policies_are_detached(self):
        a = self.a
        a.hidden_columns = {'monitor': ['Upload (MB)']}
        a.column_widths = {'monitor': {'PID': 149}}
        a.global_ports = a._parse_port_rules([dict(scope='remote', port=443, action='Allow',
            exes=[r'C:\one.exe', r'C:\two.exe'], target='example.test, other.test',
            addresses=['192.0.2.1'], target_addresses={'example.test': ['192.0.2.1']})])
        dump = NS['json'].dump
        def write(config, stream, **kwargs):
            with a.lock:
                a.hidden_columns['monitor'].append('PID')
                a.column_widths['monitor']['PID'] = 333
                rule = next(iter(a.global_ports.values()))
                rule['exes'].append(r'C:\three.exe')
                rule['target_addresses']['example.test'].append('192.0.2.2')
            return dump(config, stream, **kwargs)
        with patch('settings.json.dump', side_effect=write):
            self.assertTrue(a.save_settings())
        saved = json.loads(self.config.read_text())
        self.assertEqual(saved['hidden_columns']['monitor'], ['Upload (MB)'])
        self.assertEqual(saved['column_widths']['monitor']['PID'], 149)
        self.assertEqual(len(saved['global_port_rules'][0]['exes']), 2)
        self.assertEqual(saved['global_port_rules'][0]['target_addresses']['example.test'], ['192.0.2.1'])

    def test_connection_export_snapshots_rows_and_columns_before_save_dialog(self):
        a = self.a
        columns = ('Remote IP', 'Upload (MB)', 'Download (MB)')
        a.tree['displaycolumns'] = columns
        row = tuple('1.00 MB' if c == 'Upload (MB)' else '2.00 MB' if c == 'Download (MB)'
                    else '192.0.2.1' if c == 'Remote IP' else '' for c in App.MONITOR_COLUMNS)
        a.tree.insert('', 'end', iid='one', values=row)
        exported = self.config.parent / 'connections.csv'
        def choose(**kwargs):
            a.tree.delete('one')
            a.tree['displaycolumns'] = ('PID',)
            return str(exported)
        with patch.object(NS['filedialog'], 'asksaveasfilename', side_effect=choose), \
             patch.object(NS['messagebox'], 'showinfo'), patch.object(NS['messagebox'], 'showerror') as error:
            a.export_connections()
        error.assert_not_called()
        with exported.open(encoding='utf-8-sig', newline='') as stream:
            self.assertEqual(list(csv.reader(stream)), [list(columns), ['192.0.2.1', '1.00 MB', '2.00 MB']])

    def test_invalid_config_is_preserved_and_blocks_policy_but_recovers_profiles(self):
        a = self.a
        for contents in ('{broken', '[]', '{"global_port_rules":[{"scope":"remote","port":99999,"action":"Block"}]}',
                         '{"rate_threshold":"bad"}', '{"managed_rules":{}}'):
            with self.subTest(contents=contents):
                self.config.write_text(contents)
                with patch_dependencies(log_internal_error=Mock()):
                    a.load_settings()
                self.assertTrue(a.settings_load_error)
                self.assertFalse(a.save_settings())
                self.assertEqual(self.config.read_text(), contents)
                with patch.object(a, '_restore_firewall_profile_state_locked') as restore, \
                     patch.object(a, '_backup_firewall_profile_state') as backup, \
                     patch.object(a, 'run_ps') as run_ps, patch('firewall.os.path.exists', return_value=True), \
                     patch_dependencies(log_internal_error=Mock()):
                    ok, error = a.initialize_or_restore_firewall()
                self.assertFalse(ok)
                self.assertIn('Could not load', error)
                restore.assert_called_once()
                backup.assert_not_called()
                run_ps.assert_not_called()
                with patch.object(a, 'get_firewall_rules') as read:
                    self.assertFalse(a.block_executable(r'C:\new.exe', quiet=True))
                read.assert_not_called()

    def test_filter_all_restoring_alerts_on_auto_off_retires_the_prompt(self):
        a = self.a
        path = r'c:\demo.exe'
        a.filter_all_saved_alerts = True
        a.filter_all_saved_auto_block = False
        a.auto_hold_owners[path] = 0
        a.auto_prompt_keys.add(path)
        a.auto_prompt_key = path
        dialog = a.auto_prompt_dialog = Mock()
        a.auto_prompt_active = True
        with patch.object(a, '_queue_settings_change') as change:
            a.toggle_filter_all()
        self.assertTrue(a.log_alerts_only)
        self.assertFalse(a.auto_block_enabled or a.auto_prompt_keys or a.auto_prompt_active)
        self.assertEqual(a.auto_hold_cleanup[path], 0)
        dialog.destroy.assert_called_once()
        change.assert_called_once_with(release_auto_holds=True)

    def test_prompt_stays_topmost_and_setting_updates_open_prompt(self):
        a = self.a
        self.assertTrue(a.keep_notification_foreground)
        self.assertEqual(a.chk_foreground.cget('text'), 'Enable Keep Notification in Foreground')
        self.assertEqual(a.chk_foreground.grid_info()['row'], a.chk_auto.grid_info()['row'] + 1)
        with patch.object(a, '_theme_dialog', side_effect=lambda d: d.attributes('-alpha', 0)):
            a.show_auto_prompt(0, 'demo', 'demo', 'C:\\demo.exe', 12, '192.0.2.1', 'connection', '')
        dialog = a.auto_prompt_dialog
        done = NS['tk'].BooleanVar(self.root, False)
        self.root.after(350, lambda: done.set(True))
        self.root.wait_variable(done)
        self.assertTrue(dialog.attributes('-topmost'))
        a.keep_notification_foreground_var.set(False)
        a.on_notification_foreground_changed()
        self.root.update()
        self.assertFalse(dialog.attributes('-topmost'))
        self.assertFalse(json.loads(self.config.read_text())['keep_notification_foreground'])
        a.load_settings()
        self.assertFalse(a.keep_notification_foreground_var.get())
        a.keep_notification_foreground_var.set(True)
        a.on_notification_foreground_changed()
        self.root.update()
        self.assertTrue(dialog.attributes('-topmost'))

    def test_saved_sizes_ignore_fill_space_and_restore_maximized(self):
        a = self.a
        self.root.geometry('1560x790+90+65')
        self.root.update()
        a._set_visible_columns(a.tree, ['Process Name', 'PID'])
        a.tree.column('PID', width=123)
        self.root.update()
        a._fill_tree_column(a.tree)
        a._capture_layout()
        self.assertGreater(a.tree.column('PID', 'width'), 123)
        self.assertEqual(a.column_widths['monitor']['PID'], 123)
        self.root.state('zoomed')
        self.root.update()
        a._capture_layout()
        self.assertTrue(a.window_maximized)
        self.assertEqual(a.window_size, [1560, 790])
        self.assertEqual(a.window_position, [90, 65])
        a.save_settings()
        a.load_settings()
        a._fit_initial_window()
        self.root.update()
        self.assertEqual(self.root.state(), 'zoomed')
        self.root.state('normal')
        self.root.update()
        self.assertEqual((self.root.winfo_x(), self.root.winfo_y()), (90, 65))

    def test_visible_tray_exit_saves_position(self):
        self.root.geometry('1560x790+125+85')
        self.root.update()
        for callback in self.root.tk.call('after', 'info'):
            self.root.after_cancel(callback)
        self.a.on_closing()
        self.assertEqual(json.loads(self.config.read_text())['window_position'], [125, 85])

    def test_position_validation_and_negative_coordinates(self):
        for position in (None, [], [1], [1, 2, 3], ['1', 2], [True, 2], [1.5, 2], [100001, 0]):
            with self.subTest(position=position):
                self.config.write_text(json.dumps({'window_position': position}))
                self.a.load_settings()
                self.assertIsNone(self.a.window_position)
        self.config.write_text(json.dumps({'window_position': [-100, 45]}))
        self.a.load_settings()
        self.a._fit_initial_window()
        self.root.update()
        self.assertEqual((self.root.winfo_x(), self.root.winfo_y()), (-100, 45))

    def test_reset_restores_foreground_and_default_widths(self):
        a = self.a
        a.keep_notification_foreground = False
        a.tree.column('PID', width=333)
        a.pending_rules = [{'path': r'C:\old.exe', 'direction': 'Both'}]
        a.blocked_paths = {r'c:\old.exe': {'path': r'C:\old.exe', 'in': True, 'out': True}}
        with patch.object(NS['messagebox'], 'askyesno', return_value=True), \
             patch.object(NS['messagebox'], 'showinfo'), patch.object(NS['messagebox'], 'showerror') as error, \
             patch.object(a, 'get_firewall_rules', return_value=[]), patch.object(a, '_replace_rule_records'), \
             patch.object(a, 'refresh_rules'):
            a.reset_to_defaults()
        error.assert_not_called()
        self.assertTrue(a.keep_notification_foreground_var.get())
        self.assertTrue(json.loads(self.config.read_text())['keep_notification_foreground'])
        self.assertEqual(a.tree.column('PID', 'width'), a.tree._default_column_widths['PID'])
        self.assertFalse(a.pending_rules or a.blocked_paths)

    def test_reset_save_failure_does_not_announce_durable_success(self):
        a = self.a
        with patch.object(NS['messagebox'], 'askyesno', return_value=True), \
             patch.object(NS['messagebox'], 'showinfo') as info, patch.object(NS['messagebox'], 'showerror') as error, \
             patch.object(a, 'get_firewall_rules', return_value=[]), patch.object(a, '_replace_rule_records'), \
             patch.object(a, 'refresh_rules'), patch.object(a, 'save_settings', return_value=False):
            a.reset_to_defaults()
            info.assert_not_called()
            a.drain_ui_queue()
            self.assertEqual(error.call_args.args[0], 'Settings Not Saved')
