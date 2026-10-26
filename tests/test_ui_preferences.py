"""Connection drafts, foreground preference and saved window/table geometry."""
import json
import pathlib
import queue
import tempfile
import unittest
from collections import deque
from contextlib import ExitStack
from unittest.mock import Mock, patch

from support import App, NS, patch_dependencies
from test_firewall_monitor import app
from test_native_port_rules import connection


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
        self.root.geometry('1560x790+110+75')
        self.root.update()
        for tree in (a.tree, a.rules_tree, a.alerts_tree):
            tree.column(tree['columns'][0], width=237)
        a.tree.column('PID', width=149)
        a._hide_column(a.tree, 'PID')
        order = list(a.column_orders['monitor'])
        order[0], order[1] = order[1], order[0]
        a.column_orders['monitor'] = order
        a.tree['displaycolumns'] = tuple(c for c in order if c != 'PID')
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
        self.assertEqual(restored.tree.column('PID', 'width'), 149)
        for tree in (restored.tree, restored.rules_tree, restored.alerts_tree):
            self.assertEqual(tree.column(tree['columns'][0], 'width'), 237)

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
        with patch.object(NS['messagebox'], 'askyesno', return_value=True), \
             patch.object(NS['messagebox'], 'showinfo'), patch.object(NS['messagebox'], 'showerror') as error, \
             patch.object(a, 'get_firewall_rules', return_value=[]), patch.object(a, '_replace_rule_records'), \
             patch.object(a, 'refresh_rules'):
            a.reset_to_defaults()
        error.assert_not_called()
        self.assertTrue(a.keep_notification_foreground_var.get())
        self.assertTrue(json.loads(self.config.read_text())['keep_notification_foreground'])
        self.assertEqual(a.tree.column('PID', 'width'), a.tree._default_column_widths['PID'])
