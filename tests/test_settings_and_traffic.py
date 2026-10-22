"""UI and accounting regressions without live capture or firewall changes."""
import pathlib
import tempfile
import unittest
from unittest.mock import Mock, patch

from support import patch_dependencies
from test_firewall_monitor import App, NS, app


class GlobalTrafficTests(unittest.TestCase):
    def setUp(self):
        self.a = app()
        self.a.proc_traffic = {}
        self.a.ip_traffic = {
            '192.0.2.1': {'download': 120, 'upload': 40},
            '192.0.2.2': {'download': 230, 'upload': 60},
            '2001:db8::1': {'download': 310, 'upload': 70},
            '198.51.100.1': {'download': 900, 'upload': 800},
        }
        self.a.pruned_target_traffic = {}

    def test_networks_host_masks_and_duplicate_endpoints(self):
        a = self.a
        self.assertEqual(a.target_traffic('192.0.2.0/24'), (350, 100))
        self.assertEqual(a.target_traffic('192.0.2.1/32'), (120, 40))
        self.assertEqual(a.target_traffic('2001:0db8:0:0:0:0:0:1/128'), (310, 70))
        self.assertEqual(a.target_traffic('example.test', (
            '192.0.2.0/24', '192.0.2.1', '192.0.2.1/32', '2001:db8::1/128', 'bad address')),
            (660, 170))
        a.global_allows['example.test'] = {'addresses': ('192.0.2.1/32', '2001:db8::1/128')}
        self.assertEqual(a.target_traffic('EXAMPLE.TEST.'), (430, 110))

    def test_pruning_preserves_totals_and_new_packets_add_once(self):
        a = self.a
        a.global_blocks = {'192.0.2.0/24': {'addresses': ()}}
        a.global_allows = {'example.test': {'addresses': ('192.0.2.1/32', '2001:db8::1/128')}}
        a.ip_traffic_last_seen = {ip: i for i, ip in enumerate(a.ip_traffic)}
        a.proc_ip_upload = {}
        with patch_dependencies(TRAFFIC_MAX_IP_ENTRIES=1):
            a._prune_traffic_state_locked()
        self.assertEqual(len(a.ip_traffic), 1)
        self.assertEqual(a.target_traffic('192.0.2.0/24'), (350, 100))
        self.assertEqual(a.target_traffic('example.test'), (430, 110))
        a.ip_traffic['192.0.2.1'] = {'download': 10, 'upload': 5}
        a.ip_traffic_last_seen['192.0.2.1'] = -1
        self.assertEqual(a.target_traffic('example.test'), (440, 115))
        with patch_dependencies(TRAFFIC_MAX_IP_ENTRIES=1):
            a._prune_traffic_state_locked()
        self.assertEqual(a.target_traffic('example.test'), (440, 115))
        self.assertEqual(a.target_traffic('192.0.2.0/24'), (360, 105))

    def test_refresh_periodic_update_and_display_use_same_totals(self):
        a = self.a
        a.rules_generation = 1
        a.global_allows = {'example.test': {'addresses': ('192.0.2.1/32', '192.0.2.2/32')}}
        a.render_rules = Mock()
        a.render_monitor = Mock()
        a.render_active = Mock()
        a._finish_rule_refresh(1, {}, set(), {}, a.global_allows)
        self.assertEqual((a.rule_rows[0]['download'], a.rule_rows[0]['upload']), (350, 100))
        a.ip_traffic['192.0.2.1']['upload'] += 1024 * 1024
        a.render_rule_traffic()
        self.assertEqual(a.rule_rows[0]['upload'], 1024 * 1024 + 100)
        a.rules_tree = Mock()
        a.rules_tree.selection.return_value = []
        a.rules_tree.get_children.return_value = []
        a.rule_search_var = Mock()
        a.rule_search_var.get.return_value = ''
        a.rule_sort = [None, False]
        App.render_rules(a)
        self.assertEqual(a.rules_tree.insert.call_args.kwargs['values'][4], '1.00 MB')


class UninstallTests(unittest.TestCase):
    def test_confirmation_launch_cancel_and_errors(self):
        a = app()
        a.root = Mock()
        script = NS['os'].path.join(NS['SCRIPT_DIR'], 'Uninstall-PyFirewall.cmd')
        with patch.object(NS['os'].path, 'isfile', return_value=True) as exists, \
             patch.object(NS['messagebox'], 'askyesno', return_value=False) as confirm, \
             patch.object(NS['messagebox'], 'showerror') as error, \
             patch.object(NS['ctypes'].windll.shell32, 'ShellExecuteW', return_value=42) as launch:
            a.uninstall_pyfirewall()
            exists.assert_called_with(script)
            launch.assert_not_called()
            confirm.return_value = True
            a.uninstall_pyfirewall()
            launch.assert_called_once_with(None, 'runas', script, None, NS['SCRIPT_DIR'], 1)
            self.assertIn('dependencies', confirm.call_args.args[1])
            error.assert_not_called()
            launch.return_value = 5
            a.uninstall_pyfirewall()
            self.assertIn('Administrator permission', error.call_args.args[1])
            launch.side_effect = OSError('Launch failed')
            a.uninstall_pyfirewall()
            self.assertIn('Launch failed', error.call_args.args[1])
            launch.reset_mock()
            confirm.reset_mock()
            exists.return_value = False
            a.uninstall_pyfirewall()
            confirm.assert_not_called()
            launch.assert_not_called()
            self.assertIn('not found', error.call_args.args[1])


class SettingsInteractionTests(unittest.TestCase):
    def test_search_button_themes_and_wallet_copy(self):
        tk = NS['tk']
        root = tk.Tk()
        root.attributes('-alpha', 0)
        try:
            with tempfile.TemporaryDirectory() as directory, \
                 patch_dependencies(CONFIG_FILE=str(pathlib.Path(directory) / 'config.json'), PyFirewallSystemTray=Mock(), add_tooltip=Mock()), \
                 patch.object(App, '_start_dns_workers'), \
                 patch.object(App, '_start_background_initialization'), \
                 patch.object(App, 'update_loop'):
                a = App(root)

                def descendants(widget):
                    for child in widget.winfo_children():
                        yield child
                        yield from descendants(child)

                buttons = [w for w in descendants(root) if isinstance(w, tk.Button)]
                by_text = lambda text: [w for w in buttons if w.cget('text') == text]
                sizes = []
                for tab in (a.tab_monitor, a.tab_active, a.tab_rules, a.tab_alerts):
                    a.notebook.select(tab)
                    root.update()
                    entry = next(w for w in descendants(tab) if isinstance(w, NS['ttk'].Entry))
                    sizes.append((entry.winfo_width(), entry.winfo_rootx()))
                self.assertEqual(len(set(sizes)), 1)
                self.assertGreaterEqual(a.rules_tree.column('Status', 'width'),
                                        NS['tkfont'].nametofont('TkDefaultFont').measure('Global Port Allow') + 20)
                support = next(w for w in descendants(a.tab_settings)
                               if isinstance(w, tk.LabelFrame) and w.cget('text') == 'Support PyFirewall')
                links = [support.grid_slaves(row=i, column=1)[0] for i in range(3)]
                self.assertEqual(links[1].cget('text'), 'Donate via Crypto • Support the dev (EolnMsuk)')
                for dark in (False, True):
                    a.dark_mode_var.set(dark)
                    a.apply_theme()
                    for reference, targets in ((by_text('Apply Settings')[0], by_text('Check for Updates')),
                                               (by_text('Export Rules')[0], by_text('Import Rules')),
                                               (by_text('Add App Rule')[0], by_text('Reset to Defaults')),
                                               (a.btn_filter, by_text('Uninstall PyFirewall'))):
                        for event in ('<Enter>', '<Leave>', '<ButtonPress-1>', '<Leave>'):
                            for button in (reference, *targets):
                                button.event_generate(event)
                            for button in targets:
                                for option in ('bg', 'fg', 'activebackground', 'activeforeground'):
                                    self.assertEqual(button.cget(option), reference.cget(option))
                                self.assertEqual(button.master.cget('bg'), reference.master.cget('bg'))
                    for link in links:
                        self.assertEqual(link.cget('cursor'), 'hand2')
                        self.assertEqual(link.cget('fg'), a.colors['select'])

                a.show_crypto_wallets()
                dialog = a.crypto_dialog
                dialog.attributes('-alpha', 0)
                root.update()
                body = dialog.winfo_children()[0]
                rows = [w for w in body.winfo_children() if isinstance(w, tk.Frame)]
                self.assertEqual(len(rows), 8)
                confirmation = body.pack_slaves()[-1]
                with patch.object(root, 'clipboard_clear') as clear, patch.object(root, 'clipboard_append') as copy:
                    for row, (description, address) in zip(rows, NS['CRYPTO_WALLETS']):
                        self.assertEqual(row.winfo_children()[0].cget('text'), description)
                        self.assertEqual(row.winfo_children()[1].cget('text'), f'{address}  📋')
                        for widget in (row, *row.winfo_children()):
                            widget.event_generate('<Button-1>')
                            copy.assert_called_with(address)
                            self.assertIn('address copied', confirmation.cget('text'))
                            self.assertEqual(row.winfo_children()[1].cget('bg'), a.colors['head'])
                            self.assertEqual(row.cget('bg'), a.colors['frame'])
                            self.assertEqual(row.winfo_children()[0].cget('bg'), a.colors['frame'])
                            widget.event_generate('<ButtonRelease-1>')
                            for part in (row, *row.winfo_children()):
                                self.assertEqual(part.cget('bg'), a.colors['frame'])
                    self.assertEqual(clear.call_count, 24)
                for dark in (False, True):
                    a.dark_mode_var.set(dark)
                    a.apply_theme()
                    self.assertEqual(dialog.cget('bg'), a.colors['frame'])
                    self.assertEqual(rows[0].winfo_children()[1].cget('fg'), '#bdbdbd')
                    self.assertEqual(rows[0].winfo_children()[0].cget('fg'), a.colors['select'])
                    self.assertEqual(body.pack_slaves()[0].cget('fg'), a.colors['select'])
                    self.assertEqual(body.pack_slaves()[0].cget('text'),
                                     'Support EolnMsuk - Click any wallet to copy its address')
                a.show_crypto_wallets()
                self.assertIs(a.crypto_dialog, dialog)
                dialog.destroy()
        finally:
            for child in root.winfo_children():
                if isinstance(child, tk.Toplevel):
                    child.destroy()
            for callback in root.tk.call('after', 'info'):
                root.after_cancel(callback)
            root.destroy()


if __name__ == '__main__':
    unittest.main()
