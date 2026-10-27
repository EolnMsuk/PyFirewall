"""UI and accounting regressions without live capture or firewall changes."""
import pathlib
import tempfile
import types
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
        self.assertEqual(a.rules_tree.insert.call_args.kwargs['values'][App.RULE_COLUMNS.index('Upload (MB)')], '1.00 MB')


class GlobalPortTrafficTests(unittest.TestCase):
    def setUp(self):
        a = self.a = app()
        a.sniffing = True
        a.log_alerts_only = False
        a.rate_threshold = a.rate_window = a.upload_threshold_mb = 10
        a.captured_packets = a.captured_bytes = a.total_upload = a.total_download = 0
        a.proc_traffic = {}
        a.ip_traffic = {}
        a.ip_traffic_last_seen = {}
        a.pruned_target_traffic = {}
        a.proc_ip_upload = {}
        a.proc_ip_upload_last_seen = {}
        a.active_connections = {}
        a.next_connection_number = 1
        a.last_traffic_prune = NS['time'].monotonic()
        a._prune_connection_and_alert_history_locked = Mock()
        a.get_cached_dns = Mock(return_value='')
        a.port_watch_signal = Mock(return_value='')
        a.global_ports = a._parse_port_rules([
            {'scope': 'remote', 'port': 443, 'action': 'Allow'},
            {'scope': 'remote', 'port': 443, 'action': 'Allow', 'protocol': 'TCP',
             'target': 'example.test, 192.0.2.0/24', 'addresses': ['192.0.2.1', '2001:db8::1']},
            {'scope': 'local', 'port': 51000, 'action': 'Allow', 'direction': 'Inbound'},
            {'scope': 'remote', 'port': None, 'action': 'Allow', 'target': '2001:db8::1'},
        ])

    def capture(self, size, incoming=False, remote='192.0.2.1', port=443,
                protocol='TCP', exe='C:\\demo.exe', tracked=True, pid=1, local_port=51000):
        a = self.a
        local = '2001:db8::2' if ':' in remote else '192.0.2.100'
        src, dst = (remote, local) if incoming else (local, remote)
        sport, dport = (port, local_port) if incoming else (local_port, port)
        layers = {NS['IPv6' if ':' in remote else 'IP']: types.SimpleNamespace(src=src, dst=dst),
                  NS[protocol]: types.SimpleNamespace(sport=sport, dport=dport)}

        class Packet:
            def __len__(self):
                return size

            def __contains__(self, layer):
                return layer in layers

            def __getitem__(self, layer):
                return layers[layer]

        a.get_process_info = Mock(side_effect=lambda ip, *args:
            ('demo', exe, pid) if tracked and ip == local else (None, None, None))
        with patch_dependencies(log_internal_error=Mock(side_effect=AssertionError('Packet accounting failed'))):
            a.packet_handler(Packet())

    def test_packets_count_each_matching_rule_and_app_once(self):
        self.capture(100)
        self.capture(200, incoming=True)
        self.capture(300, exe='C:\\second.exe', pid=2)
        self.capture(400, protocol='UDP')
        self.capture(500, remote='198.51.100.1')
        self.capture(600, port=80)
        self.capture(700, incoming=True, remote='2001:db8::1')
        self.capture(999, tracked=False)
        a = self.a
        self.assertEqual(a.global_port_traffic, {
            'remote:443': {'download': 900, 'upload': 1300},
            'remote:443:TCP:example.test, 192.0.2.0/24': {'download': 900, 'upload': 400},
            'local:51000': {'download': 900, 'upload': 0},
            'remote:None:2001:db8::1': {'download': 700, 'upload': 0},
        })
        self.assertEqual(a.proc_traffic['c:\\demo.exe'], {'download': 900, 'upload': 1600})
        self.assertEqual(a.proc_traffic['c:\\second.exe'], {'download': 0, 'upload': 300})
        self.assertEqual(a.captured_packets, 7)

    def test_live_monitor_counts_each_connection_while_app_rules_keep_totals(self):
        a = self.a
        mib = 1024 * 1024
        self.capture(mib)
        self.capture(2 * mib, incoming=True)
        self.capture(3 * mib, remote='198.51.100.1')
        self.capture(4 * mib, protocol='UDP')
        self.capture(5 * mib, port=80)
        self.capture(6 * mib, local_port=51001)
        self.capture(7 * mib, pid=2)
        a.remote_host = Mock(side_effect=lambda row: row.get('domain', ''))
        a.connection_status = Mock(return_value='Allowed')
        a.connection_tag = Mock(return_value='allowed')
        tree = Mock(spec=NS['ttk'].Treeview)
        tree.selection.return_value = []
        tree.get_children.return_value = []
        search = Mock()
        search.get.return_value = ''
        a._render_connections(tree, search, ['Upload (MB)', True])
        displayed = {call.kwargs['iid']: dict(zip(App.MONITOR_COLUMNS, call.kwargs['values']))
                     for call in tree.insert.call_args_list}
        expected = {
            '1-TCP-51000-192.0.2.1-443': ('2.00 MB', '1.00 MB'),
            '1-TCP-51000-198.51.100.1-443': ('0.00 MB', '3.00 MB'),
            '1-UDP-51000-192.0.2.1-443': ('0.00 MB', '4.00 MB'),
            '1-TCP-51000-192.0.2.1-80': ('0.00 MB', '5.00 MB'),
            '1-TCP-51001-192.0.2.1-443': ('0.00 MB', '6.00 MB'),
            '2-TCP-51000-192.0.2.1-443': ('0.00 MB', '7.00 MB'),
        }
        self.assertEqual({key: (values['Download (MB)'], values['Upload (MB)'])
                          for key, values in displayed.items()}, expected)
        self.assertEqual(next(iter(displayed)), '2-TCP-51000-192.0.2.1-443')
        a.rule_rows = a._make_rule_rows({}, {'c:\\demo.exe'}, {}, {})
        a.render_rule_traffic()
        app_row = next(row for row in a.rule_rows if row['iid'].startswith('app:'))
        self.assertEqual((app_row['download'], app_row['upload']), (2 * mib, 26 * mib))
        a.active_connections.clear()
        self.capture(mib)
        self.assertEqual(next(iter(a.active_connections.values()))['upload'], mib)
        self.assertEqual(a.proc_traffic['c:\\demo.exe']['upload'], 27 * mib)

    def test_refresh_display_and_pruning_preserve_totals(self):
        a = self.a
        a.rules_generation = 1
        a.render_rules = Mock()
        a.render_monitor = Mock()
        self.capture(1024 * 1024)
        a._finish_rule_refresh(1, {}, {'c:\\demo.exe'}, {}, {})
        rows = {row['iid']: row for row in a.rule_rows}
        self.assertEqual(rows['port:remote:443']['upload'], 1024 * 1024)
        self.assertEqual(rows['app:allow:c:\\demo.exe']['upload'], 1024 * 1024)
        a.active_connections.clear()
        with patch_dependencies(TRAFFIC_MAX_IP_ENTRIES=0):
            a._prune_traffic_state_locked()
        a.render_rule_traffic()
        self.assertEqual(rows['port:remote:443']['upload'], 1024 * 1024)
        self.capture(2 * 1024 * 1024, incoming=True)
        a.render_rule_traffic()
        a.rules_tree = Mock()
        a.rules_tree.selection.return_value = []
        a.rules_tree.get_children.return_value = []
        a.rule_search_var = Mock()
        a.rule_search_var.get.return_value = ''
        a.rule_sort = ['Upload (MB)', True]
        App.render_rules(a)
        displayed = {call.kwargs['iid']: call.kwargs['values']
                     for call in a.rules_tree.insert.call_args_list}
        self.assertEqual(displayed['port:remote:443'][6:8], ('2.00 MB', '1.00 MB'))
        self.assertEqual(displayed['port:remote:None:2001:db8::1'][6:8], ('0.00 MB', '0.00 MB'))


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
                for tab in (a.tab_monitor, a.tab_rules, a.tab_alerts):
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
                self.assertEqual(links[1].cget('text'), 'Donate via Crypto')
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
                    self.assertEqual(rows[0].winfo_children()[1].cget('fg'), a.colors['wallet'])
                    self.assertEqual(rows[0].winfo_children()[0].cget('fg'), a.colors['select'])
                    self.assertEqual(body.pack_slaves()[0].cget('fg'), a.colors['fg'])
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
