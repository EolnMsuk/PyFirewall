"""UI and accounting regressions without live capture or firewall changes."""
import pathlib
import copy
import queue
import tempfile
import types
import threading
import unittest
from unittest.mock import Mock, patch

from support import App, NS, patch_dependencies
from fixtures import app, MemoryFirewall


class GlobalTrafficTests(unittest.TestCase):
    def test_alert_backlog_and_rate_histories_are_bounded_and_clear_retires_queued_history(self):
        a = app()
        a.alert_queue = queue.Queue(maxsize=2)
        a.alerts = NS['deque'](maxlen=2)
        a.render_alerts = Mock()
        a.next_alert_id = 1
        a.queue_alert = types.MethodType(App.queue_alert, a)
        for i in range(5):
            a.queue_alert('Info', 'test', '', '', str(i))
        self.assertEqual(a.alert_queue.qsize(), 2)
        self.assertEqual(a.dropped_alerts, 3)
        a.clear_alerts()
        a.drain_alerts()
        self.assertFalse(a.alerts)
        a.queue_alert('Info', 'test', '', '', 'after clear')
        a.drain_alerts()
        self.assertEqual(len(a.alerts), 1)
        a.rate_window = 5
        a.proc_traffic = {'lifetime': {'upload': 123}}
        with patch_dependencies(RATE_MAX_KEYS=2):
            self.assertFalse(a._rate_hit_locked('one', 10, 2, 5))
            self.assertFalse(a._rate_hit_locked('two', 10, 2, 5))
            self.assertFalse(a._rate_hit_locked('three', 10, 2, 5))
            self.assertEqual(len(a.connection_rates), 2)
            self.assertEqual(a.untracked_rate_events, 1)
            self.assertTrue(a._rate_hit_locked('one', 11, 2, 5))
            a._prune_rates_locked(16)
            self.assertFalse(a.connection_rates)
            self.assertFalse(a._rate_hit_locked('three', 16, 2, 5))
        self.assertEqual(a.proc_traffic['lifetime']['upload'], 123)

    def test_reconciliation_preserves_intent_and_reports_global_and_app_drift(self):
        a = app()
        native = MemoryFirewall(a)
        entries = [dict(scope='remote', port=443, action='Block', exes=[r'C:\one.exe', r'C:\two.exe'])]
        self.assertTrue(a.apply_global_port_rules(entries))
        key = next(iter(a.global_ports))
        expected = a._port_firewall_rules(a.global_ports)
        with a.firewall_lock:
            snapshot = a.sync_rule_cache()
        self.assertEqual(snapshot[-1][key]['_enforcement'], 'Verified')
        endpoint = dict(exe=r'C:\one.exe', protocol='TCP', dport=443, direction='Outgoing', dst_ip='192.0.2.1')
        self.assertTrue(a._threshold_has_rule(endpoint))
        for change, state in (('missing_member', 'Partial'), ('disabled', 'Disabled'),
                              ('protocol', 'Changed'), ('address', 'Changed'), ('program', 'Changed'), ('missing_all', 'Missing')):
            native.rules.clear()
            native.create(expected)
            first = next(iter(native.rules.values()))
            if change == 'missing_member':
                native.rules.pop(expected[-1]['name'])
            elif change == 'disabled':
                first['enabled'] = False
            elif change == 'protocol':
                first['protocol'] = 'Any'
            elif change == 'address':
                first['addresses'] = ['198.51.100.1']
            elif change == 'program':
                first['path'] = r'C:\other.exe'
            else:
                native.rules.clear()
            with self.subTest(change=change):
                snapshot = a.sync_rule_cache()
                self.assertEqual(snapshot[-1][key]['_enforcement'], state)
                self.assertFalse(a._threshold_has_rule(endpoint))
                self.assertIn(key, a.global_ports)
                row = a._make_rule_rows(*snapshot)[0]
                self.assertIn(state.lower(), row['status'])
        native.rules.clear()
        self.assertTrue(a.apply_global_port_rules(entries))  # Repair through the same transaction.
        self.assertEqual(a.sync_rule_cache()[-1][key]['_enforcement'], 'Verified')
        path = r'C:\allowed.exe'
        a.allowed_apps.add(NS['normalize_path'](path))
        rule = dict(name='PyFirewall_external_In', action='Block', direction='Inbound', path=path,
                    normalized_path=NS['normalize_path'](path), is_global=False, is_hold=False, enabled=False)
        native.rules = {rule['name']: rule}
        snapshot = a.sync_rule_cache()
        self.assertEqual(a.get_rule_status(path), 'allowed')
        self.assertEqual(snapshot[0][NS['normalize_path'](path)]['_enforcement'], 'Disabled')
        self.assertFalse(a.blocked_paths)  # Observation must not become saved intent.
        self.assertFalse(a._rule_is_duplicate(path, allow=True))
        rows = a._make_rule_rows(*snapshot)
        self.assertEqual(next(r for r in rows if r['action'] == 'Allow')['status'], 'Allowed')
        self.assertEqual(next(r for r in rows if r['action'] == 'Block')['status'], 'Block observed (disabled)')
        rule['enabled'] = True
        a.sync_rule_cache()
        self.assertEqual(a.get_rule_status(path), 'blocked_in')
        self.assertIn(NS['normalize_path'](path), a.allowed_apps)

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
        a.rules_tree.get_children.return_value = []
        a.rules_tree.selection.return_value = []
        a.rules_tree.get_children.return_value = []
        a.rule_search_var = Mock()
        a.rule_search_var.get.return_value = ''
        a.rule_sort = [None, False]
        App.render_rules(a)
        self.assertEqual(a.rules_tree.insert.call_args.kwargs['values'][App.RULE_COLUMNS.index('Upload (MB)')], '1.00 MB')

    def test_old_refresh_cannot_overwrite_a_committed_block_or_mix_policy_snapshots(self):
        a = self.a
        native = MemoryFirewall(a)
        a.ui_queue = queue.Queue()
        a.rules_generation = 1
        a.rules_refresh_pending = a.rules_refresh_worker_running = True
        a.render_rules = a.render_monitor = Mock()
        a.global_ports = a._parse_port_rules([{'scope': 'remote', 'port': 443, 'action': 'Allow'}])
        a._refresh_rules_worker()
        old = a.ui_queue.get_nowait()
        saved = []
        a.save_settings.side_effect = lambda: saved.append(copy.deepcopy(a.blocked_paths)) or True
        self.assertTrue(a._apply_rule_batch([(r'C:\new.exe', False, 'both', False)], quiet=True))
        a._finish_rule_refresh(*old[1:])
        self.assertEqual(a.get_rule_status(r'C:\new.exe'), 'blocked_both')
        self.assertIn(r'c:\new.exe', saved[-1])
        self.assertEqual(len([r for r in native.rules.values() if r.get('normalized_path') == r'c:\new.exe']), 2)
        a.global_ports = {}
        detached = a._make_rule_rows(*old[2:])
        self.assertTrue(any(r.get('is_port') for r in detached))
        a.rules_refresh_pending = True
        a._refresh_rules_worker()
        a._finish_rule_refresh(*a.ui_queue.get_nowait()[1:])
        self.assertTrue(any(r['normalized_path'] == r'c:\new.exe' for r in a.rule_rows))
        self.assertFalse(any(r.get('is_port') for r in a.rule_rows))

    def test_refresh_requires_this_runs_initialization_and_can_retry_thread_start(self):
        a = self.a
        a.firewall_initialized = True
        a.firewall_ready = False
        a.rules_tree = Mock()
        a.rules_tree.get_children.return_value = []
        a.rules_generation = 0
        a.rules_refresh_worker_running = a.rules_refresh_pending = False
        a.ui_queue = queue.Queue()
        with patch.object(NS['threading'], 'Thread') as worker:
            a.refresh_rules(force=True)
            worker.assert_not_called()
            a.firewall_ready = True
            worker.return_value.start.side_effect = RuntimeError('start failed')
            with patch_dependencies(log_internal_error=Mock()):
                a.refresh_rules(force=True)
            self.assertFalse(a.rules_loading or a.rules_refresh_worker_running)
            worker.return_value.start.side_effect = None
            a.refresh_rules(force=True)
        self.assertEqual(worker.return_value.start.call_count, 2)

    def test_legacy_address_rule_totals_exclude_the_opposite_direction(self):
        a = self.a
        rows = a._make_rule_rows({}, set(), {'192.0.2.0/24': {'direction': 'Outbound'}},
                                 {'192.0.2.1': {'direction': 'Inbound'}})
        a._update_rule_traffic_locked(rows)
        self.assertEqual([(r['download'], r['upload']) for r in rows], [(0, 100), (120, 0)])


class GlobalPortTrafficTests(unittest.TestCase):
    def test_blocked_native_worker_keeps_capture_and_tk_responsive_and_rejects_old_epoch(self):
        a = self.a
        a.global_ports = {}
        a.log_alerts_only = True
        a.rate_threshold = 1
        a.install_auto_hold = Mock(return_value=True)
        a.release_auto_holds = Mock()
        a.firewall_profile_modified = False
        entered, release, drained = threading.Event(), threading.Event(), threading.Event()
        root = NS['tk'].Tk()
        root.attributes('-alpha', 0)
        a._start_native_worker()
        try:
            def blocked():
                entered.set()
                if not release.wait(3):
                    raise RuntimeError('test timeout')
            a._queue_native_job('Blocked native operation', blocked)
            self.assertTrue(entered.wait(2))
            self.capture(100)
            self.capture(100, remote='192.0.2.2')
            self.assertEqual(a.captured_packets, 2)
            heartbeat = []
            root.after_idle(lambda: heartbeat.append(True))
            a.prompt_queue.put((0, 'key', 'demo', r'C:\demo.exe', 1, '192.0.2.1', '', 'Outgoing', 'connection', ''))
            a.drain_prompt_queue()  # Busy native lock must not wait on Tk.
            root.update()
            self.assertEqual(heartbeat, [True])
            a.auto_block_enabled = False
            a._invalidate_auto_prompts(close_dialog=True)
            a.auto_block_enabled = True
            a.rate_threshold = 50
            a._queue_native_job('Barrier', drained.set)
            release.set()
            self.assertTrue(drained.wait(2))
            a.install_auto_hold.assert_not_called()
            a.rate_threshold = 1
            self.capture(100, remote='192.0.2.3')
            drained.clear()
            a._queue_native_job('Barrier', drained.set)
            self.assertTrue(drained.wait(2))
            a.install_auto_hold.assert_called_once()
        finally:
            release.set()
            a.native_shutdown_requested = True
            a.native_worker.join(3)
            root.destroy()
        self.assertFalse(a.native_worker.is_alive())

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

    def test_process_scoped_traffic_excludes_other_executables(self):
        a = self.a
        a.global_ports = a._parse_port_rules([
            dict(scope='remote', port=443, action='Block', exe=r'C:\demo.exe')])
        key = next(iter(a.global_ports))
        self.capture(100, exe=r'C:\demo.exe')
        self.capture(200, exe=r'C:\other.exe', pid=2)
        self.assertEqual(a.global_port_traffic[key], {'download': 0, 'upload': 100})

    def test_executable_group_counts_each_member_once_and_excludes_other_processes(self):
        a = self.a
        a.global_ports = a._parse_port_rules([dict(scope='remote', port=443, action='Block',
            exes=[r'C:\demo.exe', r'C:\DEMO.exe', r'C:\second.exe'])])
        key = next(iter(a.global_ports))
        self.capture(100, exe=r'C:\demo.exe')
        self.capture(200, exe=r'C:\second.exe', pid=2)
        self.capture(300, incoming=True, exe=r'C:\second.exe', pid=2)
        self.capture(900, exe=r'C:\other.exe', pid=3)
        self.assertEqual(a.global_port_traffic, {key: {'download': 300, 'upload': 300}})

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
            'remote:443:Allow:Both': {'download': 900, 'upload': 1300},
            'remote:443:TCP:example.test, 192.0.2.0/24:Allow:Both': {'download': 900, 'upload': 400},
            'local:51000:Allow:Inbound': {'download': 900, 'upload': 0},
            'remote:None:2001:db8::1:Allow:Both': {'download': 700, 'upload': 0},
        })
        self.assertEqual(a.proc_traffic['c:\\demo.exe'], {'download': 900, 'upload': 1600})
        self.assertEqual(a.proc_traffic['c:\\second.exe'], {'download': 0, 'upload': 300})
        self.assertEqual(a.captured_packets, 7)

    def test_pause_during_attribution_discards_the_packet_before_publication(self):
        a = self.a
        a.get_cached_dns.side_effect = lambda ip: setattr(a, 'is_paused', True) or ''
        self.capture(100)
        self.assertEqual(a.captured_packets, 0)
        self.assertFalse(a.active_connections or a.proc_traffic or a.global_port_traffic)

    def test_threshold_uses_outbound_packet_policy_after_inbound_first_packet_and_clear(self):
        a = self.a
        self.capture(100, incoming=True)
        a.global_ports = a._parse_port_rules([{'scope': 'remote', 'port': 443, 'action': 'Allow',
                                             'direction': 'Outbound', 'exe': r'C:\demo.exe'}])
        a.log_alerts_only = True
        a.upload_threshold_mb = 0.00001
        a.queue_alert.side_effect = lambda *args, **kwargs: a.active_connections.clear()
        a.install_auto_hold = Mock()
        self.capture(200)
        a.install_auto_hold.assert_not_called()
        endpoint = a.queue_alert.call_args.kwargs['connection']
        self.assertEqual((endpoint['direction'], endpoint['dport'], endpoint['exe']), ('Outgoing', 443, r'C:\demo.exe'))
        self.assertFalse(a.active_connections)

    def test_removed_or_replaced_filtered_rule_retires_only_its_counter_after_commit(self):
        a = self.a
        native = MemoryFirewall(a)
        entries = [{'scope': 'remote', 'port': 443, 'action': 'Allow'},
                   {'scope': 'local', 'port': 51000, 'action': 'Block'}]
        a.global_ports = {}
        self.assertTrue(a.apply_global_port_rules(entries))
        self.capture(100)
        old = 'remote:443:Allow:Both'
        sibling = 'local:51000:Block:Both'
        previous = copy.deepcopy(a.global_port_traffic)
        with patch.object(a, '_replace_rule_records', side_effect=RuntimeError('delete failed')), \
             patch.object(NS['messagebox'], 'showerror'):
            self.assertFalse(a.remove_rule('Allowed (global)', old))
        self.assertEqual(a.global_port_traffic, previous)
        self.assertTrue(a.remove_rule('Allowed (global)', old))
        self.assertNotIn(old, a.global_port_traffic)
        self.assertEqual(a.global_port_traffic[sibling]['upload'], 100)
        self.assertTrue(a.apply_global_port_rules([entries[0]]))
        self.capture(25)
        self.assertEqual(a.global_port_traffic[old]['upload'], 25)
        replacement = [dict(entries[0], port=8443)]
        self.assertTrue(a._apply_rule_batch((), port_updates=replacement, replace_rule=('port', old), quiet=True))
        self.assertNotIn(old, a.global_port_traffic)
        self.assertEqual(a.global_port_traffic[sibling]['upload'], 125)

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
        self.assertEqual(rows['port:remote:443:Allow:Both']['upload'], 1024 * 1024)
        self.assertEqual(rows['app:allow:c:\\demo.exe']['upload'], 1024 * 1024)
        a.active_connections.clear()
        with patch_dependencies(TRAFFIC_MAX_IP_ENTRIES=0):
            a._prune_traffic_state_locked()
        a.render_rule_traffic()
        self.assertEqual(rows['port:remote:443:Allow:Both']['upload'], 1024 * 1024)
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
        self.assertEqual(displayed['port:remote:443:Allow:Both'][6:8], ('2.00 MB', '1.00 MB'))
        self.assertEqual(displayed['port:remote:None:2001:db8::1:Allow:Both'][6:8], ('0.00 MB', '0.00 MB'))


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
                    self.assertEqual(body.pack_slaves()[0].cget('fg'), a.colors['crypto_heading'])
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
