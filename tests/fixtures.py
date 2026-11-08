"""Shared partial application and in-memory firewall fixtures; no system changes."""
import copy
import queue
import threading
from unittest.mock import Mock

from support import App, NS


def app():
    a = App.__new__(App)
    a.lock = threading.RLock()
    a.firewall_lock = threading.RLock()
    a.ui_thread_id = threading.get_ident()
    a.ui_queue = queue.Queue()
    a.closed = a.is_paused = False
    a.dark_mode = NS['DEFAULT_DARK_MODE']
    a.check_updates_on_startup = NS['DEFAULT_CHECK_UPDATES_ON_STARTUP']
    a.check_updates_on_startup_var = Mock()
    a.update_check_running = a.update_check_manual = False
    a.update_dialog = None
    a.log_alerts_only = a.auto_block_enabled = True
    a.keep_notification_foreground = True
    a.keep_notification_foreground_var = Mock()
    a.column_widths = {}
    a.window_size = None
    a.window_maximized = False
    a.alert_connections = {}
    a.auto_prompt_generation = 0
    a.auto_prompt_keys = set()
    a.auto_prompt_connections = {}
    a.auto_hold_owners = {}
    a.auto_hold_cleanup = {}
    a.auto_prompt_dialog = a.auto_prompt_key = None
    a.auto_prompt_active = False
    a.prompt_queue = queue.Queue()
    a.allowed_apps = set()
    a.blocked_paths = {}
    a.global_blocks = {}
    a.global_allows = {}
    a.global_ports = {}
    a.global_port_traffic = {}
    a.connection_rates = {}
    a.upload_alerted = set()
    a.queue_alert = Mock()
    a.save_settings = Mock(return_value=True)
    a.rules_changed = Mock()
    a.root = Mock()
    a._show_rule_result = Mock()
    a.capture_error = None
    a.capture_healthy = False
    return a


def port(scope='remote', number=443, action='Allow'):
    return {'scope': scope, 'port': number, 'action': action}


def connection(**changes):
    return dict({'exe': 'C:\\demo.exe', 'lport': 51000, 'dport': 443, 'protocol': 'TCP',
                 'direction': 'Outgoing', 'dst_ip': '192.0.2.1'}, **changes)


class MemoryFirewall:
    """Implements native create/delete/snapshot only; all planning is production code."""
    def __init__(self, a, unrelated_count=0):
        self.rules = {}
        for i in range(unrelated_count):
            name = f'PyFirewall_Block_app{i}_In'
            self.rules[name] = {'name': name, 'action': 'Block', 'direction': 'Inbound',
                                'path': f'C:\\app{i}.exe', 'normalized_path': f'c:\\app{i}.exe',
                                'is_hold': False, 'is_global': False, 'addresses': ['Any']}
        hold = 'PyFirewall_AutoHold_pending_In'
        self.rules[hold] = {'name': hold, 'action': 'Block', 'direction': 'Inbound',
                            'path': 'C:\\pending.exe', 'normalized_path': 'c:\\pending.exe',
                            'is_hold': True, 'is_global': False, 'addresses': ['Any']}
        a.get_firewall_rules = Mock(side_effect=lambda: copy.deepcopy(list(self.rules.values())))
        a.delete_rule_names = Mock(side_effect=self.delete)
        a._create_rule_batch = Mock(side_effect=self.create)
        a.run_ps = Mock(side_effect=AssertionError('Native firewall calls are forbidden in memory tests'))
        a.run_netsh = Mock(side_effect=AssertionError('Native firewall calls are forbidden in memory tests'))
        self.fail_once = False

    def delete(self, names):
        for name in list(names):
            self.rules.pop(name, None)

    def create(self, rules):
        for rule in rules:
            self.rules[rule['name']] = dict(copy.deepcopy(rule), normalized_path=NS['normalize_path'](rule.get('path')),
                                             is_global=rule.get('is_port', False) or not rule.get('path'),
                                             is_hold=False)
            if self.fail_once:
                self.fail_once = False
                raise RuntimeError('Simulated partial native creation failure')

