"""Application composition, main window construction, startup and UI event loop."""

import ctypes
import queue
import socket
import threading
import time
import tkinter as tk
from collections import deque
from ctypes import wintypes
from tkinter import font as tkfont, messagebox, ttk

from auto_block import AutoBlockMixin
from constants import (
    DEFAULT_CHECK_UPDATES_ON_STARTUP,
    DEFAULT_DARK_MODE,
    DEFAULT_LOG_ALERTS_ONLY,
    DEFAULT_MAX_CONNECTIONS_ALERTS,
    DEFAULT_RATE_THRESHOLD,
    DEFAULT_RATE_WINDOW,
    DEFAULT_UPLOAD_THRESHOLD_MB,
    DNS_MAX_PENDING,
    GLOBAL_PURPLE,
)
from firewall import FirewallMixin
from helpers import error_details, log_internal_error, mb
from monitoring import MonitoringMixin
from settings import SettingsMixin
from tray import PyFirewallSystemTray
from updates import UpdatesMixin
from views import ViewsMixin
from widgets import WidgetsMixin, add_tooltip

class FirewallMonitorApp(
    WidgetsMixin, SettingsMixin, FirewallMixin, MonitoringMixin,
    AutoBlockMixin, ViewsMixin, UpdatesMixin,
):
    """Owns shared application state; feature mixins use the same locks and queues."""
    MONITOR_COLUMNS = ('#', 'Process Name', 'Status', 'Direction', 'Remote IP', 'Remote Host', 'Protocol', 'Remote Port', 'Local Port', 'Download (MB)', 'Upload (MB)', 'Signal', 'PID', 'Exe Path')
    RULE_COLUMNS = ('Status', 'Application & Global Rules', 'Direction', 'Remote Port', 'Local Port', 'Protocol', 'Download (MB)', 'Upload (MB)', 'Program Path')
    ALERT_COLUMNS = ('Time', 'Severity', 'Process', 'PID', 'Remote IP', 'Remote Host', 'Reason')
    DEFAULT_COLUMN_ORDERS = {'monitor': MONITOR_COLUMNS, 'rules': RULE_COLUMNS, 'alerts': ALERT_COLUMNS}


    # Shared state and initialization

    def __init__(self, root, activation_port=None):
        self.root = root
        root.title('Python Personal Firewall & Network Monitor')
        root.geometry('1800x900')
        root.minsize(1500, 750)
        self.lock = threading.RLock()
        self.firewall_lock = threading.RLock()
        self.dns_lock = threading.Lock()
        self.settings_io_lock = threading.Lock()
        self.settings_change_lock = threading.Lock()
        self.settings_change_worker_running = False
        self.settings_change_pending = False
        self.settings_change_release_holds = False
        self.settings_change_generation = 0
        self.ui_queue = queue.Queue()
        self.prompt_queue = queue.Queue()
        self.alert_queue = queue.Queue()
        self.tray_command_queue = queue.Queue()
        self.instance_activation_port = activation_port
        self.instance_activation_socket = None
        self.instance_activation_stop = threading.Event()
        self.tray = None
        self.tray_hidden = False
        self.sniffing = self.closed = self.is_paused = False
        self.startup_complete = self.startup_running = False
        self.update_check_running = False
        self.update_check_manual = False
        self.update_dialog = None
        self.active_connections = {}
        self.next_connection_number = 1
        self.connection_rates = {}
        self.selection_anchors = {}
        self.default_column_orders = self.DEFAULT_COLUMN_ORDERS
        self.column_orders = {key: list(order) for key, order in self.default_column_orders.items()}
        self.hidden_columns = {}
        self.column_widths = {}
        self.window_size = None
        self.window_position = None
        self.window_maximized = False
        self.rule_editor_dialog = None
        self.header_drag = {}
        self.proc_traffic = {}
        self.ip_traffic = {}
        self.pruned_target_traffic = {}
        self.global_port_traffic = {}
        self.proc_ip_upload = {}
        self.ip_traffic_last_seen = {}
        self.proc_ip_upload_last_seen = {}
        self.last_traffic_prune = time.monotonic()
        self.upload_alerted = set()
        self.total_download = self.total_upload = 0
        self.captured_packets = self.captured_bytes = 0
        self._last_capture_bytes = self._last_capture_packets = 0
        self._last_status_time = time.monotonic()
        self.capture_rate = self.capture_pps = 0.0
        self.allowed_apps = set()
        self.blocked_paths = {}
        self.global_blocks = {}
        self.global_allows = {}
        self.global_ports = {}
        self.rule_rows = []
        self.rules_loading = False
        self.rules_generation = 0
        self.rules_refresh_worker_running = False
        self.rules_refresh_pending = False
        self.pending_rules = []
        self.alerts = deque(maxlen=DEFAULT_MAX_CONNECTIONS_ALERTS)
        self.alert_connections = {}
        self.next_alert_id = 1
        self.auto_prompt_keys = set()
        self.auto_prompt_active = False
        self.auto_prompt_dialog = None
        self.auto_prompt_key = None
        self.auto_prompt_generation = 0
        self.firewall_profile_modified = False
        self.settings_save_error = None
        self.dns_cache = {}
        self.dns_cache_times = {}
        self.dns_observed_names = {}
        self.dns_pending = set()
        self.dns_queue = queue.Queue(maxsize=DNS_MAX_PENDING)
        self.dns_stop_event = threading.Event()
        self.dns_workers = []
        self._start_dns_workers()
        self.socket_process_cache = {}
        self.listener_process_cache = {}
        self.cache_time = 0.0
        self.local_addresses = set()
        self.capture_error = None
        self.capture_healthy = False
        self.capture_interface = None
        self.filter_all_enabled = True
        self.filter_all_saved_alerts = None
        self.filter_all_saved_auto_block = None
        self.saved_rate_threshold = DEFAULT_RATE_THRESHOLD
        self.rate_threshold = 1 if self.filter_all_enabled else DEFAULT_RATE_THRESHOLD
        self.rate_window = DEFAULT_RATE_WINDOW
        self.upload_threshold_mb = DEFAULT_UPLOAD_THRESHOLD_MB
        self.max_connections_alerts = DEFAULT_MAX_CONNECTIONS_ALERTS
        self.log_alerts_only = DEFAULT_LOG_ALERTS_ONLY
        self.auto_block_enabled = True
        self.keep_notification_foreground = True
        self.dark_mode = DEFAULT_DARK_MODE
        self.check_updates_on_startup = DEFAULT_CHECK_UPDATES_ON_STARTUP
        self.firewall_initialized = False
        self.rate_threshold_var = tk.StringVar(value=str(self.rate_threshold))
        self.rate_window_var = tk.StringVar(value=str(DEFAULT_RATE_WINDOW))
        self.upload_threshold_var = tk.StringVar(value=str(DEFAULT_UPLOAD_THRESHOLD_MB))
        self.max_connections_alerts_var = tk.StringVar(value=str(DEFAULT_MAX_CONNECTIONS_ALERTS))
        self.log_alerts_var = tk.BooleanVar(value=DEFAULT_LOG_ALERTS_ONLY)
        self.auto_block_var = tk.BooleanVar(value=True)
        self.keep_notification_foreground_var = tk.BooleanVar(value=True)
        self.dark_mode_var = tk.BooleanVar(value=DEFAULT_DARK_MODE)
        self.check_updates_on_startup_var = tk.BooleanVar(value=DEFAULT_CHECK_UPDATES_ON_STARTUP)
        self.search_var = tk.StringVar()
        self.rule_search_var = tk.StringVar()
        self.alert_search_var = tk.StringVar()
        self.monitor_sort = ['#', True]
        self.rule_sort = [None, False]
        self.alert_sort = ['Time', True]
        self.load_settings()
        self.setup_gui()
        self._fit_initial_window()
        self.root.bind('<Configure>', self._remember_window_size, add='+')
        self.root.protocol('WM_DELETE_WINDOW', self.minimize_to_tray)
        try:
            self.tray = PyFirewallSystemTray(self.tray_command_queue, filter_all_enabled=self.filter_all_enabled, is_paused=self.is_paused)
        except Exception:
            self.tray = None
        self._start_instance_activation_listener()
        self.root.after(50, self._start_background_initialization)
        self.root.after(100, self.update_loop)

    def _start_instance_activation_listener(self):
        """Receive a second launch request without calling Tk off the UI thread."""
        if self.instance_activation_port is None:
            return
        try:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('127.0.0.1', self.instance_activation_port))
            listener.listen(1)
            listener.settimeout(0.25)
        except OSError as exc:
            log_internal_error('instance_activation_listener', exc)
            return
        self.instance_activation_socket = listener
        threading.Thread(target=self._run_instance_activation_listener,
                         name='PyFirewall-Activation', daemon=True).start()

    def _run_instance_activation_listener(self):
        listener = self.instance_activation_socket
        while listener is not None and not self.instance_activation_stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self._handle_instance_activation(connection)

    def _handle_instance_activation(self, connection):
        try:
            with connection:
                if connection.recv(16) == b'SHOW':
                    self.tray_command_queue.put('show')
        except OSError:
            pass

    def _stop_instance_activation_listener(self):
        stop = getattr(self, 'instance_activation_stop', None)
        if stop is not None:
            stop.set()
        listener = getattr(self, 'instance_activation_socket', None)
        self.instance_activation_socket = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass

    # Main window and toolbar

    def setup_gui(self):
        self.apply_theme()
        self.setup_status_bar()
        self.main_area = tk.Frame(self.root, bg=self.colors['bg'])
        self.main_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 6))
        self.top_controls = tk.Frame(self.root, bg=self.colors['bg'])
        self.notebook = ttk.Notebook(self.main_area)
        self.notebook.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tabs = (('tab_monitor', 'Live Monitor'), ('tab_rules', 'Managed Rules'), ('tab_alerts', 'Alerts'), ('tab_settings', 'Settings'))
        for attr, title in tabs:
            tab = ttk.Frame(self.notebook)
            setattr(self, attr, tab)
            self.notebook.add(tab, text=title)
        self.setup_monitor_tab()
        self.setup_rules_tab()
        self.setup_alerts_tab()
        self.setup_settings_tab()
        self._make_monitor_controls(self.top_controls)
        self.chk_dark_top = tk.Checkbutton(self.top_controls, text='Dark Theme', variable=self.dark_mode_var, command=self.on_theme_changed, bg=self.colors['bg'], fg=self.colors['fg'], activebackground=self.colors['bg'], activeforeground=self.colors['fg'], selectcolor=self.colors['entry'], font=('Segoe UI', 9, 'bold'), relief=tk.FLAT, bd=0, highlightthickness=0)
        self.chk_dark_top.pack(side=tk.LEFT, padx=(10, 0))
        add_tooltip(self.chk_dark_top, 'Toggle the application dark theme. This stays synchronized with Settings > Appearance.')
        self.update_filter_ui()
        self.top_controls.update_idletasks()
        self.root.after_idle(self._position_top_controls)
        self.main_area.bind('<Configure>', self._position_top_controls, add='+')
        for tree in (self.tree, self.rules_tree, self.alerts_tree):
            self._bind_tree_selection(tree)
        self.tree.bind('<Button-3>', lambda e: self.show_connection_menu(e, self.tree))
        self.rules_tree.bind('<Button-3>', self.show_rules_menu)
        self.alerts_tree.bind('<Button-3>', self.show_alert_menu)
        self.alerts_tree.bind('<Double-1>', self.alert_details_from_event)
        self.root.bind('<F5>', self._on_f5)
        self.root.bind_all('<Delete>', self._on_global_delete_key, add='+')
        self.root.bind_all('<KP_Delete>', self._on_global_delete_key, add='+')
        self.apply_theme()

    def _make_monitor_controls(self, parent, prefix='', stacked=False):
        """Build identical controls in the header and Settings from one definition."""
        filter_border = self._button(parent, 'Filter All Connections OFF', self.toggle_filter_all, '#9E9E9E', pack=False, font=('Segoe UI', 10, 'bold'), padx=10, pady=2, tooltip=lambda: 'Filter All Connections is locked while monitoring is paused.' if self.is_paused else 'Force the Max Connections Threshold to 1 and inspect every new connection. Filter All Connections also enables and locks Alerts + Auto-Block Protection.')
        btn_filter = filter_border.winfo_children()[0]
        pause_border = self._button(parent, '⏸  Pause Monitoring', self.toggle_pause, '#2196F3', pack=False, font=('Segoe UI', 10, 'bold'), padx=10, pady=2, tooltip=lambda: 'Resume live packet capture and monitoring' if self.is_paused or self.capture_error is not None else 'Pause live packet capture and monitoring')
        btn_pause = pause_border.winfo_children()[0]
        if stacked:
            pause_border.grid(row=0, column=0, sticky=tk.E, pady=(0, 12))
            filter_border.grid(row=1, column=0, sticky=tk.E)
        else:
            pause_border.pack(side=tk.LEFT, padx=(0, 4))
            filter_border.pack(side=tk.LEFT)
        for name, widget in (('filter_border', filter_border), ('btn_filter', btn_filter),
                             ('pause_border', pause_border), ('btn_pause', btn_pause)):
            setattr(self, prefix + name, widget)

    def _fit_initial_window(self):
        """Size the first window from Settings content, including DPI-scaled fonts."""
        saved_size = self.window_size
        saved_position = self.window_position
        maximized = self.window_maximized
        self.root.update_idletasks()
        content = self.settings_canvas.winfo_children()[0]
        # Include every section (and bottom padding) at the current font/DPI.
        # Scrolling remains available only when the screen cannot fit it all.
        self.settings_canvas.configure(height=content.winfo_reqheight() + 16)
        self.root.update_idletasks()
        width = max(1800, self.root.winfo_reqwidth())
        height = max(900, self.root.winfo_reqheight())
        if saved_size:
            width, height = saved_size
        work_area = wintypes.RECT()
        if ctypes.windll.user32.SystemParametersInfoW(48, 0, ctypes.byref(work_area), 0):
            # Leave room for the taskbar, title bar, and resize borders.
            user32 = ctypes.windll.user32
            frame_x = user32.GetSystemMetrics(32) + user32.GetSystemMetrics(92)
            frame_y = user32.GetSystemMetrics(33) + user32.GetSystemMetrics(92)
            width = min(width, work_area.right - work_area.left - 2 * frame_x)
            height = min(height, work_area.bottom - work_area.top
                         - user32.GetSystemMetrics(4) - 2 * frame_y)
        self.root.minsize(min(1500, width), min(750, height))
        # Keep left/top anchoring even for negative coordinates on other monitors.
        position = f'+{saved_position[0]}+{saved_position[1]}' if saved_position else ''
        self.root.geometry(f'{width}x{height}{position}')
        self.root.state('zoomed' if maximized else 'normal')

    def _remember_window_size(self, event=None):
        if event is not None and event.widget is not self.root:
            return
        state = self.root.state()
        if state not in {'normal', 'zoomed'}:
            return
        with self.lock:
            self.window_maximized = state == 'zoomed'
            if state == 'normal':
                width, height = self.root.winfo_width(), self.root.winfo_height()
                if width > 1 and height > 1:
                    self.window_size = [width, height]
                    self.window_position = [self.root.winfo_x(), self.root.winfo_y()]

    def _capture_layout(self):
        """Read Tk on the UI thread before hiding or destroying the window."""
        self._remember_window_size()
        widths = {}
        for name in ('tree', 'rules_tree', 'alerts_tree'):
            tree = getattr(self, name, None)
            if tree is None:
                continue
            saved = {}
            for column in tree['columns']:
                width = tree.column(column, 'width')
                if column == tree._fill_column and width == tree._fill_width:
                    width = tree._fill_base_width
                saved[column] = width
            widths[tree._column_order_key] = saved
        with self.lock:
            self.column_widths = widths

    def _on_f5(self, _event=None):
        if hasattr(self, 'notebook') and self.notebook.select() == str(self.tab_rules):
            self.refresh_rules(force=True)
            return 'break'

    def _position_top_controls(self, _event=None):
        if not hasattr(self, 'notebook') or not hasattr(self, 'top_controls'):
            return
        try:
            self.notebook.update_idletasks()
            self.top_controls.update_idletasks()
            self.root.update_idletasks()
            tabs = self.notebook.tabs()
            if not tabs:
                return
            last_index = len(tabs) - 1
            notebook_width = self.notebook.winfo_width()
            notebook_height = self.notebook.winfo_height()
            if notebook_width <= 0 or notebook_height <= 0:
                self.root.after(50, self._position_top_controls)
                return
            tab_y = None
            last_tab_start_x = None
            for y in range(2, min(notebook_height, 40), 2):
                found_x = None
                for x in range(0, notebook_width, 4):
                    try:
                        index = self.notebook.index(f'@{x},{y}')
                    except tk.TclError:
                        continue
                    if index == last_index:
                        found_x = x
                        break
                if found_x is not None:
                    tab_y = y
                    last_tab_start_x = found_x
                    break
            if tab_y is None or last_tab_start_x is None:
                self.root.after(50, self._position_top_controls)
                return
            tab_right = last_tab_start_x
            for x in range(last_tab_start_x, notebook_width):
                try:
                    index = self.notebook.index(f'@{x},{tab_y}')
                except tk.TclError:
                    break
                if index != last_index:
                    break
                tab_right = x + 1
            probe_x = max(last_tab_start_x, tab_right - 2)
            tab_top = tab_y
            tab_bottom = tab_y
            for y in range(0, min(notebook_height, 50)):
                try:
                    index = self.notebook.index(f'@{probe_x},{y}')
                except tk.TclError:
                    continue
                if index == last_index:
                    tab_top = y
                    break
            for y in range(tab_top, min(notebook_height, 50)):
                try:
                    index = self.notebook.index(f'@{probe_x},{y}')
                except tk.TclError:
                    break
                if index != last_index:
                    break
                tab_bottom = y + 1
            controls_h = self.top_controls.winfo_reqheight()
            gap = 10
            tab_root_x = self.notebook.winfo_rootx()
            tab_root_y = self.notebook.winfo_rooty()
            root_x = tab_root_x + tab_right + gap
            tab_height = max(1, tab_bottom - tab_top)
            root_y = tab_root_y + tab_top + max(0, (tab_height - controls_h) // 2)
            x = root_x - self.root.winfo_rootx()
            y = root_y - self.root.winfo_rooty()
            self.top_controls.place(x=x, y=y, anchor=tk.NW)
            self.top_controls.lift()
        except tk.TclError:
            pass

    def _on_rules_delete(self, _event=None):
        if not hasattr(self, 'rules_tree') or not self.rules_tree.selection():
            return 'break'
        try:
            self.rules_tree.focus_force()
        except tk.TclError:
            self.rules_tree.focus_set()
        self.remove_selected_rule()
        return 'break'

    def _on_global_delete_key(self, _event=None):
        if not hasattr(self, 'rules_tree'):
            return
        try:
            focused = self.root.focus_get()
        except tk.TclError:
            focused = None
        if focused is self.rules_tree:
            return self._on_rules_delete(_event)

    # Tab construction

    def _monitor_widths(self):
        return {'#': (55, tk.CENTER, False), 'Status': (105, tk.CENTER, False), 'PID': (70, tk.CENTER, False), 'Protocol': (70, tk.CENTER, False), 'Local Port': (85, tk.CENTER, False), 'Remote Port': (85, tk.CENTER, False), 'Direction': (85, tk.CENTER, False), 'Process Name': (150, tk.W, True), 'Remote IP': (125, tk.CENTER, True), 'Remote Host': (190, tk.W, True), 'Download (MB)': (110, tk.CENTER, False), 'Upload (MB)': (110, tk.CENTER, False), 'Signal': (70, tk.W, True), 'Exe Path': (300, tk.W, True)}

    def _setup_search(self, bar, variable, render):
        variable.trace_add('write', lambda *_: render())
        # Reserve the same right-hand space before laying out toolbar actions.
        first_action = bar.pack_slaves()[0]
        ttk.Entry(bar, textvariable=variable, width=25).pack(side=tk.RIGHT, padx=5, before=first_action)
        tk.Label(bar, text='Search:').pack(side=tk.RIGHT, before=first_action)

    def setup_monitor_tab(self):
        bar = tk.Frame(self.tab_monitor, pady=8)
        bar.pack(fill=tk.X)
        self._button(bar, 'Add Rule', self.add_monitor_rule, '#2196F3',
                     tooltip='Create an application or global rule, using the selected connections when available.')
        self._button(bar, 'Allow Selected', self.allow_process, '#4CAF50')
        self._button(bar, 'Block (in) Selected', lambda: self.block_process(direction='in'), '#ff9800',
                     tooltip='Block incoming connections for the selected processes.')
        self._button(bar, 'Block Selected', self.block_process, '#c62828')
        self._button(bar, 'Export CSV', self.export_connections)
        self._button(bar, 'Clear List', self.clear_list)
        self._setup_search(bar, self.search_var, self.render_monitor)
        self.tree = self._make_tree(self.tab_monitor, self.MONITOR_COLUMNS, self._monitor_widths(), 'monitor')
        self.tree.bind('<Double-1>', lambda e: self.tree_details_from_event(e, self.tree))

    def setup_rules_tab(self):
        bar = tk.Frame(self.tab_rules, pady=8)
        bar.pack(fill=tk.X)
        self._button(bar, 'Refresh Rules', self.refresh_rules, '#2196F3')
        self._button(bar, 'Add App Rule', self.add_custom_rule, '#ff9800')
        self._button(bar, 'Add Global Rule', self.add_global_rule_dialog, GLOBAL_PURPLE, dark_color_key='global_rule_button')
        self._button(bar, 'Remove Selected', self.remove_selected_rule, '#c62828')
        self._button(bar, 'Export Rules', self.export_rules)
        self._button(bar, 'Import Rules', self.import_rules)
        self._button(bar, 'Windows Firewall', self.open_windows_firewall)
        self._setup_search(bar, self.rule_search_var, self.render_rules)
        status_width = max(155, tkfont.nametofont('TkDefaultFont').measure('Blocked (in) (Global)') + 28)
        self.rules_tree = self._make_tree(self.tab_rules, self.RULE_COLUMNS, {'Status': (status_width, tk.CENTER, False), 'Application & Global Rules': (220, tk.W, True), 'Direction': (90, tk.CENTER, False), 'Remote Port': (100, tk.CENTER, False), 'Local Port': (100, tk.CENTER, False), 'Protocol': (90, tk.CENTER, False), 'Download (MB)': (105, tk.CENTER, False), 'Upload (MB)': (105, tk.CENTER, False), 'Program Path': (450, tk.W, True)}, 'rules')
        self.rules_tree.bind('<Double-1>', lambda e: self.rule_details_from_event(e))
        self.rules_tree.bind('<Delete>', self._on_rules_delete, add='+')
        self.rules_tree.bind('<KP_Delete>', self._on_rules_delete, add='+')

    def setup_alerts_tab(self):
        bar = tk.Frame(self.tab_alerts, pady=8)
        bar.pack(fill=tk.X)
        tk.Label(bar, text='Port watches are context signals, not proof of malicious activity.').pack(side=tk.LEFT, padx=5)
        self._button(bar, 'Clear Alerts', self.clear_alerts)
        self._setup_search(bar, self.alert_search_var, self.render_alerts)
        self.alerts_tree = self._make_tree(self.tab_alerts, self.ALERT_COLUMNS, {'Time': (85, tk.CENTER, False), 'Severity': (90, tk.CENTER, False), 'Process': (170, tk.W, True), 'PID': (70, tk.CENTER, False), 'Remote IP': (170, tk.W, True), 'Remote Host': (180, tk.W, True), 'Reason': (480, tk.W, True)}, 'alerts')

    def setup_status_bar(self):
        bar = tk.Frame(self.root, pady=4, padx=10)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        specs = (('status_state', '● Monitoring', 15), ('status_firewall', 'Firewall: Protected', 25), ('status_connections', 'Connections: 0', 17), ('status_rules', 'Rules: 0', 12), ('status_capture', 'Capture: 0 KB/s • 0 pkt/s', 30), ('status_traffic', 'Total: 0.00 MB Down • 0.00 MB Up', None))
        for attr, text, width in specs:
            kwargs = {'text': text, 'anchor': tk.W}
            if width:
                kwargs['width'] = width
            widget = tk.Label(bar, **kwargs)
            if attr != 'status_state':
                widget._theme_foreground_key = 'text'
            setattr(self, attr, widget)
            widget.pack(side=tk.LEFT, padx=(0, 15))

    # Background startup and UI messages

    def _start_background_initialization(self):
        if self.closed or self.startup_running or self.startup_complete:
            return
        self.startup_running = True
        self.root.after_idle(self._update_startup_status)
        threading.Thread(target=self._background_initialization_worker, daemon=True, name='FirewallStartup').start()

    def _update_startup_status(self):
        if self.closed or not hasattr(self, 'status_firewall'):
            return
        if not self.startup_complete:
            self.status_firewall.config(text='Firewall: Initializing...')
            self.status_state.config(text='● Starting', fg='#ff9800')

    def _background_initialization_worker(self):
        try:
            ok, error = self.initialize_or_restore_firewall()
        except Exception as exc:
            log_internal_error('background_initialization', exc)
            ok, error = False, error_details(exc)
        if ok:
            try:
                self.sync_rule_cache()
            except Exception as exc:
                log_internal_error('startup_rule_cache', exc)
                ok = False
                error = error_details(exc)
                try:
                    with self.firewall_lock:
                        self._restore_firewall_profile_state_locked()
                except Exception as restore_error:
                    log_internal_error('startup_profile_restoration', restore_error)
                    error += f'; profile restoration failed: {error_details(restore_error)}'
        self.ui_queue.put(('startup_complete', ok, error))

    def drain_ui_queue(self):
        while True:
            try:
                item = self.ui_queue.get_nowait()
            except queue.Empty:
                return
            if item[0] == 'dns':
                continue
            if item[0] == 'update_check':
                self._finish_update_check(item[1])
                continue
            if item[0] == 'startup_complete':
                ok, error = (item[1], item[2])
                self.startup_running = False
                if self.closed:
                    continue
                if ok:
                    self.startup_complete = True
                    self.save_settings()
                    if self.closed:
                        continue
                    self.refresh_rules(force=True)
                    with self.lock:
                        self.sniffing = True
                    threading.Thread(target=self.start_sniffing, daemon=True, name='PacketCapture').start()
                    self.update_status()
                    if self.check_updates_on_startup:
                        self.check_for_updates(manual=False)
                else:
                    self.startup_complete = False
                    self.status_firewall.config(text='Firewall: Initialization failed')
                    self.status_state.config(text='● Startup failed', fg='#f44336')
                    messagebox.showerror('Windows Firewall Setup Failed', f'Could not initialize/restore PyFirewall rules.\n\n{error}', parent=self.root)
                continue
            if item[0] == 'rules':
                _, generation, blocked, allowed, blocks, allows = item
                self._finish_rule_refresh(generation, blocked, allowed, blocks, allows)
            elif item[0] == 'rules_error':
                generation, error = (item[1], item[2])
                if generation == self.rules_generation:
                    self.rules_loading = False
                    self.rules_tree.delete(*self.rules_tree.get_children())
                    self.rules_tree.insert('', tk.END, values=('Error', 'Firewall rule refresh failed', '', '', '', error), tags=('blocked',))

    # Status and periodic updates

    def update_status(self):
        if not hasattr(self, 'status_state'):
            return
        now = time.monotonic()
        with self.lock:
            bytes_now = self.captured_bytes
            packets_now = self.captured_packets
            connections = len(self.active_connections)
            rules = len(self.rule_rows)
            down = self.total_download
            up = self.total_upload
            paused = self.is_paused
            capture_healthy = self.capture_healthy
            capture_error = self.capture_error
        self.update_pause_button(paused or (not capture_healthy and capture_error is not None))
        elapsed = now - self._last_status_time
        if elapsed >= 0.5:
            self.capture_rate = max(0, bytes_now - self._last_capture_bytes) / elapsed
            self.capture_pps = max(0, packets_now - self._last_capture_packets) / elapsed
            self._last_capture_bytes = bytes_now
            self._last_capture_packets = packets_now
            self._last_status_time = now
        if not self.startup_complete:
            failed = not self.startup_running
            self.status_state.config(text='Startup failed' if failed else 'Starting', fg='#f44336' if failed else '#ff9800')
            self.status_firewall.config(text='Firewall: Initialization failed' if failed else 'Firewall: Initializing...')
        elif paused:
            self.status_state.config(text='Paused', fg='#ff9800')
            self.status_firewall.config(text='Firewall: Rules remain active')
        elif not capture_healthy:
            self.status_state.config(text='Capture failed' if capture_error is not None else 'Starting capture', fg='#f44336')
            self.status_firewall.config(text='Firewall: Rules active; Auto-Block unavailable')
        else:
            self.status_state.config(text='Monitoring', fg='#4CAF50')
            self.status_firewall.config(text='Firewall: Protected')
        self.status_connections.config(text=f'Connections: {connections:,}')
        self.status_rules.config(text=f'Rules: {rules:,}')
        speed = f'{self.capture_rate / (1024 * 1024):.2f} MB/s' if self.capture_rate >= 1024 * 1024 else f'{self.capture_rate / 1024:.1f} KB/s'
        self.status_capture.config(text=f'Capture: {speed} • {self.capture_pps:.0f} pkt/s')
        self.status_traffic.config(text=f'Total: {mb(down)} Down • {mb(up)} Up')

    def update_loop(self):
        if self.closed:
            return
        try:
            while True:
                try:
                    command = self.tray_command_queue.get_nowait()
                except queue.Empty:
                    break
                if command == 'show':
                    self.show_from_tray()
                elif command == 'settings':
                    self.show_settings_from_tray()
                elif command == 'toggle_filter_all':
                    self.toggle_filter_all()
                elif command == 'toggle_pause':
                    self.toggle_pause()
                elif command == 'close':
                    self.on_closing()
                    return
            self.drain_ui_queue()
            self.drain_alerts()
            self.drain_prompt_queue()
            if self.startup_complete and (not self.is_paused):
                self.render_monitor()
                self.render_rule_traffic()
                self.render_rules()
            self.update_status()
        except Exception as exc:
            log_internal_error('update_loop', exc)
        finally:
            if not self.closed:
                self.root.after(500, self.update_loop)

    def clear_list(self):
        with self.lock:
            self.active_connections.clear()
            self.next_connection_number = 1
            self.connection_rates.clear()
        self.tree.delete(*self.tree.get_children())

    # Tray visibility and shutdown

    def minimize_to_tray(self):
        if self.closed or self.tray_hidden:
            return
        try:
            self._capture_layout()
            self.tray_hidden = True
            self.root.withdraw()
        except tk.TclError:
            pass

    def show_from_tray(self):
        if self.closed:
            return
        try:
            self.tray_hidden = False
            self.root.deiconify()
            try:
                self.root.state('normal')
            except tk.TclError:
                pass
            self.root.lift()
            self.root.focus_force()
        except tk.TclError:
            pass

    def show_settings_from_tray(self):
        if self.closed:
            return
        self.show_from_tray()
        try:
            self.notebook.select(self.tab_settings)
            self.root.after_idle(self._position_top_controls)
        except tk.TclError:
            pass

    def on_closing(self):
        if self.closed:
            return
        self._capture_layout()
        with self.lock:
            self.closed = True
            self.sniffing = False
        self._stop_instance_activation_listener()
        shutdown_errors = []
        try:
            self.release_auto_holds()
        except Exception as exc:
            log_internal_error('shutdown_auto_holds', exc)
            shutdown_errors.append(f'Temporary block cleanup: {exc}')
        try:
            with self.firewall_lock:
                with self.lock:
                    profile_modified = self.firewall_profile_modified
                if profile_modified:
                    self._restore_firewall_profile_state_locked()
        except Exception as exc:
            log_internal_error('shutdown_profile_restoration', exc)
            shutdown_errors.append(f'Firewall profile restoration: {error_details(exc)}')
        if shutdown_errors:
            messagebox.showerror('Firewall Cleanup Failed', '\n'.join(shutdown_errors) + '\nAny unrestored profile backup is retained for recovery on the next launch.', parent=self.root)
        try:
            self.save_settings()
        finally:
            try:
                self.dns_stop_event.set()
            except Exception:
                pass
            try:
                if self.tray is not None:
                    self.tray.stop()
            except Exception:
                pass
            try:
                self.root.destroy()
            except tk.TclError:
                pass
