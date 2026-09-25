import sys
import os
import csv
import json
import time
import re
import socket
import ipaddress
import hashlib
import ctypes
from ctypes import wintypes
import queue
import subprocess
import threading
import traceback
from collections import deque
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
try:
    import psutil
    from scapy.all import sniff, IP, IPv6, TCP, UDP
except ImportError as exc:
    raise SystemExit(f'Missing dependency: {exc}. Install psutil, scapy, and Npcap first.')
DEFAULT_RATE_THRESHOLD = 50
DEFAULT_RATE_WINDOW = 5.0
DEFAULT_UPLOAD_THRESHOLD_MB = 50
DEFAULT_LOG_ALERTS_ONLY = True
DEFAULT_DARK_MODE = True
DEFAULT_MAX_CONNECTIONS_ALERTS = 250
CREATE_NO_WINDOW = 134217728
WATCH_PORTS = {23: 'Telnet', 445: 'SMB', 3389: 'RDP', 4444: 'Common remote-control port', 5555: 'Android Debug Bridge', 5900: 'VNC', 6667: 'IRC'}
GLOBAL_BLOCK_PREFIX = 'PyFirewall_GlobalIP_'
GLOBAL_ALLOW_PREFIX = 'PyFirewall_GlobalIPAllow_'
AUTO_HOLD_PREFIX = 'PyFirewall_AutoHold_'
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, 'firewall_config.json')
ICON_FILE = os.path.join(SCRIPT_DIR, 'PyFirewall.ico')
FIREWALL_PROFILE_BACKUP_FILE = os.path.join(SCRIPT_DIR, 'firewall_profile_backup.json')
DNS_MAX_WORKERS = 8
DNS_MAX_PENDING = 256
DNS_CACHE_MAX_ENTRIES = 2048
DNS_CACHE_TTL = 900.0
FIREWALL_COMMAND_TIMEOUT = 30.0
TRAFFIC_MAX_IP_ENTRIES = 8192
TRAFFIC_MAX_PROC_IP_ENTRIES = 16384
TRAFFIC_PRUNE_INTERVAL = 30.0
INTERNAL_ERROR_LOG_FILE = os.path.join(SCRIPT_DIR, 'firewall_monitor_errors.log')
INTERNAL_ERROR_LOG_LOCK = threading.Lock()


if os.name != 'nt':
    raise SystemExit('This application requires Windows.')
_MUTEX_HANDLE = None

def error_details(exc):
    details = [str(exc)]
    for field in ('stderr', 'stdout'):
        output = getattr(exc, field, None)
        if isinstance(output, bytes):
            output = output.decode('utf-8', errors='replace')
        if output and str(output).strip():
            details.append(f'{field}: {str(output).strip()}')
    return '\n'.join(details)

def log_internal_error(context, exc):
    try:
        with INTERNAL_ERROR_LOG_LOCK:
            with open(INTERNAL_ERROR_LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {context}: {type(exc).__name__}: {error_details(exc)}\n")
                traceback.print_exception(type(exc), exc, exc.__traceback__, file=f)
                f.write('\n')
    except Exception:
        pass

def hide_console():
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception:
        pass

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def elevate():
    if is_admin():
        return
    executable = sys.executable
    pythonw = os.path.join(os.path.dirname(sys.executable), 'pythonw.exe')
    if os.path.exists(pythonw):
        executable = pythonw
    try:
        result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', executable, subprocess.list2cmdline(sys.argv), None, 0)
        if result <= 32:
            raise OSError(f'ShellExecuteW returned {result}')
    except Exception:
        pass
    raise SystemExit

def acquire_single_instance():
    global _MUTEX_HANDLE
    name = 'Local\\PyFirewall_' + hashlib.sha1(os.path.normcase(os.path.abspath(__file__)).encode()).hexdigest()
    _MUTEX_HANDLE = ctypes.windll.kernel32.CreateMutexW(None, False, name)
    if not _MUTEX_HANDLE:
        return True
    if ctypes.windll.kernel32.GetLastError() == 183:
        ctypes.windll.user32.MessageBoxW(None, 'Python Personal Firewall & Network Monitor is already running.', 'Already Running', 48)
        return False
    return True
hide_console()
elevate()
if not acquire_single_instance():
    raise SystemExit

def normalize_path(path):
    if not path:
        return ''
    try:
        return os.path.normcase(os.path.normpath(str(path).replace('/', '\\')))
    except Exception:
        return str(path).lower()

def display_path(path):
    return os.path.normpath(str(path).replace('/', '\\')) if path else ''

def normalize_target(target):
    value = str(target or '').strip().strip('[]').casefold().rstrip('.')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value

def is_ip(target):
    try:
        ipaddress.ip_address(str(target).strip().strip('[]').split('/', 1)[0].split(' (', 1)[0])
        return True
    except ValueError:
        return False

def mb(value):
    return f'{value / (1024 * 1024):.2f} MB'

def direction_name(value):
    value = str(value or '').casefold()
    if value in {'in', 'inbound', 'incoming'}:
        return 'Inbound'
    if value in {'out', 'outbound', 'outgoing'}:
        return 'Outbound'
    return 'Both'

def direction_set(value):
    value = direction_name(value)
    return {'in'} if value == 'Inbound' else {'out'} if value == 'Outbound' else {'in', 'out'}

class ToolTip:

    def __init__(self, widget, text, delay=400):
        self.widget, self.text, self.delay = (widget, text, delay)
        self.tip = None
        self.after_id = None
        widget.bind('<Enter>', self._enter, add='+')
        widget.bind('<Leave>', self._leave, add='+')
        widget.bind('<ButtonPress>', self._leave, add='+')
        widget.bind('<Destroy>', self._leave, add='+')

    def _enter(self, _=None):
        self._cancel()
        self.after_id = self.widget.after(self.delay, self._show)

    def _leave(self, _=None):
        self._cancel()
        if self.tip:
            try:
                self.tip.destroy()
            except tk.TclError:
                pass
            self.tip = None

    def _cancel(self):
        if self.after_id:
            try:
                self.widget.after_cancel(self.after_id)
            except tk.TclError:
                pass
            self.after_id = None

    def _show(self):
        text = self.text() if callable(self.text) else self.text
        if self.tip or not str(text or '').strip():
            return
        try:
            x = self.widget.winfo_rootx() + 10
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
            tip = tk.Toplevel(self.widget)
            tip.wm_overrideredirect(True)
            tip.wm_geometry(f'+{x}+{y}')
            tip.configure(bg='#2b2b2b')
            tk.Label(tip, text=str(text), justify=tk.LEFT, bg='#2b2b2b', fg='#f0f0f0', relief='solid', borderwidth=1, font=('Segoe UI', 9), padx=8, pady=4).pack(ipadx=1)
            self.tip = tip
        except tk.TclError:
            pass

def add_tooltip(widget, text, delay=400):
    widget._tooltip = ToolTip(widget, text, delay)
    return widget._tooltip
BUTTON_TIPS = {'Block Selected': 'Choose how to block the selected application.', 'Allow Selected': 'Allow all traffic for the selected application.', 'Export CSV': 'Export the visible connection rows to a CSV file.', 'Clear List': 'Clear the Live Monitor connection list.', 'Refresh Rules': 'Refresh the Managed Rules list from Windows Firewall.', 'Add Custom Rule': 'Create an inbound or outbound application rule.', 'Allow Global IP': 'Allow an IP address or domain globally.', 'Block Global IP': 'Block an IP address or domain globally.', 'Remove Selected': 'Remove the selected managed firewall rule(s).', 'Remove Selected Rule': 'Remove the selected managed firewall rule(s).', 'Export Rules': 'Export managed rules to a JSON backup.', 'Import Rules': 'Import and apply managed rules from a JSON file.', 'Windows Firewall': 'Open Windows Defender Firewall.', 'Clear Alerts': 'Clear all entries from the Alerts list.', 'Apply Settings': 'Save and apply the monitoring thresholds and options.', 'Reset to Defaults': 'Reset saved settings and remove PyFirewall-managed rules.'}

class PyFirewallSystemTray:
    WM_TRAYICON = 1024 + 1
    WM_CLOSE = 16
    WM_DESTROY = 2
    WM_NULL = 0
    WM_RBUTTONUP = 517
    WM_LBUTTONDBLCLK = 515
    NIM_ADD = 0
    NIM_DELETE = 2
    NIF_MESSAGE = 1
    NIF_ICON = 2
    NIF_TIP = 4
    MF_STRING = 0
    MF_GRAYED = 1
    TPM_LEFTALIGN = 0
    TPM_BOTTOMALIGN = 32
    TPM_RETURNCMD = 256
    TPM_NONOTIFY = 128
    ID_SHOW = 1001
    ID_FILTER_ALL = 1002
    ID_PAUSE = 1003
    ID_SETTINGS = 1004
    ID_CLOSE = 1005
    SW_HIDE = 0

    class POINT(ctypes.Structure):
        _fields_ = [('x', wintypes.LONG), ('y', wintypes.LONG)]

    class WNDCLASSEXW(ctypes.Structure):
        _fields_ = [('cbSize', wintypes.UINT), ('style', wintypes.UINT), ('lpfnWndProc', ctypes.c_void_p), ('cbClsExtra', ctypes.c_int), ('cbWndExtra', ctypes.c_int), ('hInstance', wintypes.HINSTANCE), ('hIcon', wintypes.HICON), ('hCursor', ctypes.c_void_p), ('hbrBackground', wintypes.HBRUSH), ('lpszMenuName', wintypes.LPCWSTR), ('lpszClassName', wintypes.LPCWSTR), ('hIconSm', wintypes.HICON)]

    class NOTIFYICONDATAW(ctypes.Structure):
        _fields_ = [('cbSize', wintypes.DWORD), ('hWnd', wintypes.HWND), ('uID', wintypes.UINT), ('uFlags', wintypes.UINT), ('uCallbackMessage', wintypes.UINT), ('hIcon', wintypes.HICON), ('szTip', wintypes.WCHAR * 128), ('dwState', wintypes.DWORD), ('dwStateMask', wintypes.DWORD), ('szInfo', wintypes.WCHAR * 256), ('uVersion_or_Timeout', wintypes.UINT), ('szInfoTitle', wintypes.WCHAR * 64), ('dwInfoFlags', wintypes.DWORD), ('guidItem', ctypes.c_byte * 16), ('hBalloonIcon', wintypes.HICON)]
    WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

    def __init__(self, command_queue, filter_all_enabled=True, is_paused=False):
        self.command_queue = command_queue
        self.state_lock = threading.Lock()
        self.filter_all_enabled = bool(filter_all_enabled)
        self.is_paused = bool(is_paused)
        self.thread = None
        self.thread_id = None
        self.hwnd = None
        self.class_name = f'PyFirewallTray_{os.getpid()}_{id(self)}'
        self._wndproc = None
        self._hicon = None
        self._registered = False
        self._icon_added = False
        self._ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True, name='PyFirewallTray')
        self.thread.start()

    def _run(self):
        try:
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            self.thread_id = kernel32.GetCurrentThreadId()
            user32.RegisterClassExW.argtypes = [ctypes.POINTER(self.WNDCLASSEXW)]
            user32.RegisterClassExW.restype = wintypes.ATOM
            user32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID]
            user32.CreateWindowExW.restype = wintypes.HWND
            user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
            user32.DefWindowProcW.restype = ctypes.c_ssize_t
            user32.DestroyWindow.argtypes = [wintypes.HWND]
            user32.DestroyWindow.restype = wintypes.BOOL
            user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
            user32.ShowWindow.restype = wintypes.BOOL
            user32.LoadIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
            user32.LoadIconW.restype = wintypes.HICON
            user32.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT, ctypes.c_int, ctypes.c_int, wintypes.UINT]
            user32.LoadImageW.restype = wintypes.HICON
            user32.LoadCursorW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
            user32.LoadCursorW.restype = ctypes.c_void_p
            user32.DestroyIcon.argtypes = [wintypes.HICON]
            user32.DestroyIcon.restype = wintypes.BOOL
            user32.GetCursorPos.argtypes = [ctypes.POINTER(self.POINT)]
            user32.GetCursorPos.restype = wintypes.BOOL
            user32.CreatePopupMenu.argtypes = []
            user32.CreatePopupMenu.restype = wintypes.HMENU
            user32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR]
            user32.AppendMenuW.restype = wintypes.BOOL
            user32.DestroyMenu.argtypes = [wintypes.HMENU]
            user32.DestroyMenu.restype = wintypes.BOOL
            user32.SetForegroundWindow.argtypes = [wintypes.HWND]
            user32.SetForegroundWindow.restype = wintypes.BOOL
            user32.TrackPopupMenu.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.LPVOID]
            user32.TrackPopupMenu.restype = wintypes.UINT
            user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
            user32.PostMessageW.restype = wintypes.BOOL
            user32.PostThreadMessageW.argtypes = [wintypes.DWORD, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
            user32.PostThreadMessageW.restype = wintypes.BOOL
            shell32 = ctypes.windll.shell32
            shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(self.NOTIFYICONDATAW)]
            shell32.Shell_NotifyIconW.restype = wintypes.BOOL
            default_icon = ctypes.cast(ctypes.c_void_p(32512), wintypes.LPCWSTR)
            arrow_cursor = user32.LoadCursorW(None, default_icon)
            self._hicon = user32.LoadImageW(None, ICON_FILE, 1, 0, 0, 16 | 64)
            if not self._hicon:
                self._hicon = user32.LoadIconW(None, default_icon)
            if not self._hicon:
                raise OSError('Could not load a PyFirewall icon or the default Windows application icon')
            self._wndproc = self.WNDPROC(self._window_proc)
            wnd = self.WNDCLASSEXW()
            wnd.cbSize = ctypes.sizeof(self.WNDCLASSEXW)
            wnd.style = 0
            wnd.lpfnWndProc = ctypes.cast(self._wndproc, wintypes.LPVOID)
            wnd.cbClsExtra = 0
            wnd.cbWndExtra = 0
            wnd.hInstance = kernel32.GetModuleHandleW(None)
            wnd.hIcon = self._hicon
            wnd.hCursor = arrow_cursor
            wnd.hbrBackground = None
            wnd.lpszMenuName = None
            wnd.lpszClassName = self.class_name
            wnd.hIconSm = self._hicon
            atom = user32.RegisterClassExW(ctypes.byref(wnd))
            if not atom:
                raise OSError(f'RegisterClassExW failed with error {ctypes.get_last_error()}')
            self._registered = True
            self.hwnd = user32.CreateWindowExW(0, self.class_name, 'PyFirewall', 0, 0, 0, 0, 0, None, None, wnd.hInstance, None)
            if not self.hwnd:
                raise OSError(f'CreateWindowExW failed with error {ctypes.get_last_error()}')
            user32.ShowWindow(self.hwnd, self.SW_HIDE)
            nid = self.NOTIFYICONDATAW()
            nid.cbSize = ctypes.sizeof(self.NOTIFYICONDATAW)
            nid.hWnd = self.hwnd
            nid.uID = 1
            nid.uFlags = self.NIF_MESSAGE | self.NIF_ICON | self.NIF_TIP
            nid.uCallbackMessage = self.WM_TRAYICON
            nid.hIcon = self._hicon
            nid.szTip = 'PyFirewall'
            if not shell32.Shell_NotifyIconW(self.NIM_ADD, ctypes.byref(nid)):
                raise OSError(f'Shell_NotifyIconW(NIM_ADD) failed with error {ctypes.get_last_error()}')
            self._icon_added = True
            self._ready.set()
            msg = wintypes.MSG()
            while True:
                result = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if result == 0 or result == -1:
                    break
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        except Exception:
            self._ready.set()
        finally:
            try:
                if self._icon_added and self.hwnd:
                    nid = self.NOTIFYICONDATAW()
                    nid.cbSize = ctypes.sizeof(self.NOTIFYICONDATAW)
                    nid.hWnd = self.hwnd
                    nid.uID = 1
                    ctypes.windll.shell32.Shell_NotifyIconW(self.NIM_DELETE, ctypes.byref(nid))
                    self._icon_added = False
            except Exception:
                pass
            try:
                if self.hwnd:
                    ctypes.windll.user32.DestroyWindow(self.hwnd)
                    self.hwnd = None
            except Exception:
                pass
            try:
                if self._registered:
                    ctypes.windll.user32.UnregisterClassW(self.class_name, ctypes.windll.kernel32.GetModuleHandleW(None))
                    self._registered = False
            except Exception:
                pass
            try:
                if self._hicon:
                    ctypes.windll.user32.DestroyIcon(self._hicon)
                    self._hicon = None
            except Exception:
                pass

    def _window_proc(self, hwnd, msg, wparam, lparam):
        if msg == self.WM_TRAYICON:
            event = wintypes.UINT(lparam & 4294967295).value
            if event == self.WM_RBUTTONUP:
                self._show_context_menu(hwnd)
            elif event == self.WM_LBUTTONDBLCLK:
                self.command_queue.put('show')
            return 0
        if msg == self.WM_CLOSE:
            ctypes.windll.user32.DestroyWindow(hwnd)
            return 0
        if msg == self.WM_DESTROY:
            ctypes.windll.user32.PostQuitMessage(0)
            return 0
        return ctypes.windll.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def update_state(self, filter_all_enabled=None, is_paused=None):
        with self.state_lock:
            if filter_all_enabled is not None:
                self.filter_all_enabled = bool(filter_all_enabled)
            if is_paused is not None:
                self.is_paused = bool(is_paused)

    def _get_state(self):
        with self.state_lock:
            return (self.filter_all_enabled, self.is_paused)

    def _show_context_menu(self, hwnd):
        user32 = ctypes.windll.user32
        menu = user32.CreatePopupMenu()
        if not menu:
            return
        try:
            filter_all_enabled, is_paused = self._get_state()
            filter_command_flags = self.MF_STRING | (self.MF_GRAYED if is_paused else 0)
            filter_text = 'Disable Filter All Connections' if filter_all_enabled else 'Filter All Connections'
            pause_text = 'Resume Monitoring' if is_paused else 'Pause Monitoring'
            user32.AppendMenuW(menu, self.MF_STRING, self.ID_SHOW, 'Show PyFirewall')
            user32.AppendMenuW(menu, self.MF_STRING, self.ID_PAUSE, pause_text)
            user32.AppendMenuW(menu, filter_command_flags, self.ID_FILTER_ALL, filter_text)
            user32.AppendMenuW(menu, self.MF_STRING, self.ID_SETTINGS, 'Settings')
            user32.AppendMenuW(menu, self.MF_STRING, self.ID_CLOSE, 'Close')
            point = self.POINT()
            if not user32.GetCursorPos(ctypes.byref(point)):
                return
            user32.SetForegroundWindow(hwnd)
            command = user32.TrackPopupMenu(menu, self.TPM_LEFTALIGN | self.TPM_BOTTOMALIGN | self.TPM_RETURNCMD | self.TPM_NONOTIFY, point.x, point.y, 0, hwnd, None)
            user32.PostMessageW(hwnd, self.WM_NULL, 0, 0)
            if command == self.ID_SHOW:
                self.command_queue.put('show')
            elif command == self.ID_PAUSE:
                self.command_queue.put('toggle_pause')
            elif command == self.ID_FILTER_ALL:
                self.command_queue.put('toggle_filter_all')
            elif command == self.ID_SETTINGS:
                self.command_queue.put('settings')
            elif command == self.ID_CLOSE:
                self.command_queue.put('close')
        finally:
            user32.DestroyMenu(menu)

    def stop(self):
        hwnd = self.hwnd
        if hwnd:
            try:
                ctypes.windll.user32.PostMessageW(hwnd, self.WM_CLOSE, 0, 0)
            except Exception:
                pass
        elif self.thread and self.thread.is_alive() and self.thread_id:
            try:
                ctypes.windll.user32.PostThreadMessageW(self.thread_id, self.WM_CLOSE, 0, 0)
            except Exception:
                pass

class FirewallMonitorApp:
    MONITOR_COLUMNS = ('#', 'Process Name', 'Status', 'PID', 'Direction', 'Protocol', 'Local Port', 'Remote IP', 'Remote Host', 'Remote Port', 'Download (MB)', 'Upload (MB)', 'Signal', 'Exe Path')
    ACTIVE_COLUMNS = ('#', 'Process Name', 'PID', 'Direction', 'Protocol', 'Local Port', 'Remote IP', 'Remote Host', 'Remote Port', 'Download (MB)', 'Upload (MB)', 'Signal', 'Exe Path')
    RULE_COLUMNS = ('Status', 'Rule / Application', 'Direction', 'Download (MB)', 'Upload (MB)', 'Program Path')
    ALERT_COLUMNS = ('Time', 'Severity', 'Process', 'PID', 'Remote IP', 'Remote Host', 'Reason')
    DEFAULT_COLUMN_ORDERS = {'monitor': ('#', 'Process Name', 'Status', 'PID', 'Direction', 'Protocol', 'Local Port', 'Remote IP', 'Remote Host', 'Remote Port', 'Download (MB)', 'Upload (MB)', 'Exe Path', 'Signal'), 'active': ACTIVE_COLUMNS, 'rules': RULE_COLUMNS, 'alerts': ALERT_COLUMNS}

    def __init__(self, root):
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
        self.tray = None
        self.tray_hidden = False
        self.sniffing = self.closed = self.is_paused = False
        self.startup_complete = self.startup_running = False
        self.active_connections = {}
        self.next_connection_number = 1
        self.connection_rates = {}
        self.selection_anchors = {}
        self._active_drag_tree = None
        self._drag_indicator = None
        self.default_column_orders = self.DEFAULT_COLUMN_ORDERS
        self.column_orders = {key: list(order) for key, order in self.default_column_orders.items()}
        self.header_drag = {}
        self.proc_traffic = {}
        self.ip_traffic = {}
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
        self.rule_rows = []
        self.rules_loading = False
        self.rules_generation = 0
        self.rules_refresh_worker_running = False
        self.rules_refresh_pending = False
        self.pending_rules = []
        self.alerts = deque(maxlen=DEFAULT_MAX_CONNECTIONS_ALERTS)
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
        self.dark_mode = DEFAULT_DARK_MODE
        self.firewall_initialized = False
        self.rate_threshold_var = tk.StringVar(value=str(self.rate_threshold))
        self.rate_window_var = tk.StringVar(value=str(DEFAULT_RATE_WINDOW))
        self.upload_threshold_var = tk.StringVar(value=str(DEFAULT_UPLOAD_THRESHOLD_MB))
        self.max_connections_alerts_var = tk.StringVar(value=str(DEFAULT_MAX_CONNECTIONS_ALERTS))
        self.log_alerts_var = tk.BooleanVar(value=DEFAULT_LOG_ALERTS_ONLY)
        self.auto_block_var = tk.BooleanVar(value=True)
        self.dark_mode_var = tk.BooleanVar(value=DEFAULT_DARK_MODE)
        self.search_var = tk.StringVar()
        self.active_search_var = tk.StringVar()
        self.rule_search_var = tk.StringVar()
        self.alert_search_var = tk.StringVar()
        self.monitor_sort = ['#', True]
        self.active_sort = ['Process Name', False]
        self.rule_sort = [None, False]
        self.alert_sort = ['Time', True]
        self.load_settings()
        self.setup_gui()
        self.root.protocol('WM_DELETE_WINDOW', self.minimize_to_tray)
        try:
            self.tray = PyFirewallSystemTray(self.tray_command_queue, filter_all_enabled=self.filter_all_enabled, is_paused=self.is_paused)
        except Exception:
            self.tray = None
        self.root.after(50, self._start_background_initialization)
        self.root.after(100, self.update_loop)


    def load_settings(self):
        if not os.path.exists(CONFIG_FILE):
            return
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except Exception:
            return
        with self.lock:
            self.filter_all_enabled = bool(config.get('filter_all_enabled', True))
            self.saved_rate_threshold = max(1, int(config.get('saved_rate_threshold', config.get('rate_threshold', DEFAULT_RATE_THRESHOLD))))
            self.rate_threshold = 1 if self.filter_all_enabled else max(1, int(config.get('rate_threshold', self.saved_rate_threshold)))
            self.rate_window = max(0.1, float(config.get('rate_window', DEFAULT_RATE_WINDOW)))
            self.upload_threshold_mb = max(0.1, float(config.get('upload_threshold_mb', DEFAULT_UPLOAD_THRESHOLD_MB)))
            self.max_connections_alerts = max(1, int(config.get('max_connections_alerts', DEFAULT_MAX_CONNECTIONS_ALERTS)))
            self.alerts = deque(self.alerts, maxlen=self.max_connections_alerts)
            self.log_alerts_only = bool(config.get('log_alerts_only_enabled', DEFAULT_LOG_ALERTS_ONLY))
            self.auto_block_enabled = self.log_alerts_only and bool(config.get('auto_block_enabled', True))
            saved_filter_alerts = config.get('filter_all_saved_alerts')
            saved_filter_auto = config.get('filter_all_saved_auto_block')
            if self.filter_all_enabled:
                if isinstance(saved_filter_alerts, bool):
                    self.filter_all_saved_alerts = saved_filter_alerts
                else:
                    self.filter_all_saved_alerts = self.log_alerts_only
                if isinstance(saved_filter_auto, bool):
                    self.filter_all_saved_auto_block = self.filter_all_saved_alerts and saved_filter_auto
                else:
                    self.filter_all_saved_auto_block = self.filter_all_saved_alerts and self.auto_block_enabled
                self.log_alerts_only = True
                self.auto_block_enabled = True
            else:
                self.filter_all_saved_alerts = None
                self.filter_all_saved_auto_block = None
            self.dark_mode = bool(config.get('dark_mode', DEFAULT_DARK_MODE))
            self.firewall_initialized = bool(config.get('firewall_initialized', False))
            saved_column_orders = config.get('column_orders', {})
            if isinstance(saved_column_orders, dict):
                for key, default in self.default_column_orders.items():
                    saved = saved_column_orders.get(key)
                    if not isinstance(saved, (list, tuple)):
                        continue
                    valid = [column for column in saved if column in default]
                    if key == 'monitor' and 'Status' not in valid:
                        if 'Process Name' in valid:
                            valid.insert(valid.index('Process Name') + 1, 'Status')
                        else:
                            valid.append('Status')
                    valid.extend((column for column in default if column not in valid))
                    self.column_orders[key] = valid
            self.allowed_apps = {normalize_path(p) for p in config.get('allowed_apps', []) if normalize_path(p)}
            self.pending_rules = []
            self.blocked_paths = {}
            for rule in config.get('managed_rules', []) or []:
                if not isinstance(rule, dict) or not rule.get('path'):
                    continue
                if str(rule.get('action', 'Block')).casefold() == 'allow':
                    continue
                path = display_path(rule.get('path', ''))
                norm = normalize_path(path)
                if not norm or norm in self.allowed_apps:
                    continue
                direction = direction_name(rule.get('direction', 'Both'))
                self.pending_rules.append({'path': path, 'direction': direction})
                wanted = direction_set(direction)
                self.blocked_paths[norm] = {'in': 'in' in wanted, 'out': 'out' in wanted, 'path': path}
            for entry in config.get('global_ip_blocks', []) or []:
                target = normalize_target(entry.get('target', '') if isinstance(entry, dict) else entry)
                if target:
                    addresses = entry.get('addresses', []) if isinstance(entry, dict) else []
                    self.global_blocks[target] = {'addresses': tuple((str(a) for a in addresses if str(a).strip()))}
            for entry in config.get('global_ip_allows', []) or []:
                target = normalize_target(entry.get('target', '') if isinstance(entry, dict) else entry)
                if target and target not in self.global_blocks:
                    addresses = entry.get('addresses', []) if isinstance(entry, dict) else []
                    self.global_allows[target] = {'addresses': tuple((str(a) for a in addresses if str(a).strip()))}
        self.rate_threshold_var.set(str(self.rate_threshold))
        self.rate_window_var.set(str(self.rate_window))
        self.upload_threshold_var.set(str(self.upload_threshold_mb))
        self.max_connections_alerts_var.set(str(self.max_connections_alerts))
        self.log_alerts_var.set(self.log_alerts_only)
        self.auto_block_var.set(self.auto_block_enabled)
        self.dark_mode_var.set(self.dark_mode)

    @staticmethod
    def _direction_from_flags(data):
        return 'Both' if data['in'] and data['out'] else 'Inbound' if data['in'] else 'Outbound'

    def save_settings(self):
        temp = CONFIG_FILE + '.tmp'
        try:
            with self.settings_io_lock:
                with self.lock:
                    managed = [{'action': 'Allow', 'direction': 'Both', 'path': path} for path in sorted(self.allowed_apps)]
                    managed += [{'action': 'Block', 'direction': self._direction_from_flags(data), 'path': data.get('path', normalized)} for normalized, data in sorted(self.blocked_paths.items())]
                    config = {'filter_all_enabled': self.filter_all_enabled, 'filter_all_saved_alerts': self.filter_all_saved_alerts, 'filter_all_saved_auto_block': self.filter_all_saved_auto_block, 'saved_rate_threshold': self.saved_rate_threshold, 'rate_threshold': self.rate_threshold, 'rate_window': self.rate_window, 'upload_threshold_mb': self.upload_threshold_mb, 'max_connections_alerts': self.max_connections_alerts, 'log_alerts_only_enabled': self.log_alerts_only, 'auto_block_enabled': self.auto_block_enabled, 'allowed_apps': sorted(self.allowed_apps), 'managed_rules': managed, 'global_ip_blocks': [{'target': target, 'addresses': list(data.get('addresses', ()))} for target, data in sorted(self.global_blocks.items())], 'global_ip_allows': [{'target': target, 'addresses': list(data.get('addresses', ()))} for target, data in sorted(self.global_allows.items())], 'dark_mode': bool(self.dark_mode), 'firewall_initialized': self.firewall_initialized, 'column_orders': {key: list(order) for key, order in self.column_orders.items()}}
                with open(temp, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(temp, CONFIG_FILE)
            self.settings_save_error = None
            return True
        except (OSError, TypeError, ValueError) as exc:
            self.settings_save_error = str(exc)
            try:
                if os.path.exists(temp):
                    os.remove(temp)
            except OSError:
                pass
            return False

    def apply_theme(self):
        dark = self.dark_mode_var.get()
        self.colors = {'bg': '#181818' if dark else '#f2f2f2', 'frame': '#1e1e1e' if dark else '#f2f2f2', 'sub': '#242424' if dark else '#ffffff', 'fg': '#e8e8e8' if dark else '#333333', 'muted': '#a8a8a8' if dark else '#757575', 'entry': '#252526' if dark else '#ffffff', 'select': '#3b78c8' if dark else '#0078D7', 'head': '#2d2d30' if dark else '#e0e0e0', 'even': '#252526' if dark else '#f9f9f9', 'odd': '#1e1e1e' if dark else '#ffffff', 'blocked': '#8b1e1e' if dark else '#ffcaca', 'blocked_in': '#7a4b11' if dark else '#ffe0b2', 'global_block': '#5f2a7a' if dark else '#d1b3e6', 'global_allow': '#90CAF9', 'allowed': '#294f31' if dark else '#e3f5e7', 'watch': '#5b4a16' if dark else '#fff3cd'}
        self.root.configure(bg=self.colors['bg'])
        style = ttk.Style(self.root)
        try:
            style.theme_use('clam')
        except tk.TclError:
            pass
        style.configure('TFrame', background=self.colors['frame'])
        style.configure('TLabel', background=self.colors['frame'], foreground=self.colors['fg'])
        style.configure('TLabelframe', background=self.colors['sub'], foreground=self.colors['fg'], bordercolor=self.colors['blocked_in'])
        style.configure('TLabelframe.Label', background=self.colors['sub'], foreground=self.colors['fg'])
        style.configure('TNotebook', background=self.colors['bg'], borderwidth=0)
        style.configure('TNotebook.Tab', background=self.colors['head'], foreground=self.colors['fg'], font=('Segoe UI', 10, 'bold'), padding=[10, 5, 10, 5])
        style.map('TNotebook.Tab', background=[('selected', self.colors['frame']), ('active', self.colors['sub'])], foreground=[('selected', self.colors['fg']), ('active', self.colors['fg'])], padding=[('selected', [10, 8, 10, 4]), ('!selected', [10, 5, 10, 5])])
        style.configure('TCheckbutton', background=self.colors['frame'], foreground=self.colors['fg'])
        style.map('TCheckbutton', background=[('active', self.colors['frame'])], foreground=[('disabled', self.colors['muted']), ('active', self.colors['fg'])])
        style.configure('Treeview', background=self.colors['sub'], foreground=self.colors['fg'], fieldbackground=self.colors['sub'], rowheight=25)
        style.configure('Treeview.Heading', background=self.colors['head'], foreground=self.colors['fg'], font=('Segoe UI', 9, 'bold'))
        style.map('Treeview.Heading', background=[('active', '#d8d8d8'), ('pressed', '#c8c8c8')], foreground=[('active', '#000000'), ('pressed', '#000000')])
        style.map('Treeview', background=[('selected', self.colors['select'])], foreground=[('selected', '#ffffff')])
        style.configure('TEntry', fieldbackground=self.colors['entry'], foreground=self.colors['fg'])
        style.map('TEntry', fieldbackground=[('disabled', self.colors['head'])], foreground=[('disabled', self.colors['muted'])])

        def repaint(parent):
            for widget in parent.winfo_children():
                try:
                    if isinstance(widget, tk.LabelFrame):
                        widget.configure(bg=self.colors['frame'], fg=self.colors['fg'])
                    elif isinstance(widget, tk.Frame):
                        widget.configure(bg='#555555' if getattr(widget, '_button_border_frame', False) else self.colors['frame'])
                    elif isinstance(widget, tk.Label):
                        widget.configure(bg=self.colors['frame'], fg=self.colors['fg'])
                    elif isinstance(widget, tk.Entry):
                        widget.configure(bg=self.colors['entry'], fg=self.colors['fg'], insertbackground=self.colors['fg'])
                    elif isinstance(widget, tk.Checkbutton):
                        widget.configure(bg=self.colors['frame'], fg=self.colors['fg'], activebackground=self.colors['frame'], activeforeground=self.colors['fg'], selectcolor=self.colors['entry'])
                except tk.TclError:
                    pass
                repaint(widget)
        repaint(self.root)
        self.configure_tags()
        self.update_filter_ui()
        self.update_status()

    def configure_tags(self):
        for name in ('tree', 'active_tree', 'rules_tree', 'alerts_tree'):
            tree = getattr(self, name, None)
            if tree is None:
                continue
            for tag, key, fg in (('even', 'even', None), ('odd', 'odd', None), ('blocked', 'blocked', None), ('blocked_in', 'blocked_in', None), ('global_block', 'global_block', '#ffffff' if self.dark_mode_var.get() else self.colors['fg']), ('global_allow', 'global_allow', '#000000'), ('allowed', 'allowed', None), ('watch', 'watch', None)):
                tree.tag_configure(tag, background=self.colors[key], foreground=fg or self.colors['fg'])

    def on_theme_changed(self):
        with self.lock:
            self.dark_mode = bool(self.dark_mode_var.get())
        self.save_settings()
        self.apply_theme()

    def setup_gui(self):
        self.apply_theme()
        self.setup_status_bar()
        self.main_area = tk.Frame(self.root, bg=self.colors['bg'])
        self.main_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 6))
        self.top_controls = tk.Frame(self.root, bg=self.colors['bg'])
        self.notebook = ttk.Notebook(self.main_area)
        self.notebook.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tabs = (('tab_monitor', 'Live Monitor'), ('tab_rules', 'Managed Rules'), ('tab_active', 'Active'), ('tab_alerts', 'Alerts'), ('tab_settings', 'Settings'))
        for attr, title in tabs:
            tab = ttk.Frame(self.notebook)
            setattr(self, attr, tab)
            self.notebook.add(tab, text=title)
        self.setup_monitor_tab()
        self.setup_rules_tab()
        self.setup_active_tab()
        self.setup_alerts_tab()
        self.setup_settings_tab()
        self.filter_border = self._button(self.top_controls, 'Filter All Connections OFF', self.toggle_filter_all, '#9E9E9E', pack=False, font=('Segoe UI', 10, 'bold'), padx=10, pady=2, tooltip=lambda: 'Filter All Connections is locked while monitoring is paused.' if self.is_paused else 'Force the Max Connections Threshold to 1 and inspect every new connection. Filter All Connections also enables and locks Alerts + Auto-Block Protection.')
        self.btn_filter = self.filter_border.winfo_children()[0]
        self.filter_border.pack(side=tk.LEFT, padx=(0, 4))
        self.pause_border = self._button(self.top_controls, '⏸  Pause Monitoring', self.toggle_pause, '#2196F3', pack=False, font=('Segoe UI', 10, 'bold'), padx=10, pady=2, tooltip=lambda: 'Resume live packet capture and monitoring' if self.is_paused else 'Pause live packet capture and monitoring')
        self.btn_pause = self.pause_border.winfo_children()[0]
        self.pause_border.pack(side=tk.LEFT)
        self.chk_dark_top = tk.Checkbutton(self.top_controls, text='Dark Theme', variable=self.dark_mode_var, command=self.on_theme_changed, bg=self.colors['bg'], fg=self.colors['fg'], activebackground=self.colors['bg'], activeforeground=self.colors['fg'], selectcolor=self.colors['entry'], font=('Segoe UI', 9, 'bold'), relief=tk.FLAT, bd=0, highlightthickness=0)
        self.chk_dark_top.pack(side=tk.LEFT, padx=(10, 0))
        add_tooltip(self.chk_dark_top, 'Toggle the application dark theme. This stays synchronized with Settings > Appearance.')
        self.update_filter_ui()
        self.top_controls.update_idletasks()
        self.root.after_idle(self._position_top_controls)
        self.main_area.bind('<Configure>', self._position_top_controls, add='+')
        for tree in (self.tree, self.active_tree, self.rules_tree, self.alerts_tree):
            self._bind_tree_selection(tree)
        self.tree.bind('<Button-3>', lambda e: self.show_connection_menu(e, self.tree))
        self.active_tree.bind('<Button-3>', lambda e: self.show_connection_menu(e, self.active_tree))
        self.rules_tree.bind('<Button-3>', self.show_rules_menu)
        self.alerts_tree.bind('<Button-3>', self.show_alert_menu)
        self.alerts_tree.bind('<Double-1>', self.alert_details_from_event)
        self.root.bind('<F5>', self._on_f5)
        self.root.bind_all('<Delete>', self._on_global_delete_key, add='+')
        self.root.bind_all('<KP_Delete>', self._on_global_delete_key, add='+')
        self.apply_theme()

    def _on_f5(self, _event=None):
        if hasattr(self, 'notebook') and self.notebook.select() == str(self.tab_rules):
            self.refresh_rules(force=True)
            return 'break'

    @staticmethod
    def _hover_color(color):
        try:
            value = str(color).lstrip('#')
            if len(value) != 6:
                return str(color)
            red, green, blue = (int(value[index:index + 2], 16) for index in (0, 2, 4))
            return '#{:02x}{:02x}{:02x}'.format(max(0, int(red * 0.72)), max(0, int(green * 0.72)), max(0, int(blue * 0.72)))
        except (TypeError, ValueError):
            return str(color)

    @classmethod
    def _bind_button_hover(cls, button, border=None):
        if getattr(button, '_pyfirewall_hover_bound', False):
            return button
        button._pyfirewall_hover_bound = True

        def set_normal_state(bg=None, activebackground=None):
            try:
                if bg is not None:
                    button._pyfirewall_base_bg = bg
                if activebackground is not None:
                    button._pyfirewall_base_active_bg = activebackground
                else:
                    button._pyfirewall_base_active_bg = getattr(button, '_pyfirewall_base_bg', button.cget('bg'))
                if border is not None:
                    border._pyfirewall_base_bg = getattr(button, '_pyfirewall_base_bg', border.cget('bg'))
            except tk.TclError:
                pass

        set_normal_state(button.cget('bg'), button.cget('activebackground'))

        def enter(_event=None):
            try:
                if str(button.cget('state')) == str(tk.DISABLED):
                    button.configure(cursor='arrow')
                    return
                normal_bg = getattr(button, '_pyfirewall_base_bg', button.cget('bg'))
                hover = cls._hover_color(normal_bg)
                button.configure(bg=hover, activebackground=hover, cursor='hand2')
                if border is not None:
                    border.configure(bg=hover)
            except tk.TclError:
                pass

        def leave(_event=None):
            try:
                normal_bg = getattr(button, '_pyfirewall_base_bg', button.cget('bg'))
                normal_active_bg = getattr(button, '_pyfirewall_base_active_bg', normal_bg)
                button.configure(bg=normal_bg, activebackground=normal_active_bg, cursor='')
                if border is not None:
                    border.configure(bg=normal_bg)
            except tk.TclError:
                pass

        button.bind('<Enter>', enter, add='+')
        button.bind('<Leave>', leave, add='+')
        button._pyfirewall_set_normal_state = set_normal_state
        return button

    def _set_button_colors(self, button, border, color, fg='white', state=tk.NORMAL):
        if button is None:
            return
        try:
            button.configure(bg=color, activebackground=color, fg=fg, activeforeground=fg, state=state)
            setter = getattr(button, '_pyfirewall_set_normal_state', None)
            if callable(setter):
                setter(color, color)
            else:
                button._pyfirewall_base_bg = color
                button._pyfirewall_base_active_bg = color
            if border is not None:
                border.configure(bg=color)
                border._pyfirewall_base_bg = color
        except tk.TclError:
            pass

    def _button(self, parent, text, command, color=None, pack=True, tooltip=None, **options):
        color = color or '#757575'
        border = tk.Frame(parent, bg=color, bd=0, highlightthickness=0)
        border._button_border_frame = True
        settings = {'text': text, 'command': command, 'bg': color, 'fg': 'white', 'activebackground': color, 'activeforeground': 'white', 'relief': 'flat', 'borderwidth': 0, 'highlightthickness': 0, 'font': ('Segoe UI', 9, 'bold'), 'padx': 9}
        settings.update(options)
        button = tk.Button(border, **settings)
        self._bind_button_hover(button, border)
        button.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        if pack:
            border.pack(side=tk.LEFT, padx=4)
        add_tooltip(button, tooltip or BUTTON_TIPS.get(text, ''))
        return button if pack else border

    def _make_tree(self, parent, columns, widths, order_key):
        tree = ttk.Treeview(parent, columns=columns, show='headings', selectmode='extended')
        tree._column_order_key = order_key
        for column in columns:
            width, anchor, stretch = widths.get(column, (180, tk.W, True))
            tree.heading(column, text=column)
            tree.column(column, width=width, anchor=anchor, stretch=stretch)
        order = self._normalized_column_order(order_key, columns)
        tree['displaycolumns'] = tuple(order)
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree.bind('<Control-a>', self.select_all_rows)
        tree.bind('<Control-A>', self.select_all_rows)
        self._bind_tree_headers(tree)
        return tree

    def _normalized_column_order(self, order_key, columns=None):
        default = tuple(self.default_column_orders[order_key])
        available = set(columns or default)
        with self.lock:
            saved = list(self.column_orders.get(order_key, list(default)))
            result = [c for c in saved if c in available]
            result.extend((c for c in default if c in available and c not in result))
            if columns:
                result.extend((c for c in columns if c not in result))
            self.column_orders[order_key] = result
            return list(result)

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

    def _tree_column_from_x(self, tree, x):
        try:
            token = tree.identify_column(x)
            if not token.startswith('#'):
                return None
            index = int(token[1:]) - 1
            order = list(tree['displaycolumns'])
            if 0 <= index < len(order):
                return order[index]
        except (ValueError, tk.TclError):
            pass
        return None

    def _bind_tree_headers(self, tree):
        tree.bind('<Button-1>', self._tree_header_press, add='+')
        tree.bind('<B1-Motion>', self._tree_header_motion, add='+')
        tree.bind('<ButtonRelease-1>', self._tree_header_release, add='+')

    def _tree_header_press(self, event):
        tree = event.widget
        if not isinstance(tree, ttk.Treeview):
            return
        if tree.identify_region(event.x, event.y) != 'heading':
            return
        column = self._tree_column_from_x(tree, event.x)
        if not column:
            return 'break'
        self.header_drag[str(tree)] = {'column': column, 'start_x': event.x, 'dragging': False}
        tree.focus_set()
        return 'break'

    def _tree_header_motion(self, event):
        tree = event.widget
        if not isinstance(tree, ttk.Treeview):
            return
        state = self.header_drag.get(str(tree))
        if not state:
            return
        if abs(event.x - state['start_x']) >= 6:
            state['dragging'] = True
        if state['dragging']:
            tree.configure(cursor='hand2')
        return 'break'

    def _tree_header_release(self, event):
        tree = event.widget
        if not isinstance(tree, ttk.Treeview):
            return
        state = self.header_drag.pop(str(tree), None)
        if not state:
            return
        tree.configure(cursor='')
        if not state['dragging']:
            self.sort_tree(tree, state['column'])
            return 'break'
        source = state['column']
        order = list(tree['displaycolumns'])
        if source not in order:
            return 'break'
        target = self._tree_column_from_x(tree, event.x)
        if target and target in order and (target != source):
            source_index = order.index(source)
            target_index = order.index(target)
            order.pop(source_index)
            insert_at = target_index + 1 if target_index > source_index else target_index
            order.insert(insert_at, source)
            tree['displaycolumns'] = tuple(order)
            with self.lock:
                self.column_orders[tree._column_order_key] = list(order)
            self.save_settings()
        return 'break'

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

    def _bind_tree_selection(self, tree):
        tree.bind('<Button-1>', self._tree_selection_press, add='+')
        tree.bind('<B1-Motion>', self._tree_selection_drag, add='+')
        tree.bind('<ButtonRelease-1>', self._tree_selection_release, add='+')

    @staticmethod
    def _nearest_tree_row_for_y(tree, y):
        try:
            children = list(tree.get_children())
            if not children:
                return None
            first_box = tree.bbox(children[0])
            last_box = tree.bbox(children[-1])
            if first_box and y < first_box[1]:
                return children[0]
            if last_box and y >= last_box[1] + last_box[3]:
                return children[-1]
            best_iid = None
            best_distance = None
            for iid in children:
                box = tree.bbox(iid)
                if not box:
                    continue
                top, height = (box[1], box[3])
                center = top + height / 2
                distance = abs(y - center)
                if best_distance is None or distance < best_distance:
                    best_distance = distance
                    best_iid = iid
            return best_iid
        except tk.TclError:
            return None

    def _create_drag_indicator(self, tree, start_x, start_y):
        self._destroy_drag_indicator()
        try:
            indicator = tk.Toplevel(self.root)
            indicator.overrideredirect(True)
            indicator.attributes('-topmost', True)
            canvas = tk.Canvas(indicator, bg='#ffffff', highlightthickness=0, bd=0)
            canvas.pack(fill=tk.BOTH, expand=True)
            canvas.bind('<B1-Motion>', self._tree_selection_drag, add='+')
            canvas.bind('<ButtonRelease-1>', self._tree_selection_release, add='+')
            try:
                indicator.wm_attributes('-disabled', True)
            except tk.TclError:
                pass
            try:
                indicator.wm_attributes('-transparentcolor', '#ffffff')
            except tk.TclError:
                pass
            canvas.create_rectangle(1, 1, 2, 2, outline='#808080', dash=(2, 2), width=1, tags='rubberband')
            self._drag_indicator = indicator
            self._drag_indicator_canvas = canvas
            self._drag_indicator_start = (int(start_x), int(start_y))
            self._update_drag_indicator(start_x, start_y)
        except tk.TclError:
            self._drag_indicator = None
            self._drag_indicator_canvas = None

    def _update_drag_indicator(self, current_x, current_y):
        if not self._drag_indicator:
            return
        try:
            x1, y1 = self._drag_indicator_start
            x2, y2 = (int(current_x), int(current_y))
            left, right = sorted((x1, x2))
            top, bottom = sorted((y1, y2))
            width = max(2, right - left + 2)
            height = max(2, bottom - top + 2)
            self._drag_indicator.geometry(f'{width}x{height}+{left}+{top}')
            self._drag_indicator_canvas.delete('rubberband')
            self._drag_indicator_canvas.create_rectangle(1, 1, max(1, width - 2), max(1, height - 2), outline='#666666', dash=(2, 2), width=1, tags='rubberband')
            self._drag_indicator.update_idletasks()
        except tk.TclError:
            self._destroy_drag_indicator()

    def _destroy_drag_indicator(self):
        indicator = getattr(self, '_drag_indicator', None)
        if indicator:
            try:
                indicator.destroy()
            except tk.TclError:
                pass
        self._drag_indicator = None
        self._drag_indicator_canvas = None

    def _tree_selection_press(self, event):
        tree = event.widget
        if not isinstance(tree, ttk.Treeview):
            return
        region = tree.identify_region(event.x, event.y)
        if region in {'heading', 'separator'}:
            tree._drag_selection_state = None
            if self._active_drag_tree is tree:
                self._active_drag_tree = None
            self._destroy_drag_indicator()
            return
        children = list(tree.get_children())
        iid = tree.identify_row(event.y)
        started_on_blank = not iid or iid not in children
        if not children:
            tree._drag_selection_state = None
            return
        last_box = tree.bbox(children[-1])
        started_below_rows = bool(started_on_blank and last_box and (event.y >= last_box[1] + last_box[3]))
        if started_below_rows:
            tree.selection_remove(tree.selection())
            self.selection_anchors.pop(str(tree), None)
        if started_on_blank:
            start_iid = self._nearest_tree_row_for_y(tree, event.y)
            if not start_iid:
                tree._drag_selection_state = None
                if self._active_drag_tree is tree:
                    self._active_drag_tree = None
                return 'break' if started_below_rows else None
            tree._drag_selection_state = {'start_iid': start_iid, 'start_x': event.x, 'start_y': event.y, 'start_root_x': event.x_root, 'start_root_y': event.y_root, 'control': bool(event.state & 4), 'shift': bool(event.state & 1), 'dragging': False, 'started_on_blank': True, 'drag_base_selection': tuple(tree.selection())}
            self._active_drag_tree = tree
            return 'break' if started_below_rows else None
        anchor = self.selection_anchors.get(str(tree))
        shift = bool(event.state & 1)
        control = bool(event.state & 4)
        if shift and anchor in children:
            start = children.index(anchor)
            end = children.index(iid)
            lo, hi = sorted((start, end))
            range_iids = children[lo:hi + 1]
            if control:
                tree.selection_add(range_iids)
            else:
                tree.selection_set(range_iids)
        elif control:
            if iid in tree.selection():
                tree.selection_remove(iid)
            else:
                tree.selection_add(iid)
        else:
            tree.selection_set(iid)
        try:
            tree.focus_force()
        except tk.TclError:
            tree.focus_set()
        tree.focus(iid)
        self.selection_anchors[str(tree)] = iid
        tree._drag_selection_state = {'start_iid': iid, 'start_x': event.x, 'start_y': event.y, 'start_root_x': event.x_root, 'start_root_y': event.y_root, 'control': control, 'shift': shift, 'dragging': False, 'started_on_blank': False, 'drag_base_selection': tuple(tree.selection())}
        self._active_drag_tree = tree
        return 'break'

    def _tree_selection_drag(self, event):
        tree = event.widget
        if not isinstance(tree, ttk.Treeview):
            tree = self._active_drag_tree
            if not tree:
                return
            return self._perform_tree_selection_drag(tree, event.x_root, event.y_root, None, event)
        state = getattr(tree, '_drag_selection_state', None)
        if not state:
            return
        return self._perform_tree_selection_drag(tree, event.x_root, event.y_root, event.y, event)

    def _perform_tree_selection_drag(self, tree, root_x, root_y, local_y, event=None):
        state = getattr(tree, '_drag_selection_state', None)
        if not state:
            return
        if self.header_drag.get(str(tree)):
            return 'break'
        if event is not None and isinstance(event.widget, ttk.Treeview):
            region = tree.identify_region(event.x, event.y)
            if region in {'heading', 'separator'}:
                return 'break'
        delta = max(abs(int(root_x) - state['start_root_x']), abs(int(root_y) - state['start_root_y']))
        if not state['dragging'] and delta < 4:
            return
        state['dragging'] = True
        try:
            current_local_y = local_y
            if current_local_y is None:
                current_local_y = int(root_y) - tree.winfo_rooty()
            children = list(tree.get_children())
            start_iid = state['start_iid']
            if start_iid not in children or not children:
                return
            current_iid = tree.identify_row(current_local_y)
            if current_iid not in children:
                current_iid = self._nearest_tree_row_for_y(tree, current_local_y)
            if not current_iid:
                return
            start = children.index(start_iid)
            end = children.index(current_iid)
            lo, hi = sorted((start, end))
            range_iids = children[lo:hi + 1]
            if state['control']:
                tree.selection_set(state['drag_base_selection'])
                tree.selection_add(range_iids)
            elif state['started_on_blank']:
                tree.selection_set(range_iids)
            else:
                tree.selection_set(range_iids)
            try:
                tree.focus(current_iid)
            except tk.TclError:
                pass
            self._active_drag_tree = tree
            if not self._drag_indicator:
                self._create_drag_indicator(tree, state['start_root_x'], state['start_root_y'])
            self._update_drag_indicator(root_x, root_y)
        except tk.TclError:
            pass
        return

    def _tree_selection_release(self, event):
        tree = event.widget
        if not isinstance(tree, ttk.Treeview):
            tree = self._active_drag_tree
        if not isinstance(tree, ttk.Treeview):
            return
        if isinstance(event.widget, ttk.Treeview):
            region = tree.identify_region(event.x, event.y)
            if region in {'heading', 'separator'} and (not getattr(tree, '_drag_selection_state', None)):
                return
        state = getattr(tree, '_drag_selection_state', None)
        if not state:
            self._active_drag_tree = None
            self._destroy_drag_indicator()
            return
        try:
            if state.get('dragging'):
                children = list(tree.get_children())
                current_local_y = int(event.y) if isinstance(event.widget, ttk.Treeview) else int(event.y_root) - tree.winfo_rooty()
                current_iid = tree.identify_row(current_local_y)
                if current_iid not in children:
                    current_iid = self._nearest_tree_row_for_y(tree, current_local_y) if children else None
                if current_iid:
                    self.selection_anchors[str(tree)] = current_iid
                    try:
                        tree.focus(current_iid)
                    except tk.TclError:
                        pass
        except (tk.TclError, IndexError, AttributeError):
            pass
        finally:
            tree._drag_selection_state = None
            if self._active_drag_tree is tree:
                self._active_drag_tree = None
            self._destroy_drag_indicator()
            try:
                tree.configure(cursor='')
            except tk.TclError:
                pass
        if state.get('dragging') or state.get('started_on_blank'):
            return 'break'

    def _tree_selection_click(self, event):
        return self._tree_selection_press(event)

    def _remember_selection_anchor(self, tree, iid):
        if iid and tree.exists(iid):
            self.selection_anchors[str(tree)] = iid

    def _monitor_widths(self):
        return {'#': (55, tk.CENTER, False), 'Status': (105, tk.CENTER, False), 'PID': (70, tk.CENTER, False), 'Protocol': (70, tk.CENTER, False), 'Local Port': (85, tk.CENTER, False), 'Remote Port': (85, tk.CENTER, False), 'Direction': (85, tk.CENTER, False), 'Process Name': (150, tk.W, True), 'Remote IP': (125, tk.CENTER, True), 'Remote Host': (190, tk.W, True), 'Download (MB)': (110, tk.CENTER, False), 'Upload (MB)': (110, tk.CENTER, False), 'Signal': (210, tk.W, True), 'Exe Path': (300, tk.W, True)}

    def setup_monitor_tab(self):
        bar = tk.Frame(self.tab_monitor, pady=8)
        bar.pack(fill=tk.X)
        self._button(bar, 'Block Selected', self.block_process, '#f44336')
        self._button(bar, 'Allow Selected', self.allow_process, '#4CAF50')
        self._button(bar, 'Export CSV', self.export_connections)
        self._button(bar, 'Clear List', self.clear_list)
        self.search_var.trace_add('write', lambda *_: self.render_monitor())
        ttk.Entry(bar, textvariable=self.search_var, width=25).pack(side=tk.RIGHT, padx=5)
        tk.Label(bar, text='Search:').pack(side=tk.RIGHT)
        self.tree = self._make_tree(self.tab_monitor, self.MONITOR_COLUMNS, self._monitor_widths(), 'monitor')
        self.tree.bind('<Double-1>', lambda e: self.tree_details_from_event(e, self.tree))

    def setup_active_tab(self):
        bar = tk.Frame(self.tab_active, pady=8)
        bar.pack(fill=tk.X)
        self._button(bar, 'Block Selected', lambda: self.block_process(self.active_tree), '#f44336')
        self._button(bar, 'Allow Selected', lambda: self.allow_process(self.active_tree), '#4CAF50')
        self._button(bar, 'Export CSV', lambda: self.export_connections(self.active_tree))
        self.active_search_var.trace_add('write', lambda *_: self.render_active())
        ttk.Entry(bar, textvariable=self.active_search_var, width=25).pack(side=tk.RIGHT, padx=5)
        tk.Label(bar, text='Search:').pack(side=tk.RIGHT)
        self.active_tree = self._make_tree(self.tab_active, self.ACTIVE_COLUMNS, self._monitor_widths(), 'active')
        self.active_tree.bind('<Double-1>', lambda e: self.tree_details_from_event(e, self.active_tree))

    def setup_rules_tab(self):
        bar = tk.Frame(self.tab_rules, pady=8)
        bar.pack(fill=tk.X)
        self._button(bar, 'Refresh Rules', self.refresh_rules, '#2196F3')
        self._button(bar, 'Add Custom Rule', self.add_custom_rule, '#ff9800')
        self._button(bar, 'Allow Global IP', lambda: self.add_global_target('Allow'), '#90CAF9')
        self._button(bar, 'Block Global IP', lambda: self.add_global_target('Block'), '#7B1FA2')
        self._button(bar, 'Remove Selected', self.remove_selected_rule, '#f44336')
        self._button(bar, 'Export Rules', self.export_rules)
        self._button(bar, 'Import Rules', self.import_rules)
        self._button(bar, 'Windows Firewall', self.open_windows_firewall)
        self.rule_search_var.trace_add('write', lambda *_: self.render_rules())
        ttk.Entry(bar, textvariable=self.rule_search_var, width=24).pack(side=tk.RIGHT, padx=5)
        tk.Label(bar, text='Search:').pack(side=tk.RIGHT)
        self.rules_tree = self._make_tree(self.tab_rules, self.RULE_COLUMNS, {'Status': (95, tk.CENTER, False), 'Rule / Application': (220, tk.W, True), 'Direction': (90, tk.CENTER, False), 'Download (MB)': (105, tk.CENTER, False), 'Upload (MB)': (105, tk.CENTER, False), 'Program Path': (450, tk.W, True)}, 'rules')
        self.rules_tree.bind('<Double-1>', lambda e: self.rule_details_from_event(e))
        self.rules_tree.bind('<Delete>', self._on_rules_delete, add='+')
        self.rules_tree.bind('<KP_Delete>', self._on_rules_delete, add='+')

    def setup_alerts_tab(self):
        bar = tk.Frame(self.tab_alerts, pady=8)
        bar.pack(fill=tk.X)
        tk.Label(bar, text='Port watches are context signals, not proof of malicious activity.').pack(side=tk.LEFT, padx=5)
        self._button(bar, 'Clear Alerts', self.clear_alerts)
        self.alert_search_var.trace_add('write', lambda *_: self.render_alerts())
        ttk.Entry(bar, textvariable=self.alert_search_var, width=25).pack(side=tk.RIGHT, padx=5)
        tk.Label(bar, text='Search:').pack(side=tk.RIGHT)
        self.alerts_tree = self._make_tree(self.tab_alerts, self.ALERT_COLUMNS, {'Time': (85, tk.CENTER, False), 'Severity': (90, tk.CENTER, False), 'Process': (170, tk.W, True), 'PID': (70, tk.CENTER, False), 'Remote IP': (170, tk.W, True), 'Remote Host': (180, tk.W, True), 'Reason': (480, tk.W, True)}, 'alerts')

    def setup_settings_tab(self):
        outer = tk.Frame(self.tab_settings, padx=30, pady=25)
        outer.pack(fill=tk.BOTH, expand=True)
        frame = tk.LabelFrame(outer, text='Auto-Block Protection', padx=18, pady=14)
        frame.pack(fill=tk.X)
        self.chk_alerts = ttk.Checkbutton(frame, text='Enable Alerts (required for Auto-Block)', variable=self.log_alerts_var, command=self.on_log_alerts_changed)
        self.chk_alerts.grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=5)
        self.chk_auto = ttk.Checkbutton(frame, text='Enable Auto-Block Protection', variable=self.auto_block_var, command=self.on_auto_block_changed)
        self.chk_auto.grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=5)
        fields = (('Max Connections Threshold', self.rate_threshold_var, 'connections / process / target'), ('Time Window', self.rate_window_var, 'seconds'), ('Max Upload Threshold', self.upload_threshold_var, 'MB / process / target IP'))
        for row, (label, variable, suffix) in enumerate(fields, 3):
            tk.Label(frame, text=label).grid(row=row, column=0, sticky=tk.W, pady=6)
            entry = ttk.Entry(frame, textvariable=variable, width=10)
            entry.grid(row=row, column=1, sticky=tk.W, pady=6)
            if row == 3:
                self.rate_threshold_entry = entry
            elif row == 4:
                self.rate_window_entry = entry
            tk.Label(frame, text=suffix, fg=self.colors['muted']).grid(row=row, column=2, sticky=tk.W, padx=8)
        tk.Label(frame, text='Max Connections / Alerts').grid(row=6, column=0, sticky=tk.W, pady=6)
        ttk.Entry(frame, textvariable=self.max_connections_alerts_var, width=10).grid(row=6, column=1, sticky=tk.W, pady=6)
        tk.Label(frame, text='rows retained in Live Monitor and Alerts', fg=self.colors['muted']).grid(row=6, column=2, sticky=tk.W, padx=8)
        self._button(frame, 'Apply Settings', self.apply_settings, '#2196F3', pack=False).grid(row=7, column=0, sticky=tk.W, pady=(12, 0))
        appearance = tk.LabelFrame(outer, text='Appearance', padx=18, pady=14)
        appearance.pack(fill=tk.X, pady=18)
        ttk.Checkbutton(appearance, text='Use Dark Theme', variable=self.dark_mode_var, command=self.on_theme_changed).pack(anchor=tk.W)

        support = tk.LabelFrame(
            outer,
            text='Support PyFirewall',
            padx=18,
            pady=14,
            bg=self.colors['frame'],
            fg=self.colors['fg']
        )
        support.pack(fill=tk.X, pady=18)

        github_url = 'https://github.com/EolnMsuk/PyFirewall'
        venmo_url = 'https://venmo.com/u/rustonrails'

        def open_support_link(url):
            try:
                os.startfile(url)
            except OSError:
                pass

        try:
            import base64
            import struct

            if os.path.isfile(ICON_FILE):
                with open(ICON_FILE, 'rb') as icon_file:
                    icon_data = icon_file.read()

                icon_png = None
                if len(icon_data) >= 6:
                    reserved, icon_type, icon_count = struct.unpack_from('<HHH', icon_data, 0)
                    if reserved == 0 and icon_type == 1:
                        for index in range(icon_count):
                            entry_offset = 6 + (index * 16)
                            if entry_offset + 16 > len(icon_data):
                                break
                            image_size, image_offset = struct.unpack_from('<II', icon_data, entry_offset + 8)
                            payload = icon_data[image_offset:image_offset + image_size]
                            if payload.startswith(b'\x89PNG\r\n\x1a\n'):
                                if icon_png is None or image_size > len(icon_png):
                                    icon_png = payload

                if icon_png:
                    icon_image = tk.PhotoImage(data=base64.b64encode(icon_png).decode('ascii'))
                    if icon_image.width() > 128:
                        factor = max(2, icon_image.width() // 128)
                        while factor > 1 and icon_image.width() // factor < 96:
                            factor -= 1
                        icon_image = icon_image.subsample(factor, factor)

                    self.settings_icon_photo = icon_image

                    icon_label = tk.Label(
                        support,
                        image=self.settings_icon_photo,
                        bg=self.colors['frame'],
                        cursor='hand2',
                        borderwidth=0,
                        highlightthickness=0,
                        relief=tk.FLAT
                    )
                    icon_label.pack(anchor=tk.W, pady=(0, 8))
                    icon_label.bind('<Button-1>', lambda _event: open_support_link(github_url))
                    add_tooltip(icon_label, 'Open the PyFirewall GitHub page.')
        except (OSError, ValueError, struct.error, tk.TclError):
            pass

        github_label = tk.Label(
            support,
            text='GitHub • github.com/EolnMsuk/PyFirewall',
            bg=self.colors['frame'],
            fg=self.colors['select'],
            cursor='hand2',
            font=('Segoe UI', 9, 'underline')
        )
        github_label.pack(anchor=tk.W, pady=2)
        github_label.bind('<Button-1>', lambda _event: open_support_link(github_url))
        add_tooltip(github_label, 'Open the PyFirewall GitHub repository.')

        donation_label = tk.Label(
            support,
            text='Donate via Venmo • Support the dev (EolnMsuk)',
            bg=self.colors['frame'],
            fg=self.colors['select'],
            cursor='hand2',
            font=('Segoe UI', 9, 'underline')
        )
        donation_label.pack(anchor=tk.W, pady=2)
        donation_label.bind('<Button-1>', lambda _event: open_support_link(venmo_url))
        add_tooltip(donation_label, 'Open venmo.com/u/rustonrails in your default browser.')

        danger = tk.LabelFrame(outer, text='Danger Zone', padx=18, pady=14)
        danger.pack(fill=tk.X)
        tk.Label(danger, text='Reset saved settings and remove only PyFirewall_* rules.', fg=self.colors['muted'], wraplength=700, justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 10))
        self._button(danger, 'Reset to Defaults', self.reset_to_defaults, '#c62828')
        self.update_auto_block_controls()

    def setup_status_bar(self):
        bar = tk.Frame(self.root, pady=4, padx=10)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        specs = (('status_state', '● Monitoring', 15), ('status_firewall', 'Firewall: Protected', 25), ('status_connections', 'Connections: 0', 17), ('status_rules', 'Rules: 0', 12), ('status_capture', 'Capture: 0 KB/s • 0 pkt/s', 30), ('status_traffic', 'Total: 0.00 MB Down • 0.00 MB Up', None))
        for attr, text, width in specs:
            kwargs = {'text': text, 'anchor': tk.W}
            if width:
                kwargs['width'] = width
            widget = tk.Label(bar, **kwargs)
            setattr(self, attr, widget)
            widget.pack(side=tk.LEFT, padx=(0, 15))

    def _update_threshold_entries(self):
        state = tk.DISABLED if self.filter_all_enabled or self.is_paused else tk.NORMAL
        for name in ('rate_threshold_entry', 'rate_window_entry'):
            entry = getattr(self, name, None)
            if entry is not None:
                entry.config(state=state)

    def update_filter_ui(self):
        if self.is_paused:
            text = ('🔒' if self.filter_all_enabled else '🔓') + f"  Filter All Connections {('ON' if self.filter_all_enabled else 'OFF')}"
            color, state, fg = ('#9E9E9E', tk.DISABLED, '#ffffff')
        elif self.filter_all_enabled:
            text, color, state, fg = ('🔒  Filter All Connections ON', '#f44336', tk.NORMAL, '#ffffff')
        else:
            text, color, state, fg = ('🔓  Filter All Connections OFF', '#9E9E9E', tk.NORMAL, '#ffffff')
        if hasattr(self, 'btn_filter'):
            self._set_button_colors(self.btn_filter, getattr(self, 'filter_border', None), color, fg, state)
            self.btn_filter.configure(text=text)
        if self.tray is not None:
            self.tray.update_state(filter_all_enabled=self.filter_all_enabled, is_paused=self.is_paused)
        self._update_threshold_entries()

    def toggle_filter_all(self):
        if self.is_paused:
            return
        try:
            current = int(self.rate_threshold_var.get())
            if current > 1:
                self.saved_rate_threshold = current
        except (ValueError, tk.TclError):
            pass
        with self.lock:
            enabling = not self.filter_all_enabled
            if enabling:
                self.filter_all_saved_alerts = bool(self.log_alerts_only)
                self.filter_all_saved_auto_block = self.filter_all_saved_alerts and bool(self.auto_block_enabled)
                self.filter_all_enabled = True
                self.log_alerts_only = True
                self.auto_block_enabled = True
            else:
                self.filter_all_enabled = False
                restored_alerts = True if self.filter_all_saved_alerts is None else bool(self.filter_all_saved_alerts)
                restored_auto_block = restored_alerts and (True if self.filter_all_saved_auto_block is None else bool(self.filter_all_saved_auto_block))
                self.log_alerts_only = restored_alerts
                self.auto_block_enabled = restored_auto_block
                self.filter_all_saved_alerts = None
                self.filter_all_saved_auto_block = None
            if self.filter_all_enabled:
                self.rate_threshold = 1
                self.rate_threshold_var.set('1')
            else:
                self.rate_threshold = max(1, self.saved_rate_threshold)
                self.rate_threshold_var.set(str(self.rate_threshold))
            self.log_alerts_var.set(self.log_alerts_only)
            self.auto_block_var.set(self.auto_block_enabled)
        self.update_auto_block_controls()
        self.update_filter_ui()
        self.root.update_idletasks()
        self._queue_settings_change(release_auto_holds=not self.log_alerts_only or not self.auto_block_enabled)
        self.save_settings()

    def toggle_pause(self):
        with self.lock:
            self.is_paused = not self.is_paused
            paused = self.is_paused
        if paused:
            self._invalidate_auto_prompts(close_dialog=True)
        pause_text = '▶  Resume Monitoring' if paused else '⏸  Pause Monitoring'
        pause_color = '#9E9E9E' if paused else '#2196F3'
        if hasattr(self, 'btn_pause'):
            self._set_button_colors(self.btn_pause, getattr(self, 'pause_border', None), pause_color, '#ffffff', tk.NORMAL)
            self.btn_pause.configure(text=pause_text)
        self.update_auto_block_controls()
        self.update_filter_ui()
        if paused:
            try:
                self.release_auto_holds()
            except Exception as exc:
                messagebox.showerror('Temporary Block Cleanup Failed', str(exc), parent=self.root)
        else:
            self.render_all()
        self.update_status()

    def update_auto_block_controls(self):
        if hasattr(self, 'chk_alerts'):
            self.chk_alerts.config(state=tk.DISABLED if self.is_paused or self.filter_all_enabled else tk.NORMAL)
        if hasattr(self, 'chk_auto'):
            self.chk_auto.config(state=tk.NORMAL if self.log_alerts_only and (not self.is_paused) and (not self.filter_all_enabled) else tk.DISABLED)
        self._update_threshold_entries()

    def _queue_settings_change(self, release_auto_holds=False):
        with self.settings_change_lock:
            self.settings_change_generation += 1
            self.settings_change_pending = True
            self.settings_change_release_holds = self.settings_change_release_holds or release_auto_holds
            if self.settings_change_worker_running:
                return
            self.settings_change_worker_running = True
        threading.Thread(target=self._settings_change_worker, daemon=True, name='PyFirewall-Settings').start()

    def _release_auto_holds_for_generation(self, generation):
        try:
            with self.firewall_lock:
                with self.settings_change_lock:
                    if generation != self.settings_change_generation:
                        return False
                with self.lock:
                    if self.closed or (self.log_alerts_only and self.auto_block_enabled):
                        return False
                self.remove_auto_holds_locked()
                with self.settings_change_lock:
                    generation_is_current = generation == self.settings_change_generation
                with self.lock:
                    still_current = generation_is_current and (not self.closed) and (not self.log_alerts_only) and (not self.auto_block_enabled)
                if still_current:
                    self._invalidate_auto_prompts(close_dialog=False)
                return still_current
        except Exception as exc:
            self.queue_alert('High', 'Temporary blocks', '', '', f'Could not release temporary blocks: {exc}')
            return False

    def _settings_change_worker(self):
        while True:
            with self.settings_change_lock:
                if not self.settings_change_pending:
                    self.settings_change_worker_running = False
                    return
                release_auto_holds = self.settings_change_release_holds
                self.settings_change_release_holds = False
                self.settings_change_pending = False
            with self.settings_change_lock:
                generation = self.settings_change_generation
            with self.lock:
                disabled = not self.log_alerts_only or not self.auto_block_enabled
                closed = self.closed
            if closed:
                continue
            if release_auto_holds and disabled:
                self._release_auto_holds_for_generation(generation)
            self.save_settings()

    def on_log_alerts_changed(self):
        enabled = bool(self.log_alerts_var.get())
        with self.lock:
            self.log_alerts_only = enabled
            if not enabled:
                self.auto_block_enabled = False
        if not enabled:
            self._invalidate_auto_prompts(close_dialog=True)
            self.auto_block_var.set(False)
        self.update_auto_block_controls()
        self.root.update_idletasks()
        self._queue_settings_change(release_auto_holds=not enabled)

    def on_auto_block_changed(self):
        enabled = bool(self.auto_block_var.get())
        with self.lock:
            self.auto_block_enabled = self.log_alerts_only and enabled
            actual_enabled = self.auto_block_enabled
        if not actual_enabled:
            self._invalidate_auto_prompts(close_dialog=True)
        self.auto_block_var.set(actual_enabled)
        self.update_auto_block_controls()
        self.root.update_idletasks()
        self._queue_settings_change(release_auto_holds=not actual_enabled)

    def _prune_connection_and_alert_history_locked(self):
        limit = max(1, int(self.max_connections_alerts))

        if len(self.active_connections) > limit:
            overflow = len(self.active_connections) - limit
            oldest = sorted(
                self.active_connections.items(),
                key=lambda item: item[1].get('number', 0),
            )[:overflow]
            for key, _ in oldest:
                self.active_connections.pop(key, None)

        if self.alerts.maxlen != limit:
            self.alerts = deque(self.alerts, maxlen=limit)

    def apply_settings(self):
        try:
            threshold = 1 if self.filter_all_enabled else int(self.rate_threshold_var.get().strip())
            window = float(self.rate_window_var.get().strip())
            upload = float(self.upload_threshold_var.get().strip())
            max_connections_alerts = int(self.max_connections_alerts_var.get().strip())
        except (ValueError, tk.TclError):
            messagebox.showerror('Invalid Settings', 'Threshold and Max Connections / Alerts must be whole numbers; Time Window and Upload Threshold must be positive numbers.')
            return False
        if threshold < 1 or window <= 0 or upload <= 0 or max_connections_alerts < 1:
            messagebox.showerror('Invalid Settings', 'Threshold and Max Connections / Alerts must be at least 1; Time Window and Upload Threshold must be > 0.')
            return False
        with self.lock:
            self.rate_threshold = threshold
            if not self.filter_all_enabled:
                self.saved_rate_threshold = threshold
            self.rate_window = window
            self.upload_threshold_mb = upload
            self.max_connections_alerts = max_connections_alerts
            self._prune_connection_and_alert_history_locked()
            self.connection_rates.clear()
            self.proc_ip_upload.clear()
            self.proc_ip_upload_last_seen.clear()
            self.upload_alerted.clear()
        self.rate_threshold_var.set(str(threshold))
        self.rate_window_var.set(str(window))
        self.upload_threshold_var.set(str(upload))
        self.max_connections_alerts_var.set(str(max_connections_alerts))
        self.save_settings()
        if self.startup_complete:
            self.render_monitor()
            self.render_active()
            self.render_alerts()
        self.update_status()
        return True

    def reset_to_defaults(self):
        if not messagebox.askyesno('Reset to Defaults', 'Remove all PyFirewall_* firewall rules and reset application settings?\n\nOther Windows Firewall rules will not be changed.', icon='warning'):
            return
        try:
            with self.firewall_lock:
                with self.settings_change_lock:
                    self.settings_change_generation += 1
                    self.settings_change_pending = False
                    self.settings_change_release_holds = False
                records = self.get_firewall_rules()
                self._replace_rule_records(records, (), lambda: None)
                self._invalidate_auto_prompts(close_dialog=True)
            with self.lock:
                self.filter_all_enabled = True
                self.is_paused = False
                self.filter_all_saved_alerts = None
                self.filter_all_saved_auto_block = None
                self.saved_rate_threshold = DEFAULT_RATE_THRESHOLD
                self.rate_threshold = 1 if self.filter_all_enabled else DEFAULT_RATE_THRESHOLD
                self.rate_window = DEFAULT_RATE_WINDOW
                self.upload_threshold_mb = DEFAULT_UPLOAD_THRESHOLD_MB
                self.max_connections_alerts = DEFAULT_MAX_CONNECTIONS_ALERTS
                self.log_alerts_only = DEFAULT_LOG_ALERTS_ONLY
                self.auto_block_enabled = True
                self.dark_mode = bool(self.dark_mode_var.get())
                self.allowed_apps.clear()
                self.blocked_paths.clear()
                self.global_blocks.clear()
                self.global_allows.clear()
                self.active_connections.clear()
                self.connection_rates.clear()
                self.proc_ip_upload.clear()
                self.proc_ip_upload_last_seen.clear()
                self.upload_alerted.clear()
                self.ip_traffic_last_seen.clear()
                self.proc_traffic.clear()
                self.ip_traffic.clear()
                self.total_download = self.total_upload = 0
                self.firewall_initialized = True
                self.column_orders = {key: list(order) for key, order in self.default_column_orders.items()}
            for tree_name, order_key in (('tree', 'monitor'), ('active_tree', 'active'), ('rules_tree', 'rules'), ('alerts_tree', 'alerts')):
                tree = getattr(self, tree_name, None)
                if tree is not None:
                    tree['displaycolumns'] = tuple(self.column_orders[order_key])
            self.rate_threshold_var.set(str(self.rate_threshold))
            self.rate_window_var.set(str(DEFAULT_RATE_WINDOW))
            self.upload_threshold_var.set(str(DEFAULT_UPLOAD_THRESHOLD_MB))
            self.max_connections_alerts_var.set(str(DEFAULT_MAX_CONNECTIONS_ALERTS))
            self.log_alerts_var.set(DEFAULT_LOG_ALERTS_ONLY)
            self.auto_block_var.set(True)
            self.clear_alerts()
            self.clear_list()
            self._set_button_colors(self.btn_pause, getattr(self, 'pause_border', None), '#2196F3', '#ffffff', tk.NORMAL)
            self.btn_pause.config(text='⏸  Pause Monitoring')
            self.update_auto_block_controls()
            self.update_filter_ui()
            if self.startup_complete:
                self.render_all()
            self.save_settings()
            self.refresh_rules(force=True)
            self.update_status()
            messagebox.showinfo('Defaults Restored', 'PyFirewall-managed rules and saved settings were reset.')
        except Exception as exc:
            messagebox.showerror('Reset Failed', str(exc))

    def _run(self, args, check=True):
        return subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=check,
            creationflags=CREATE_NO_WINDOW,
            timeout=FIREWALL_COMMAND_TIMEOUT,
        )

    def run_ps(self, command, check=True):
        return self._run(('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command), check)

    def run_netsh(self, args, check=True):
        return self._run(('netsh', 'advfirewall', 'firewall', *args), check)

    def delete_rule_names(self, names, strict=True):
        names = sorted(set(n for n in names if n))
        if not names:
            return False
        # Keep discovery, deletion and verification in one process. Match literal
        # display names (including legacy netsh rules whose Name is a GUID).
        command = "$ErrorActionPreference='Stop'\n$names=@(" + ','.join(self._ps_quote(n) for n in names) + ")\n"
        command += '''
$existing = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.DisplayName -in $names })
foreach ($r in $existing) { $r | Remove-NetFirewallRule -ErrorAction Stop }
$remaining = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.DisplayName -in $names })
if ($remaining.Count) { throw ('Firewall rules could not be removed: ' + ($remaining.DisplayName -join ', ')) }
if ($existing.Count) { 'removed' } else { 'absent' }
'''
        try:
            output = self.run_ps(command).stdout.strip()
            if output not in {'removed', 'absent'}:
                raise RuntimeError('Invalid firewall deletion result.')
            return output == 'removed'
        except Exception:
            # Re-read actual state after a failed/partial batch before fallback.
            return self._delete_rule_names_individually(names, strict)

    def _delete_rule_names_individually(self, names, strict=True):
        names = set(n for n in names if n)
        if not names:
            return False
        existing = {r['name'] for r in self.get_firewall_rules()}
        for name in names & existing:
            try:
                self.run_netsh(['delete', 'rule', f'name={name}'])
            except (subprocess.SubprocessError, OSError):
                pass
        remaining = names & {r['name'] for r in self.get_firewall_rules()}
        if remaining:
            raise RuntimeError('Firewall rules could not be removed: ' + ', '.join(sorted(remaining)))
        return bool(names & existing)

    def _replace_rule_records(self, previous, desired_names, apply, apply_first=False):
        names = {r['name'] for r in previous} | set(desired_names)
        try:
            if apply_first:
                apply()
            self.delete_rule_names(r['name'] for r in previous)
            if not apply_first:
                apply()
        except Exception as error:
            cleanup_error = None
            try:
                self.delete_rule_names(names)
            except Exception as exc:
                cleanup_error = exc
            try:
                remaining = {r['name'] for r in self.get_firewall_rules()}
                self._restore_app_rule_records([r for r in previous if r['name'] not in remaining])
                if cleanup_error:
                    raise cleanup_error
            except Exception as rollback_error:
                try:
                    self.sync_rule_cache()
                    self.save_settings()
                except Exception as reconcile_error:
                    log_internal_error('rule_reconciliation', reconcile_error)
                raise RuntimeError(f'Rule update failed: {error}; rollback failed: {rollback_error}') from rollback_error
            raise

    def get_firewall_rules(self):
        command = '''
$rules = Get-NetFirewallRule -ErrorAction Stop |
  Where-Object {$_.DisplayName -like "PyFirewall_*"} |
  ForEach-Object {
    $r = $_
    $a = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction Stop |
      Select-Object -First 1
    [PSCustomObject]@{
      DisplayName=[string]$r.DisplayName
      Action=[string]$r.Action
      Direction=[string]$r.Direction
      Addresses=@((Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction Stop).RemoteAddress)
      Program=if($null -ne $a){[string]$a.Program}else{""}
    }
  }
if($null -eq $rules){"[]"}else{@($rules)|ConvertTo-Json -Compress}
'''
        output = self.run_ps(command).stdout.strip()
        if not output:
            return []
        try:
            raw = json.loads(output)
        except (json.JSONDecodeError, TypeError) as exc:
            raise RuntimeError(f'Windows Firewall returned invalid rule data: {exc}') from exc
        if isinstance(raw, dict):
            raw = [raw]
        if not isinstance(raw, list):
            raise RuntimeError('Windows Firewall returned an unexpected rule-data format.')
        records = []
        for item in raw:
            if not isinstance(item, dict):
                raise RuntimeError('Windows Firewall returned an invalid rule record.')
            if not str(item.get('DisplayName', '') or '').strip():
                raise RuntimeError('Windows Firewall returned a rule without a display name.')
            if 'Action' not in item or 'Direction' not in item:
                raise RuntimeError('Windows Firewall returned incomplete rule metadata.')
            name = str(item.get('DisplayName', '') or '')
            global_rule = name.startswith((GLOBAL_BLOCK_PREFIX, GLOBAL_ALLOW_PREFIX))
            records.append({'name': name, 'action': str(item.get('Action', '') or ''), 'direction': str(item.get('Direction', '') or ''), 'path': '' if global_rule else display_path(item.get('Program', '')), 'normalized_path': '' if global_rule else normalize_path(item.get('Program', '')), 'is_global': global_rule, 'is_hold': name.startswith(AUTO_HOLD_PREFIX), 'addresses': item.get('Addresses', [])})
        return records

    def app_rule_base(self, proc_name, exe_path, kind='Block'):
        base = re.sub('[^A-Za-z0-9_.-]+', '_', os.path.splitext(os.path.basename(exe_path))[0] or proc_name or 'Process')[:60]
        digest = hashlib.sha1(normalize_path(exe_path).encode('utf-8', 'ignore')).hexdigest()[:8]
        return f'PyFirewall_{kind}_{base}_{digest}'

    def global_rule_base(self, target, allow):
        digest = hashlib.sha1(normalize_target(target).encode('utf-8')).hexdigest()[:12]
        return f'{(GLOBAL_ALLOW_PREFIX if allow else GLOBAL_BLOCK_PREFIX)}{digest}'

    @staticmethod
    def _ps_quote(value):
        return "'" + str(value).replace("'", "''") + "'"

    def _app_rule_commands(self, name, exe_path, side, action='block'):
        direction = 'Inbound' if side == 'in' else 'Outbound'
        action_name = 'Block' if str(action).casefold() == 'block' else 'Allow'
        ps_command = (
            f"New-NetFirewallRule -Name {self._ps_quote(name)} -DisplayName {self._ps_quote(name)} "
            f"-Direction {direction} -Program {self._ps_quote(exe_path)} "
            f"-Action {action_name} -Enabled True -Profile Any -ErrorAction Stop | Out-Null"
        )
        verify = (
            f"$r=Get-NetFirewallRule -Name {self._ps_quote(name)} -ErrorAction Stop; "
            f"$a=Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction Stop | Select-Object -First 1; "
            f"if(-not $a){{throw 'Application filter is missing.'}}; "
            f"if([string]$r.Enabled -ne 'True'){{throw 'Firewall rule is disabled.'}}; "
            f"if([string]$r.Direction -ne {self._ps_quote(direction)}){{throw ('Wrong direction: ' + [string]$r.Direction)}}; "
            f"if([string]$r.Action -ne {self._ps_quote(action_name)}){{throw ('Wrong action: ' + [string]$r.Action)}}; "
            f"if(-not [string]::Equals([string]$a.Program,{self._ps_quote(exe_path)},[System.StringComparison]::OrdinalIgnoreCase)){{throw ('Wrong program: ' + [string]$a.Program)}}"
        )
        return ps_command, verify

    def _add_app_firewall_rule(self, name, exe_path, side, action='block'):
        """Compatibility path for one application rule, including netsh fallback."""
        action_name = 'Block' if str(action).casefold() == 'block' else 'Allow'
        created = False
        used_netsh = False
        ps_command, verify = self._app_rule_commands(name, exe_path, side, action)

        try:
            self.run_ps(ps_command)
            created = True
        except Exception as first_error:
            first_detail = getattr(first_error, 'stderr', '') or ''
            try:
                self.run_netsh([
                    'add', 'rule',
                    f'name={name}',
                    f'dir={side}',
                    f'action={action_name.casefold()}',
                    f'program={exe_path}',
                    'enable=yes',
                    'profile=any',
                ])
                created = True
                used_netsh = True
            except Exception as second_error:
                second_detail = getattr(second_error, 'stderr', '') or ''
                try:
                    self.delete_rule_names((name,))
                except Exception:
                    pass
                raise RuntimeError(
                    f"Could not create application firewall rule '{name}' for '{exe_path}'. "
                    f"PowerShell: {str(first_detail).strip() or str(first_error)}; "
                    f"netsh: {str(second_detail).strip() or str(second_error)}"
                ) from second_error

        try:
            self.run_ps(verify)
            return
        except Exception as exc:
            if used_netsh:
                try:
                    self.run_netsh(['show', 'rule', f'name={name}', 'verbose'])
                    return
                except Exception:
                    pass
            detail = getattr(exc, 'stderr', '') or ''
            if created:
                try:
                    self.delete_rule_names((name,))
                except Exception:
                    pass
            raise RuntimeError(
                f"Windows Firewall created rule '{name}', but verification failed for '{exe_path}': "
                f"{str(detail).strip() or str(exc)}"
            ) from exc

    def add_app_rules(self, proc_name, exe_path, direction, kind='Block'):
        base = self.app_rule_base(proc_name, exe_path, kind)
        names, commands, checks = [], [], []
        for side in direction_set(direction):
            name = f"{base}_{'In' if side == 'in' else 'Out'}"
            create, verify = self._app_rule_commands(name, exe_path, side)
            names.append(name)
            commands.append(create)
            checks.append(verify)
        try:
            self.run_ps("$ErrorActionPreference='Stop'\n" + '\n'.join(commands + checks))
            return base
        except Exception as error:
            # A timeout can leave either direction installed. Confirm cleanup
            # before retrying, so fallback cannot create duplicate rules.
            try:
                self.delete_rule_names(names)
            except Exception as cleanup_error:
                raise RuntimeError(f'Application rule batch failed: {error_details(error)}; cleanup failed: {cleanup_error}') from cleanup_error
            return self._add_app_rules_individually(proc_name, exe_path, direction, kind)

    def _add_app_rules_individually(self, proc_name, exe_path, direction, kind='Block'):
        base = self.app_rule_base(proc_name, exe_path, kind)
        created_names = []
        try:
            for side in direction_set(direction):
                name = f"{base}_{('In' if side == 'in' else 'Out')}"
                self._add_app_firewall_rule(name, exe_path, side, 'block')
                created_names.append(name)
            return base
        except Exception:
            if created_names:
                try:
                    self.delete_rule_names(created_names)
                except Exception:
                    pass
            raise

    def _restore_app_rule_records(self, records):
        created = []
        try:
            for record in records:
                path = display_path(record.get('path', ''))
                name = str(record.get('name', '') or '').strip()
                if not name:
                    continue
                if record.get('is_global'):
                    addresses = record.get('addresses', [])
                    if isinstance(addresses, str):
                        addresses = [addresses]
                    side = 'in' if direction_name(record['direction']) == 'Inbound' else 'out'
                    self.run_netsh(['add', 'rule', f'name={name}', f'dir={side}',
                                    'action=' + record['action'].lower(),
                                    'remoteip=' + ','.join(addresses), 'enable=yes'])
                    created.append(name)
                    continue
                if not path:
                    raise ValueError(f'Missing program for rule {name}')
                action = 'Allow' if str(record.get('action', '')).casefold() == 'allow' else 'Block'
                suffixes = {'in': 'In', 'out': 'Out'}
                for side in direction_set(record.get('direction', 'Both')):
                    rule_name = name if name.endswith(f"_{suffixes[side]}") else f"{name}_{suffixes[side]}"
                    self._add_app_firewall_rule(rule_name, path, side, action)
                    created.append(rule_name)
        except Exception:
            if created:
                try:
                    self.delete_rule_names(created)
                except Exception:
                    pass
            raise

    def resolve_global_target(self, target):
        target = normalize_target(target)
        try:
            if '/' in target:
                return (str(ipaddress.ip_network(target, strict=False)),)
            return (str(ipaddress.ip_address(target)),)
        except ValueError:
            pass
        try:
            addresses = {result[4][0] for result in socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)}
            return tuple(sorted(addresses, key=lambda value: (ipaddress.ip_address(value).version, value)))
        except OSError:
            return ()

    def add_global_rule_sync(self, target, allow):
        target = normalize_target(target)
        try:
            target = str(ipaddress.ip_network(target, strict=False)) if '/' in target else str(ipaddress.ip_address(target))
        except ValueError:
            pass
        addresses = self.resolve_global_target(target)
        if not addresses:
            raise ValueError('Enter a valid IP address or a domain that resolves to at least one IP address.')
        base = self.global_rule_base(target, allow)
        other = self.global_rule_base(target, not allow)
        names = {f'{prefix}_{side}' for prefix in (base, other) for side in ('In', 'Out')}
        previous = [r for r in self.get_firewall_rules() if r['name'] in names]
        def create():
            for side in ('in', 'out'):
                name = f'{base}_{side.title()}'
                self.run_netsh(['add', 'rule', f'name={name}', f'dir={side}',
                                'action=' + ('allow' if allow else 'block'),
                                'remoteip=' + ','.join(addresses), 'enable=yes'])
            records = {r['name']: r for r in self.get_firewall_rules()}
            for side, direction in (('In', 'Inbound'), ('Out', 'Outbound')):
                record = records.get(f'{base}_{side}')
                if not record or record['action'].casefold() != ('allow' if allow else 'block') or direction_name(record['direction']) != direction:
                    raise RuntimeError(f'Global firewall rule verification failed: {base}_{side}')
        self._replace_rule_records(previous, names, create)
        return target, addresses

    def _read_firewall_profile_state(self):
        command = "Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,@{n='Enabled';e={[string]$_.Enabled}},@{n='DefaultInboundAction';e={[string]$_.DefaultInboundAction}},@{n='DefaultOutboundAction';e={[string]$_.DefaultOutboundAction}} | ConvertTo-Json -Compress"
        output = self.run_ps(command).stdout.strip() or '[]'
        raw = json.loads(output)
        if isinstance(raw, dict):
            raw = [raw]
        profiles = []
        for item in raw if isinstance(raw, list) else []:
            name = str(item.get('Name', '') or '')
            if not name:
                continue
            profiles.append({
                'name': name,
                'enabled': self._profile_enabled(item.get('Enabled', False)),
                'default_inbound_action': self._profile_action(item.get('DefaultInboundAction')), 
                'default_outbound_action': self._profile_action(item.get('DefaultOutboundAction')), 
            })
        if not profiles:
            raise ValueError('No Windows Firewall profiles were returned.')
        return profiles

    def _backup_firewall_profile_state(self):
        if os.path.exists(FIREWALL_PROFILE_BACKUP_FILE):
            return
        profiles = self._read_firewall_profile_state()
        backup = {'version': 1, 'created_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'profiles': profiles}
        temp = FIREWALL_PROFILE_BACKUP_FILE + '.tmp'
        with open(temp, 'w', encoding='utf-8') as f:
            json.dump(backup, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, FIREWALL_PROFILE_BACKUP_FILE)

    def initialize_or_restore_firewall(self):
        try:
            with self.firewall_lock:
                with self.lock:
                    if self.closed:
                        return False, 'Application is closing.'
                if os.path.exists(FIREWALL_PROFILE_BACKUP_FILE):
                    self._restore_firewall_profile_state_locked()
                self._backup_firewall_profile_state()
                with self.lock:
                    self.firewall_profile_modified = True
                try:
                    self.run_ps('Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {Set-NetFirewallProfile -Name $_.Name -Enabled True -DefaultInboundAction Allow -DefaultOutboundAction Allow -ErrorAction Stop}')
                    self.restore_saved_rules_locked()
                    self.remove_auto_holds_locked()
                except Exception as setup_error:
                    log_internal_error('firewall_setup', setup_error)
                    try:
                        self._restore_firewall_profile_state_locked()
                    except Exception as restore_error:
                        raise RuntimeError(f'Firewall setup failed: {error_details(setup_error)}\n'
                                           f'Profile restoration also failed: {error_details(restore_error)}') from restore_error
                    raise
                with self.lock:
                    self.firewall_initialized = True
            return True, ''
        except Exception as exc:
            log_internal_error('initialize_or_restore_firewall', exc)
            return False, error_details(exc)

    @staticmethod
    def _profile_action(value):
        actions = {'0': 'NotConfigured', '2': 'Allow', '4': 'Block',
                   'notconfigured': 'NotConfigured', 'allow': 'Allow', 'block': 'Block'}
        result = actions.get(str(value).strip().casefold())
        if result is None:
            raise ValueError(f'Invalid firewall profile action: {value!r}')
        return result

    @staticmethod
    def _profile_enabled(value):
        if value is True or str(value).casefold() in {'true', '1'}:
            return True
        if value is False or str(value).casefold() in {'false', '0'}:
            return False
        raise ValueError(f'Invalid firewall enabled state: {value!r}')

    def _restore_firewall_profile_state_locked(self):
        if not os.path.exists(FIREWALL_PROFILE_BACKUP_FILE):
            return False
        with open(FIREWALL_PROFILE_BACKUP_FILE, 'r', encoding='utf-8') as f:
            backup = json.load(f)
        profiles = backup.get('profiles') if isinstance(backup, dict) else None
        if not isinstance(profiles, list) or not profiles:
            raise ValueError('Firewall profile backup is missing or invalid.')
        validated = []
        for profile in profiles:
            if not isinstance(profile, dict) or profile.get('name') not in {'Domain', 'Private', 'Public'}:
                raise ValueError('Invalid firewall profile in backup.')
            validated.append((profile['name'], self._profile_enabled(profile.get('enabled')),
                              self._profile_action(profile.get('default_inbound_action')),
                              self._profile_action(profile.get('default_outbound_action'))))
        if {p[0] for p in validated} != {'Domain', 'Private', 'Public'} or len(validated) != 3:
            raise ValueError('Backup must contain each firewall profile exactly once.')
        for name, enabled, inbound, outbound in validated:
            self.run_ps(f"Set-NetFirewallProfile -Name {self._ps_quote(name)} "
                        f"-Enabled {'True' if enabled else 'False'} "
                        f"-DefaultInboundAction {inbound} -DefaultOutboundAction {outbound} -ErrorAction Stop")
        os.remove(FIREWALL_PROFILE_BACKUP_FILE)
        with self.lock:
            self.firewall_profile_modified = False
            self.firewall_initialized = False
        return True

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

    def restore_saved_rules_locked(self):
        with self.lock:
            allowed = list(self.allowed_apps)
            pending = list(self.pending_rules)
            global_blocks = list(self.global_blocks)
            global_allows = list(self.global_allows)
        records = self.get_firewall_rules()
        for path in allowed:
            self.delete_rule_names((r['name'] for r in records if r['normalized_path'] == path))
        for rule in pending:
            path = display_path(rule['path'])
            norm = normalize_path(path)
            wanted = direction_set(rule['direction'])
            actual = set()
            for record in records:
                if record['normalized_path'] == norm and not record['is_hold'] and record['action'].casefold() == 'block':
                    d = record['direction'].casefold()
                    if 'in' in d:
                        actual.add('in')
                    if 'out' in d:
                        actual.add('out')
            if actual != wanted:
                proc_name = os.path.splitext(os.path.basename(path))[0]
                base = self.app_rule_base(proc_name, path)
                self._replace_rule_records([r for r in records if r['normalized_path'] == norm],
                                           (base + '_In', base + '_Out'),
                                           lambda: self.add_app_rules(proc_name, path, rule['direction']))
        for target in global_blocks:
            target, addresses = self.add_global_rule_sync(target, False)
            with self.lock:
                self.global_blocks[target] = {'addresses': addresses}
        for target in global_allows:
            target, addresses = self.add_global_rule_sync(target, True)
            with self.lock:
                self.global_allows[target] = {'addresses': addresses}
        with self.lock:
            self.pending_rules.clear()

    def remove_auto_holds_locked(self, normalized_path=None):
        records = self.get_firewall_rules()
        holds = [r for r in records if r['is_hold'] and (not normalized_path or r['normalized_path'] == normalized_path)]
        self._replace_rule_records(holds, (), lambda: None)

    def get_rule_status(self, exe_path):
        norm = normalize_path(exe_path)
        with self.lock:
            if norm in self.allowed_apps:
                return 'allowed'
            data = self.blocked_paths.get(norm, {})
            if data.get('in') and data.get('out'):
                return 'blocked_both'
            if data.get('in'):
                return 'blocked_in'
            if data.get('out'):
                return 'blocked_out'
            return ''

    def get_rule_status_display(self, exe_path):
        status = self.get_rule_status(exe_path)
        return {'allowed': 'Allowed', 'blocked_both': 'Blocked', 'blocked_in': 'Blocked (In)', 'blocked_out': 'Blocked'}.get(status, '—')

    def _global_match(self, collection, remote_ip, domain):
        try:
            remote = ipaddress.ip_address(str(remote_ip).split('%', 1)[0])
        except ValueError:
            return False
        for target, data in collection.items():
            for address in (target, *data.get('addresses', ())):
                try:
                    if remote in ipaddress.ip_network(address, strict=False):
                        return True
                except ValueError:
                    continue
        return False

    def is_globally_blocked(self, remote_ip, domain=''):
        with self.lock:
            return self._global_match(self.global_blocks, remote_ip, domain)

    def is_globally_allowed(self, remote_ip, domain=''):
        with self.lock:
            return self._global_match(self.global_allows, remote_ip, domain)

    def connection_has_rule(self, exe_path, remote_ip, domain, direction):
        if self.is_globally_blocked(remote_ip, domain) or self.is_globally_allowed(remote_ip, domain):
            return True
        status = self.get_rule_status(exe_path)
        normalized_direction = direction_name(direction)
        if status in {'allowed', 'blocked_both'}:
            return True
        if status == 'blocked_in':
            return normalized_direction == 'Inbound'
        if status == 'blocked_out':
            return normalized_direction == 'Outbound'
        return False

    def application_has_rule(self, exe_path):
        return bool(self.get_rule_status(exe_path))

    def rules_changed(self):
        self.refresh_rules(force=True)

    def block_executable(self, exe_path, proc_name=None, direction='both', refresh=True, quiet=False, update_ui=True):
        path = display_path(exe_path)
        norm = normalize_path(path)
        if not norm:
            return False
        proc_name = proc_name or os.path.splitext(os.path.basename(path))[0] or 'Process'
        try:
            with self.firewall_lock:
                records = self.get_firewall_rules()
                previous = [r for r in records if r['normalized_path'] == norm]
                base = self.app_rule_base(proc_name, path, 'Block')
                # AutoHold and permanent rules have distinct names. Verify the
                # permanent block before removing temporary protection.
                replacing_hold = bool(previous) and all(r.get('is_hold') for r in previous)
                self._replace_rule_records(previous, (base + '_In', base + '_Out'),
                                           lambda: self.add_app_rules(proc_name, path, direction, kind='Block'),
                                           apply_first=replacing_hold)
                with self.lock:
                    wanted = direction_set(direction)
                    self.allowed_apps.discard(norm)
                    self.blocked_paths[norm] = {'in': 'in' in wanted, 'out': 'out' in wanted, 'path': path}
                    self.connection_rates = {k: v for k, v in self.connection_rates.items() if k[0] != norm}
            if update_ui:
                self._cancel_app_prompt(norm)
            self.save_settings()
            if refresh and update_ui:
                self.rules_changed()
            return True
        except Exception as exc:
            self.queue_alert('High', path, '', '', f'Firewall rule update failed: {exc}')
            if not quiet:
                messagebox.showerror('Block Failed', f'{proc_name}\n\n{exc}')
            return False

    def allow_executable(self, exe_path, refresh=True, quiet=False, update_ui=True):
        path = display_path(exe_path)
        norm = normalize_path(path)
        if not norm:
            return False
        try:
            with self.firewall_lock:
                records = self.get_firewall_rules()
                previous = [r for r in records if r['normalized_path'] == norm]
                self._replace_rule_records(previous, (), lambda: None)
                with self.lock:
                    self.allowed_apps.add(norm)
                    self.blocked_paths.pop(norm, None)
                    self.connection_rates = {k: v for k, v in self.connection_rates.items() if k[0] != norm}
                    self.upload_alerted = {k for k in self.upload_alerted if k[0] != norm}
            if update_ui:
                self._cancel_app_prompt(norm)
            self.save_settings()
            if refresh and update_ui:
                self.rules_changed()
            return True
        except Exception as exc:
            self.queue_alert('High', path, '', '', f'Firewall rule update failed: {exc}')
            if not quiet:
                messagebox.showerror('Allow Failed', f'{path}\n\n{exc}')
            return False

    def add_global_rule(self, target, allow, refresh=True, quiet=False):
        target = normalize_target(target)
        if not target:
            return False
        try:
            with self.firewall_lock:
                target, addresses = self.add_global_rule_sync(target, allow)
                with self.lock:
                    destination = self.global_allows if allow else self.global_blocks
                    other = self.global_blocks if allow else self.global_allows
                    destination[target] = {'addresses': addresses}
                    other.pop(target, None)
            self.save_settings()
            try:
                self.release_auto_holds()
            except Exception as exc:
                self.queue_alert('High', 'Temporary blocks', '', target, f'Global rule applied, but pending blocks could not be released: {exc}')
            if refresh:
                self.rules_changed()
            return True
        except Exception as exc:
            self.queue_alert('High', 'Global rule', '', target, f'Firewall rule update failed: {exc}')
            if not quiet:
                messagebox.showerror('Global Rule Failed', f"{('Allow' if allow else 'Block')} {target}\n\n{exc}")
            return False

    def remove_rule(self, status, path, refresh=True):
        status = str(status).casefold()
        try:
            with self.firewall_lock:
                records = self.get_firewall_rules()
                if status in {'global block', 'global allow'}:
                    target = normalize_target(str(path).split(' (', 1)[0])
                    allow = status == 'global allow'
                    base = self.global_rule_base(target, allow)
                    self._replace_rule_records([r for r in records if r['name'].startswith(base)], (), lambda: None)
                    with self.lock:
                        (self.global_allows if allow else self.global_blocks).pop(target, None)
                else:
                    norm = normalize_path(path)
                    self._replace_rule_records([r for r in records if r['normalized_path'] == norm], (), lambda: None)
                    with self.lock:
                        self.allowed_apps.discard(norm)
                        self.blocked_paths.pop(norm, None)
                    self._cancel_app_prompt(norm)
            self.save_settings()
            if refresh:
                self.rules_changed()
            return True
        except Exception as exc:
            messagebox.showerror('Remove Rule Failed', str(exc))
            return False

    @staticmethod
    def _blocked_from_records(records):
        blocked = {}
        for record in records:
            if record['is_global'] or record['is_hold'] or record['action'].casefold() != 'block':
                continue
            norm = record['normalized_path']
            if not norm:
                continue
            data = blocked.setdefault(norm, {'in': False, 'out': False, 'path': record['path']})
            direction = record['direction'].casefold()
            data['in'] |= 'in' in direction
            data['out'] |= 'out' in direction
        return blocked

    def sync_rule_cache(self):
        with self.firewall_lock:
            records = self.get_firewall_rules()
            blocked = self._blocked_from_records(records)
            with self.lock:
                self.allowed_apps.difference_update(blocked)
                self.blocked_paths = blocked
                names = {r['name'] for r in records}
                for allow, collection in ((False, self.global_blocks), (True, self.global_allows)):
                    for target in list(collection):
                        base = self.global_rule_base(target, allow)
                        if not ({base + '_In', base + '_Out'} & names):
                            collection.pop(target, None)

    def refresh_rules(self, force=False):
        with self.lock:
            if not self.firewall_initialized:
                return
            self.rules_generation += 1
            self.rules_refresh_pending = True
            if self.rules_refresh_worker_running:
                return
            self.rules_loading = True
            self.rules_refresh_worker_running = True
        self.rules_tree.delete(*self.rules_tree.get_children())
        self.rules_tree.insert('', tk.END, iid='__loading__', values=('Loading', 'Reading Windows Firewall...', '', '', '', ''), tags=('even',))
        threading.Thread(target=self._refresh_rules_worker, daemon=True, name='RuleRefresh').start()

    def _refresh_rules_worker(self):
        while True:
            with self.lock:
                if self.closed:
                    self.rules_refresh_pending = False
                    self.rules_refresh_worker_running = False
                    return
                if not self.rules_refresh_pending:
                    self.rules_refresh_worker_running = False
                    return
                self.rules_refresh_pending = False
                generation = self.rules_generation
            try:
                with self.firewall_lock:
                    records = self.get_firewall_rules()
                    with self.lock:
                        allowed = set(self.allowed_apps)
                        blocks = {k: dict(v) for k, v in self.global_blocks.items()}
                        allows = {k: dict(v) for k, v in self.global_allows.items()}
                self.ui_queue.put(('rules', generation, self._blocked_from_records(records), allowed, blocks, allows))
            except Exception as exc:
                self.ui_queue.put(('rules_error', generation, str(exc)))
            with self.lock:
                if self.closed:
                    self.rules_refresh_pending = False
                    self.rules_refresh_worker_running = False
                    return
                if self.rules_refresh_pending:
                    continue
                self.rules_refresh_worker_running = False
                return

    def _make_rule_rows(self, blocked, allowed, blocks, allows):
        rows = []
        allowed_normalized = {normalize_path(path) for path in allowed}
        for path in sorted(allowed):
            rows.append({'iid': f'app:allow:{path}', 'status': 'Allowed', 'rule': os.path.basename(path) or path, 'action': 'Allow', 'direction': 'Both', 'path': path, 'normalized_path': path, 'download': 0, 'upload': 0})
        for path, data in sorted(blocked.items()):
            if path in allowed_normalized:
                continue
            direction = self._direction_from_flags(data)
            rows.append({'iid': f'app:block:{path}', 'status': 'Blocked' if direction != 'Inbound' else 'Blocked (In)', 'rule': os.path.basename(data['path']) or data['path'], 'action': 'Block', 'direction': direction, 'path': data['path'], 'normalized_path': path, 'download': 0, 'upload': 0})
        for kind, collection in (('block', blocks), ('allow', allows)):
            global_text = 'Block' if kind == 'block' else 'Allow'
            for target, data in sorted(collection.items()):
                addresses = tuple(data.get('addresses', ()))
                rows.append({'iid': f'global:{kind}:{target}', 'status': f'Global {global_text}', 'rule': f'Global IP {global_text}', 'action': global_text, 'direction': 'Both', 'path': target if not addresses else f"{target} ({', '.join(addresses)})", 'normalized_path': target, 'addresses': addresses, 'global_type': kind, 'download': 0, 'upload': 0})
        return rows

    def _finish_rule_refresh(self, generation, blocked, allowed, blocks, allows):
        if generation != self.rules_generation or self.closed:
            return
        with self.lock:
            self.blocked_paths = {path: {'in': data['in'], 'out': data['out'], 'path': data['path']} for path, data in blocked.items() if path not in self.allowed_apps}
        rows = self._make_rule_rows(blocked, allowed, blocks, allows)
        with self.lock:
            proc_traffic = {key: dict(value) for key, value in self.proc_traffic.items()}
            for row in rows:
                if row.get('global_type'):
                    down, up = self._target_traffic_locked(row['normalized_path'], row.get('addresses', ()))
                else:
                    stats = proc_traffic.get(row['normalized_path'], {})
                    down = stats.get('download', 0)
                    up = stats.get('upload', 0)
                row['download'] = down
                row['upload'] = up
        self.rule_rows = rows
        self.rules_loading = False
        self.render_rules()
        self.render_monitor()
        self.render_active()

    def add_custom_rule(self):
        path = filedialog.askopenfilename(title='Select Executable', filetypes=[('Executable Files', '*.exe'), ('All files', '*.*')])
        if not path:
            return
        proc = os.path.splitext(os.path.basename(path))[0] or 'Process'
        direction = self.ask_direction(f'Choose a rule for {proc}', allow=True)
        if direction == 'allow':
            self.allow_executable(path)
        elif direction:
            self.block_executable(path, proc, direction)

    def add_global_target(self, action):
        target = simpledialog.askstring(f'{action} Global Target', 'IP address or domain:', parent=self.root)
        if target:
            self.add_global_rule(target, action == 'Allow')

    def ask_direction(self, prompt, allow=False):
        result = {'value': None}
        dialog = tk.Toplevel(self.root)
        dialog.title('Firewall Action')
        dialog.resizable(False, False)
        dialog.withdraw()
        dialog.transient(self.root)
        dialog.grab_set()
        self._theme_dialog(dialog)
        tk.Label(dialog, text=prompt, wraplength=380, padx=18, pady=15, bg=self.colors['frame'], fg=self.colors['fg']).pack()
        buttons = tk.Frame(dialog, bg=self.colors['frame'])
        buttons.pack(fill=tk.X, padx=15, pady=5)

        def choose(value):
            result['value'] = value
            dialog.destroy()
        for text, value, color, tip in (('Block In & Out', 'both', '#f44336', 'Block incoming and outgoing traffic.'), ('Block Incoming Only', 'in', '#ff9800', 'Block incoming traffic and leave outgoing traffic allowed.')):
            button = tk.Button(buttons, text=text, command=lambda v=value: choose(v), bg=color, fg='white', relief='flat')
            self._bind_button_hover(button)
            button.pack(fill=tk.X, pady=3)
            add_tooltip(button, tip)
        if allow:
            button = tk.Button(buttons, text='Allow All', command=lambda: choose('allow'), bg='#4CAF50', fg='white', relief='flat')
            self._bind_button_hover(button)
            button.pack(fill=tk.X, pady=3)
            add_tooltip(button, 'Allow all traffic for the executable.')
        button = tk.Button(buttons, text='Cancel', command=dialog.destroy, bg=self.colors.get('head', '#757575'), fg=self.colors['fg'], relief='flat')
        self._bind_button_hover(button)
        button.pack(fill=tk.X, pady=3)
        add_tooltip(button, 'Close without changing the firewall rules.')
        dialog.update_idletasks()
        self._center_dialog(dialog)
        dialog.deiconify()
        dialog.lift()
        dialog.focus_force()
        self.root.wait_window(dialog)
        return result['value']

    def sort_tree(self, tree, column):
        states = ((self.tree, self.monitor_sort, self.render_monitor), (self.active_tree, self.active_sort, self.render_active), (self.rules_tree, self.rule_sort, self.render_rules))
        state, renderer = (self.alert_sort, self.render_alerts)
        for target, candidate, fn in states:
            if tree is target:
                state, renderer = (candidate, fn)
                break
        if state[0] == column:
            state[1] = not state[1]
        else:
            state[:] = [column, column in {'#', 'Download (MB)', 'Upload (MB)', 'Time', 'PID'}]
        renderer()

    @staticmethod
    def search_text(row):
        return ' '.join(map(str, (row.get('name', ''), row.get('pid', ''), row.get('direction', ''), row.get('protocol', ''), row.get('lport', ''), row.get('dst_ip', ''), row.get('domain', ''), row.get('dport', ''), mb(row.get('_down', 0)), mb(row.get('_up', 0)), row.get('signal', ''), row.get('exe', '')))).casefold()

    def sort_monitor_rows(self, rows, state):
        column, reverse = state
        fields = {'#': lambda r: r['number'], 'Process Name': lambda r: r['name'].casefold(), 'Status': lambda r: self.get_rule_status_display(r.get('exe', '')).casefold(), 'PID': lambda r: r['pid'], 'Direction': lambda r: r['direction'].casefold(), 'Protocol': lambda r: r['protocol'].casefold(), 'Local Port': lambda r: r['lport'], 'Remote IP': lambda r: r['dst_ip'].casefold(), 'Remote Host': lambda r: r.get('domain', '').casefold(), 'Remote Port': lambda r: r['dport'], 'Download (MB)': lambda r: r.get('_down', 0), 'Upload (MB)': lambda r: r.get('_up', 0), 'Signal': lambda r: r.get('signal', '').casefold(), 'Exe Path': lambda r: r['exe'].casefold()}
        rows.sort(key=fields.get(column, lambda r: ''), reverse=reverse)

    def _render_connections(self, tree, search_var, sort_state, active_only=False):
        if not isinstance(tree, ttk.Treeview):
            return
        search = search_var.get().casefold().strip()
        now = time.monotonic()
        with self.lock:
            rows = [dict(row) for row in self.active_connections.values() if not active_only or now - row.get('last_seen', row.get('first_seen', now)) <= 5]
            traffic = {key: dict(value) for key, value in self.proc_traffic.items()}
        for row in rows:
            data = traffic.get(normalize_path(row['exe']) or row['name'].casefold(), {})
            row['_down'] = data.get('download', 0)
            row['_up'] = data.get('upload', 0)
        if search:
            rows = [row for row in rows if search in self.search_text(row)]
        self.sort_monitor_rows(rows, sort_state)
        selected = set(tree.selection())
        tree.delete(*tree.get_children())
        for index, row in enumerate(rows):
            tree.insert('', tk.END, iid=row['key'], values=self.connection_values(row, include_status=(tree is self.tree)), tags=(self.connection_tag(row, index),))
        if selected:
            tree.selection_set([iid for iid in selected if tree.exists(iid)])

    def render_monitor(self):
        self._render_connections(self.tree, self.search_var, self.monitor_sort)

    def render_active(self):
        self._render_connections(self.active_tree, self.active_search_var, self.active_sort, active_only=True)

    def connection_values(self, row, include_status=False):
        values = (row['number'], row['name'], row['pid'], row['direction'], row['protocol'], row['lport'], row['dst_ip'], row.get('domain') or '—', row['dport'], mb(row.get('_down', 0)), mb(row.get('_up', 0)), row.get('signal') or '—', row['exe'])
        if include_status:
            return (values[0], values[1], self.get_rule_status_display(row.get('exe', '')), *values[2:])
        return values

    def connection_tag(self, row, index=0):
        remote = row.get('dst_ip', '')
        domain = row.get('domain', '')
        if self.is_globally_blocked(remote, domain):
            return 'global_block'
        if self.is_globally_allowed(remote, domain):
            return 'global_allow'
        status = self.get_rule_status(row.get('exe', ''))
        if status == 'allowed':
            return 'allowed'
        if status == 'blocked_in':
            return 'blocked_in'
        if status in {'blocked_both', 'blocked_out'}:
            return 'blocked'
        return 'watch' if row.get('signal') else 'even' if index % 2 == 0 else 'odd'

    def alert_tag(self, values):
        row, remote_ip = self.alert_context(values)
        domain = (row or {}).get('domain', '')
        if self.is_globally_blocked(remote_ip, domain):
            return 'global_block'
        if self.is_globally_allowed(remote_ip, domain):
            return 'global_allow'
        if row:
            status = self.get_rule_status(row.get('exe', ''))
            if status == 'allowed':
                return 'allowed'
            if status == 'blocked_in':
                return 'blocked_in'
            if status in {'blocked_both', 'blocked_out'}:
                return 'blocked'
        return ''

    def render_rules(self):
        if not hasattr(self, 'rules_tree'):
            return
        search = self.rule_search_var.get().casefold().strip()
        rows = list(self.rule_rows)
        if search:
            rows = [row for row in rows if search in ' '.join(map(str, (row['status'], row['rule'], row['action'], row['direction'], row['path'], mb(row.get('download', 0)), mb(row.get('upload', 0))))).casefold()]
        column, reverse = self.rule_sort
        if column:
            fields = {'Status': lambda r: r['status'].casefold(), 'Rule / Application': lambda r: r['rule'].casefold(), 'Direction': lambda r: r['direction'].casefold(), 'Download (MB)': lambda r: r.get('download', 0), 'Upload (MB)': lambda r: r.get('upload', 0), 'Program Path': lambda r: r['path'].casefold()}
            rows.sort(key=fields.get(column, lambda r: ''), reverse=reverse)
        selected = set(self.rules_tree.selection())
        self.rules_tree.delete(*self.rules_tree.get_children())
        for row in rows:
            tag = 'global_allow' if row.get('global_type') == 'allow' else 'global_block' if row.get('global_type') == 'block' else 'allowed' if row['status'] == 'Allowed' else 'blocked_in' if row['status'] == 'Blocked (In)' else 'blocked'
            self.rules_tree.insert('', tk.END, iid=row['iid'], values=(row['status'], row['rule'], row['direction'], mb(row.get('download', 0)), mb(row.get('upload', 0)), row['path']), tags=(tag,))
        if selected:
            self.rules_tree.selection_set([iid for iid in selected if self.rules_tree.exists(iid)])

    def render_alerts(self):
        if not hasattr(self, 'alerts_tree'):
            return
        search = self.alert_search_var.get().casefold().strip()
        rows = list(self.alerts)
        column, reverse = self.alert_sort
        fields = {'Time': lambda x: x[1], 'Severity': lambda x: str(x[2]).casefold(), 'Process': lambda x: str(x[3]).casefold(), 'PID': lambda x: int(x[4] or 0), 'Remote IP': lambda x: str(x[5]).casefold(), 'Remote Host': lambda x: str(x[6]).casefold(), 'Reason': lambda x: str(x[7]).casefold()}
        rows.sort(key=fields.get(column, lambda x: ''), reverse=reverse)
        selected = set(self.alerts_tree.selection())
        rendered = []
        for alert_id, ts, severity, process, pid, remote, host, reason in rows:
            host = host or self.get_cached_dns(str(remote).split(':', 1)[0])
            values = (time.strftime('%H:%M:%S', time.localtime(ts)), severity, process, pid, remote, host or '—', reason)
            if search and search not in ' '.join(map(str, values)).casefold():
                continue
            rendered.append((alert_id, values, self.alert_tag(values)))
        self.alerts_tree.delete(*self.alerts_tree.get_children())
        for alert_id, values, tag in rendered:
            self.alerts_tree.insert('', tk.END, iid=f'alert_{alert_id}', values=values, tags=(tag,) if tag else ())
        keep = [iid for iid in selected if self.alerts_tree.exists(iid)]
        if keep:
            self.alerts_tree.selection_set(keep)

    def render_all(self):
        self.render_monitor()
        self.render_active()
        self.render_rules()
        self.render_alerts()

    def refresh_process_cache(self):
        now = time.monotonic()
        if now - self.cache_time < 2:
            return
        socket_cache, listener_cache = {}, {}
        try:
            local_addresses = {normalize_target(a.address.split('%', 1)[0])
                               for addresses in psutil.net_if_addrs().values()
                               for a in addresses if a.family in (socket.AF_INET, socket.AF_INET6)}
            local_addresses.update({'127.0.0.1', '::1'})
            for conn in psutil.net_connections(kind='inet'):
                if not conn.laddr or not conn.pid:
                    continue
                family_key = int(conn.family)
                proto = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                local_ip = normalize_target(conn.laddr.ip.split('%', 1)[0])
                local_port = conn.laddr.port
                if conn.raddr:
                    remote_ip = normalize_target(conn.raddr.ip.split('%', 1)[0])
                    key = (family_key, proto, local_ip, local_port, remote_ip, conn.raddr.port)
                    socket_cache.setdefault(key, set()).add(conn.pid)
                elif proto == 'UDP' or conn.status == psutil.CONN_LISTEN:
                    listener_cache.setdefault((family_key, proto, local_ip, local_port), set()).add(conn.pid)
            self.local_addresses = local_addresses
            self.socket_process_cache = socket_cache
            self.listener_process_cache = listener_cache
            self.cache_time = now
        except (psutil.Error, OSError) as exc:
            self.socket_process_cache = {}
            self.listener_process_cache = {}
            log_internal_error('refresh_process_cache', exc)

    def get_process_info(self, local_ip, local_port, remote_ip, remote_port, proto, family_key):
        self.refresh_process_cache()
        local_ip_n = normalize_target(local_ip.split('%', 1)[0])
        remote_ip_n = normalize_target(remote_ip.split('%', 1)[0])
        if local_ip_n not in self.local_addresses:
            return None, None, None
        candidates = self.socket_process_cache.get((family_key, proto, local_ip_n, int(local_port), remote_ip_n, int(remote_port)))
        if candidates is None:
            candidates = set(self.listener_process_cache.get((family_key, proto, local_ip_n, int(local_port)), ()))
            wildcard = '0.0.0.0' if family_key == int(socket.AF_INET) else '::'
            candidates.update(self.listener_process_cache.get((family_key, proto, wildcard, int(local_port)), ()))
        if len(candidates) != 1:
            return None, None, None
        pid = next(iter(candidates))
        try:
            proc = psutil.Process(pid)
            return proc.name(), proc.exe(), pid
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None, None, None

    def _start_dns_workers(self):
        for index in range(DNS_MAX_WORKERS):
            worker = threading.Thread(target=self._dns_worker, daemon=True, name=f'PyFirewall-DNS-{index + 1}')
            worker.start()
            self.dns_workers.append(worker)

    def _dns_worker(self):
        while not self.dns_stop_event.is_set():
            try:
                ip = self.dns_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.resolve_dns(ip)
            except Exception:
                with self.dns_lock:
                    self.dns_pending.discard(ip)
            finally:
                self.dns_queue.task_done()

    def get_cached_dns(self, ip):
        ip = str(ip or '')
        if not ip:
            return ''
        now = time.monotonic()
        with self.dns_lock:
            cached = self.dns_cache.get(ip)
            cached_at = self.dns_cache_times.get(ip, 0.0)
            if cached is not None and (now - cached_at) < DNS_CACHE_TTL:
                return cached
            if cached is not None:
                self.dns_cache.pop(ip, None)
                self.dns_cache_times.pop(ip, None)
            if ip in self.dns_pending or len(self.dns_pending) >= DNS_MAX_PENDING:
                return ''
            self.dns_pending.add(ip)
        try:
            self.dns_queue.put_nowait(ip)
        except queue.Full:
            with self.dns_lock:
                self.dns_pending.discard(ip)
        return ''

    def resolve_dns(self, ip):
        host = ''
        try:
            host = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            pass
        except Exception:
            pass
        with self.dns_lock:
            if len(self.dns_cache) >= DNS_CACHE_MAX_ENTRIES and ip not in self.dns_cache:
                oldest_ip = min(self.dns_cache_times, key=self.dns_cache_times.get, default=None)
                if oldest_ip is not None:
                    self.dns_cache.pop(oldest_ip, None)
                    self.dns_cache_times.pop(oldest_ip, None)
            self.dns_cache[ip] = host
            self.dns_cache_times[ip] = time.monotonic()
            self.dns_pending.discard(ip)
        self.ui_queue.put(('dns', ip))

    def _prune_traffic_state_locked(self):
        self.last_traffic_prune = time.monotonic()
        if len(self.ip_traffic) > TRAFFIC_MAX_IP_ENTRIES:
            excess = len(self.ip_traffic) - TRAFFIC_MAX_IP_ENTRIES
            for key, _ in sorted(self.ip_traffic_last_seen.items(), key=lambda item: item[1])[:excess]:
                self.ip_traffic.pop(key, None)
                self.ip_traffic_last_seen.pop(key, None)
        if len(self.proc_ip_upload) > TRAFFIC_MAX_PROC_IP_ENTRIES:
            excess = len(self.proc_ip_upload) - TRAFFIC_MAX_PROC_IP_ENTRIES
            for key, _ in sorted(self.proc_ip_upload_last_seen.items(), key=lambda item: item[1])[:excess]:
                self.proc_ip_upload.pop(key, None)
                self.proc_ip_upload_last_seen.pop(key, None)
                self.upload_alerted.discard(key)

    @staticmethod
    def port_watch_signal(local_port, remote_port):
        parts = []
        for label, port in (('Remote', remote_port), ('Local', local_port)):
            try:
                desc = WATCH_PORTS.get(int(port))
            except (TypeError, ValueError):
                desc = None
            if desc:
                parts.append(f'{label} {int(port)} ({desc})')
        return f"Port watch: {'; '.join(parts)}" if parts else ''

    def packet_handler(self, packet):
        with self.lock:
            if self.is_paused or not self.sniffing or self.closed:
                return
            log_alerts = self.log_alerts_only
            rate_threshold = self.rate_threshold
            rate_window = self.rate_window
            upload_threshold = self.upload_threshold_mb
        try:
            packet_size = max(0, len(packet))
            if IP in packet:
                family_key = 2
                src, dst = (packet[IP].src, packet[IP].dst)
            elif IPv6 in packet:
                family_key = 23
                src, dst = (packet[IPv6].src, packet[IPv6].dst)
            else:
                return
            if TCP in packet:
                proto = 'TCP'
                sport, dport = (int(packet[TCP].sport), int(packet[TCP].dport))
            elif UDP in packet:
                proto = 'UDP'
                sport, dport = (int(packet[UDP].sport), int(packet[UDP].dport))
            else:
                return
            if not sport:
                return
            outgoing = self.get_process_info(src, sport, dst, dport, proto, family_key)
            incoming = self.get_process_info(dst, dport, src, sport, proto, family_key)
            if outgoing[0] and incoming[0]:
                return
            if outgoing[0] and outgoing[1]:
                proc_name, exe, pid = outgoing
                direction = 'Outgoing'
            elif incoming[0] and incoming[1]:
                proc_name, exe, pid = incoming
                direction = 'Incoming'
            else:
                return
            local_port, remote_ip, remote_port = (sport, dst, dport) if direction == 'Outgoing' else (dport, src, sport)
            key = f'{pid}-{proto}-{local_port}-{remote_ip}-{remote_port}'
            domain = self.get_cached_dns(remote_ip)
            signal = self.port_watch_signal(local_port, remote_port)
            norm_exe = normalize_path(exe) or proc_name.casefold()
            norm_ip = normalize_target(remote_ip)
            now = time.monotonic()
            with self.lock:
                self.captured_packets += 1
                self.captured_bytes += packet_size
                if direction == 'Outgoing':
                    self.total_upload += packet_size
                else:
                    self.total_download += packet_size
                pstats = self.proc_traffic.setdefault(norm_exe, {'download': 0, 'upload': 0})
                istats = self.ip_traffic.setdefault(norm_ip, {'download': 0, 'upload': 0})
                side = 'upload' if direction == 'Outgoing' else 'download'
                pstats[side] += packet_size
                istats[side] += packet_size
                is_new = key not in self.active_connections
                if is_new:
                    self.active_connections[key] = {'key': key, 'number': self.next_connection_number, 'name': proc_name, 'pid': pid, 'direction': direction, 'protocol': proto, 'lport': local_port, 'dst_ip': remote_ip, 'domain': domain, 'dport': remote_port, 'signal': signal, 'exe': exe, 'first_seen': now, 'last_seen': now}
                    self.next_connection_number += 1
                    self._prune_connection_and_alert_history_locked()
                else:
                    row = self.active_connections[key]
                    row['last_seen'] = now
                    if not row.get('domain') and domain:
                        row['domain'] = domain
                upload_key = None
                upload_total = 0
                if direction == 'Outgoing' and remote_ip not in {'127.0.0.1', '::1'}:
                    upload_key = (norm_exe, norm_ip)
                    upload_total = self.proc_ip_upload.get(upload_key, 0) + packet_size
                    self.proc_ip_upload[upload_key] = upload_total
                    self.proc_ip_upload_last_seen[upload_key] = now
                self.ip_traffic_last_seen[norm_ip] = now
                if now - self.last_traffic_prune >= TRAFFIC_PRUNE_INTERVAL:
                    self._prune_traffic_state_locked()
                rate_hit = False
                if is_new and log_alerts:
                    rate_key = (norm_exe, norm_ip)
                    timestamps = self.connection_rates.setdefault(rate_key, deque())
                    while timestamps and now - timestamps[0] > rate_window:
                        timestamps.popleft()
                    timestamps.append(now)
                    rate_hit = len(timestamps) >= rate_threshold
                    if rate_hit:
                        self.connection_rates.pop(rate_key, None)
            if signal and is_new:
                self.queue_alert('Watch', proc_name, pid, f'{remote_ip}:{remote_port}', f'{direction} connection on {proto}; {signal}.')
            if upload_key and log_alerts and (upload_total >= upload_threshold * 1024 * 1024):
                with self.lock:
                    first_upload_alert = upload_key not in self.upload_alerted
                    if first_upload_alert:
                        self.upload_alerted.add(upload_key)
                if first_upload_alert:
                    self.handle_threshold(proc_name, exe, pid, remote_ip, domain, direction, key, 'upload', mb(upload_total))
            if rate_hit:
                self.handle_threshold(proc_name, exe, pid, remote_ip, domain, direction, key, 'connection', '')
        except Exception as exc:
            log_internal_error('packet_handler', exc)

    def handle_threshold(self, proc_name, exe, pid, remote_ip, domain, direction, key, reason, detail):
        app_rule_exists = self.application_has_rule(exe)
        globally_blocked = self.is_globally_blocked(remote_ip, domain)
        globally_allowed = self.is_globally_allowed(remote_ip, domain)
        if globally_blocked:
            text = f'{reason.title()} threshold reached for {remote_ip}; a Global IP Block is already applied.'
        elif globally_allowed:
            text = f'{reason.title()} threshold reached for {remote_ip}; a Global IP Allow is already applied.'
        elif app_rule_exists:
            text = f'{reason.title()} threshold reached for {remote_ip}; an application rule is already applied, so Auto-Block will not prompt again.'
        else:
            with self.lock:
                auto_enabled = self.auto_block_enabled
            if not auto_enabled:
                text = f'{reason.title()} threshold reached for {remote_ip}; Auto-Block Protection is disabled.'
            else:
                text = f"{reason.title()} threshold reached for {remote_ip}{(f' ({detail})' if detail else '')}; the process was blocked pending your decision."
        self.queue_alert('High', proc_name, pid, remote_ip, text)
        with self.lock:
            active = self.log_alerts_only and self.auto_block_enabled and (not self.is_paused)
        if active and not globally_blocked and not globally_allowed and not app_rule_exists:
            self.start_auto_block(proc_name, exe, pid, remote_ip, domain, direction, key, reason, detail)

    def start_sniffing(self):
        while True:
            with self.lock:
                if not self.sniffing or self.closed:
                    return
                paused = self.is_paused
            if paused:
                time.sleep(0.25)
                continue
            try:
                sniff(filter='ip or ip6', prn=self.packet_handler, store=False, timeout=1)
                with self.lock:
                    recovered = self.capture_error is not None
                    self.capture_healthy = True
                    self.capture_error = None
                if recovered:
                    self.queue_alert('Info', 'Packet capture', '', '', 'Packet capture recovered.')
            except Exception as exc:
                with self.lock:
                    changed = self.capture_error != str(exc)
                    self.capture_error = str(exc)
                    self.capture_healthy = False
                if changed:
                    log_internal_error('packet_capture', exc)
                    self.queue_alert('High', 'Packet capture', '', '',
                                     f'Monitoring and Auto-Block unavailable: {exc}')
                time.sleep(1)

    def install_auto_hold(self, proc_name, exe, remote_ip='', domain='', prompt_generation=None):
        norm = normalize_path(exe)
        if not norm:
            return False
        try:
            with self.firewall_lock:
                with self.lock:
                    if not self.log_alerts_only or not self.auto_block_enabled or self.is_paused or self.closed:
                        return False
                    if norm in self.allowed_apps:
                        return False
                    if prompt_generation is not None and prompt_generation != self.auto_prompt_generation:
                        return False
                    if self._global_match(self.global_blocks, remote_ip, domain) or self._global_match(self.global_allows, remote_ip, domain):
                        return False
                records = self.get_firewall_rules()
                if any((not r['is_global']) and (not r['is_hold']) and r['normalized_path'] == norm for r in records):
                    return False
                self.delete_rule_names((r['name'] for r in records if r['is_hold'] and r['normalized_path'] == norm))
                self.add_app_rules(proc_name, exe, 'both', kind='AutoHold')
            return True
        except Exception:
            return False

    def _cancel_app_prompt(self, norm):
        dialog = None
        with self.lock:
            self.auto_prompt_keys.discard(norm)
            pending = []
            while True:
                try:
                    item = self.prompt_queue.get_nowait()
                except queue.Empty:
                    break
                if item[1] != norm:
                    pending.append(item)
            for item in pending:
                self.prompt_queue.put(item)
            if self.auto_prompt_key == norm:
                dialog = self.auto_prompt_dialog
                self.auto_prompt_dialog = None
                self.auto_prompt_key = None
                self.auto_prompt_active = False
        if dialog is not None:
            try:
                dialog.destroy()
            except tk.TclError:
                pass

    def _invalidate_auto_prompts(self, close_dialog=False):
        dialog = None
        with self.lock:
            self.auto_prompt_generation += 1
            self.auto_prompt_keys.clear()
            if close_dialog:
                dialog = self.auto_prompt_dialog
                self.auto_prompt_dialog = None
                self.auto_prompt_key = None
                self.auto_prompt_active = False
            while True:
                try:
                    self.prompt_queue.get_nowait()
                except queue.Empty:
                    break
        if close_dialog and dialog is not None:
            try:
                dialog.destroy()
            except tk.TclError:
                pass

    def start_auto_block(self, proc_name, exe, pid, remote_ip, domain, direction, key, reason, detail):
        with self.firewall_lock:
            self._start_auto_block_locked(proc_name, exe, pid, remote_ip, domain, direction, key, reason, detail)

    def _start_auto_block_locked(self, proc_name, exe, pid, remote_ip, domain, direction, key, reason, detail):
        prompt_key = normalize_path(exe) or key
        with self.lock:
            if not self.log_alerts_only or not self.auto_block_enabled or self.is_paused or self.closed:
                return
            if prompt_key in self.auto_prompt_keys:
                return
            generation = self.auto_prompt_generation
            self.auto_prompt_keys.add(prompt_key)
        if not self.install_auto_hold(proc_name, exe, remote_ip, domain, generation):
            with self.lock:
                current = generation == self.auto_prompt_generation
                self.auto_prompt_keys.discard(prompt_key)
                active_now = self.log_alerts_only and self.auto_block_enabled and (not self.is_paused) and (not self.closed)
            if current and active_now and (not self.application_has_rule(exe)) and (not self.is_globally_blocked(remote_ip, domain)) and (not self.is_globally_allowed(remote_ip, domain)):
                self.queue_alert('High', proc_name, pid, remote_ip, 'Threshold reached, but the temporary Auto-Block hold could not be installed.')
            return
        with self.lock:
            if generation != self.auto_prompt_generation or self.closed or self.is_paused or not self.log_alerts_only or not self.auto_block_enabled:
                stale = True
            else:
                stale = False
                self.prompt_queue.put((generation, prompt_key, proc_name, exe, pid, remote_ip, domain, direction, reason, detail))
        if stale:
            try:
                with self.firewall_lock:
                    self.remove_auto_holds_locked(normalize_path(exe))
            except Exception as exc:
                self.queue_alert('High', proc_name, pid, remote_ip, f'Could not release cancelled temporary block: {exc}')
            with self.lock:
                self.auto_prompt_keys.discard(prompt_key)
            return

    def release_auto_holds(self):
        with self.firewall_lock:
            self.remove_auto_holds_locked()
            self._invalidate_auto_prompts(close_dialog=True)

    def queue_alert(self, severity, process, pid, remote, reason):
        self.alert_queue.put((time.time(), severity, process, pid, remote, '', reason))

    def drain_alerts(self):
        changed = False
        for _ in range(100):
            try:
                alert = self.alert_queue.get_nowait()
            except queue.Empty:
                break
            alert_id = self.next_alert_id
            self.next_alert_id += 1
            self.alerts.append((alert_id, *alert))
            changed = True
        if changed:
            self.render_alerts()

    def clear_alerts(self):
        self.alerts.clear()
        if hasattr(self, 'alerts_tree'):
            self.alerts_tree.delete(*self.alerts_tree.get_children())

    def select_all_rows(self, event=None):
        tree = event.widget if event else None
        if isinstance(tree, ttk.Treeview):
            try:
                tree.focus_force()
            except tk.TclError:
                tree.focus_set()
            tree.selection_set(tree.get_children())
            children = tree.get_children()
            if children:
                self._remember_selection_anchor(tree, children[0])
            return 'break'

    def selected_rows(self, tree):
        return [(iid, tree.item(iid, 'values')) for iid in tree.selection() if tree.item(iid, 'values')]

    def open_file_location_from_tree(self, tree, iid):
        if not iid or not tree.exists(iid):
            return
        values = tree.item(iid, 'values')
        path = ''
        if tree is self.tree or tree is self.active_tree:
            with self.lock:
                row = self.active_connections.get(iid)
            if row:
                path = row.get('exe', '')
            else:
                columns = tuple(tree['columns'])
                mapping = dict(zip(columns, values))
                path = mapping.get('Exe Path', '')
        elif tree is self.rules_tree:
            columns = tuple(tree['columns'])
            mapping = dict(zip(columns, values))
            status = str(mapping.get('Status', '')).casefold()
            if status not in {'global block', 'global allow'}:
                path = mapping.get('Program Path', '')
        elif tree is self.alerts_tree:
            row, _ = self.alert_context(values)
            path = (row or {}).get('exe', '')
            if not path:
                pid_value = values[3] if len(values) > 3 else ''
                if str(pid_value).isdigit():
                    try:
                        path = psutil.Process(int(pid_value)).exe()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                        path = ''
        self.open_file_location(path)

    def open_file_location(self, exe_path):
        path = display_path(exe_path)
        if not path:
            messagebox.showinfo('Open File Location', 'The executable path for this process is not available.')
            return
        if not os.path.isfile(path):
            messagebox.showinfo('Open File Location', f'The executable could not be found:\n\n{path}')
            return
        try:
            result = ctypes.windll.shell32.ShellExecuteW(None, 'open', 'explorer.exe', f'/select,"{path}"', None, 1)
            if result <= 32:
                raise OSError(f'ShellExecuteW returned {result}')
        except Exception as exc:
            log_internal_error('Open File Location', exc)
            messagebox.showerror('Open File Location', f'Could not open File Explorer for:\n\n{path}\n\n{exc}')

    def _focus_menu_row(self, tree, event):
        iid = tree.identify_row(event.y)
        if not iid:
            return None
        if iid not in tree.selection():
            tree.selection_set(iid)
        try:
            tree.focus_force()
        except tk.TclError:
            tree.focus_set()
        tree.focus(iid)
        self._remember_selection_anchor(tree, iid)
        return iid

    def show_connection_menu(self, event, tree):
        iid = self._focus_menu_row(tree, event)
        if not iid:
            return
        menu = self._context_menu()
        actions = (('Allow Process', lambda: self.allow_process(tree), 'allowed'), ('Block Process (In & Out)', lambda: self.block_process(tree, 'both'), 'blocked'), ('Block Incoming Only', lambda: self.block_process(tree, 'in'), 'blocked_in'), ('Allow IP (Global)', lambda: self.bulk_global(tree, True, domain=False), 'global_allow'), ('Block IP (Global)', lambda: self.bulk_global(tree, False, domain=False), 'global_block'), ('Allow Domain (Global)', lambda: self.bulk_global(tree, True, domain=True), 'global_allow'), ('Block Domain (Global)', lambda: self.bulk_global(tree, False, domain=True), 'global_block'))
        for label, command, tag in actions[:3]:
            self._menu_rule_command(menu, label, command, tag)
        menu.add_separator()
        for label, command, tag in actions[3:]:
            self._menu_rule_command(menu, label, command, tag)
        menu.add_separator()
        menu.add_command(label='Open File Location', command=lambda iid=iid: self.open_file_location_from_tree(tree, iid))
        menu.add_command(label='Connection Details', command=lambda: self.show_connection_details(tree))
        menu.add_command(label='Copy Row', command=lambda: self.copy_rows(tree))
        menu.add_command(label='Remove App Rule', command=lambda: self.remove_selected_connection_rules(tree))
        menu.post(event.x_root, event.y_root)

    def show_rules_menu(self, event):
        iid = self._focus_menu_row(self.rules_tree, event)
        if not iid:
            return
        values = self.rules_tree.item(iid, 'values')
        status = str(values[0]).casefold() if values else ''
        menu = self._context_menu()
        actions = (('Allow Global', lambda: self.bulk_rule_global(True), 'global_allow'), ('Block Global', lambda: self.bulk_rule_global(False), 'global_block')) if status in {'global block', 'global allow'} else (('Allow Process', self.rules_menu_allow, 'allowed'), ('Block Process', lambda: self.rules_menu_block('both'), 'blocked'), ('Block Incoming', lambda: self.rules_menu_block('in'), 'blocked_in'))
        for label, command, tag in actions:
            self._menu_rule_command(menu, label, command, tag)
        if status not in {'global block', 'global allow'}:
            menu.add_command(label='Open File Location', command=lambda iid=iid: self.open_file_location_from_tree(self.rules_tree, iid))
        menu.add_command(label='Rule Details', command=lambda: self.show_rule_details(self.rules_tree))
        menu.add_command(label='Copy Row', command=lambda: self.copy_rows(self.rules_tree))
        menu.add_command(label='Remove Rule', command=self.remove_selected_rule)
        menu.post(event.x_root, event.y_root)

    def show_alert_menu(self, event):
        iid = self._focus_menu_row(self.alerts_tree, event)
        if not iid:
            return
        menu = self._context_menu()
        actions = (('Allow Process', lambda: self.alert_action(True, False), 'allowed'), ('Block Process (In & Out)', lambda: self.alert_action(False, False, 'both'), 'blocked'), ('Block Incoming Only', lambda: self.alert_action(False, False, 'in'), 'blocked_in'))
        for label, command, tag in actions:
            self._menu_rule_command(menu, label, command, tag)
        menu.add_separator()
        actions = (('Allow IP (Global)', lambda: self.alert_action(True, True), 'global_allow'), ('Block IP (Global)', lambda: self.alert_action(False, True), 'global_block'), ('Allow Domain (Global)', lambda: self.alert_global_domain(True), 'global_allow'), ('Block Domain (Global)', lambda: self.alert_global_domain(False), 'global_block'))
        for label, command, tag in actions:
            self._menu_rule_command(menu, label, command, tag)
        menu.add_command(label='Open File Location', command=lambda iid=iid: self.open_file_location_from_tree(self.alerts_tree, iid))
        menu.add_command(label='Alert Details', command=lambda iid=iid: self.alert_details(iid))
        menu.add_command(label='Copy Row', command=lambda: self.copy_rows(self.alerts_tree))
        menu.add_command(label='Remove App Rule', command=self.remove_selected_alert_rules)
        menu.post(event.x_root, event.y_root)

    def _context_menu(self):
        return tk.Menu(self.root, tearoff=False, bg=self.colors['sub'], fg=self.colors['fg'], activebackground=self.colors['select'], activeforeground='#ffffff')

    def _menu_rule_command(self, menu, label, command, rule_tag):
        rule_colors = {'allowed': '#4CAF50', 'blocked': '#f44336', 'blocked_in': '#ff9800', 'global_allow': '#2196F3', 'global_block': '#7B1FA2'}
        color = rule_colors.get(rule_tag, self.colors['fg'])
        menu.add_command(label=label, command=command, foreground=color, activeforeground='#ffffff')

    def _display_values(self, tree, iid):
        mapping = dict(zip(tree['columns'], tree.item(iid, 'values')))
        return tuple((mapping.get(column, '') for column in tree['displaycolumns']))

    def copy_rows(self, tree):
        rows = [self._display_values(tree, iid) for iid in tree.selection()]
        if rows:
            self.root.clipboard_clear()
            self.root.clipboard_append('\n'.join(('\t'.join(map(str, row)) for row in rows)))

    def tree_details_from_event(self, event, tree):
        iid = tree.identify_row(event.y)
        if iid:
            tree.selection_set(iid)
            tree.focus_set()
            tree.focus(iid)
            self._remember_selection_anchor(tree, iid)
            self.show_connection_details(tree)

    def rule_details_from_event(self, event):
        iid = self.rules_tree.identify_row(event.y)
        if iid:
            self.rules_tree.selection_set(iid)
            self.rules_tree.focus_set()
            self.rules_tree.focus(iid)
            self._remember_selection_anchor(self.rules_tree, iid)
            self.show_rule_details(self.rules_tree)

    def selected_connection_data(self, tree):
        result = []
        with self.lock:
            for iid, values in self.selected_rows(tree):
                row = self.active_connections.get(iid)
                if row:
                    result.append(dict(row))
                elif values:
                    columns = tuple(tree['columns'])
                    mapping = dict(zip(columns, values))
                    pid_value = mapping.get('PID', 0)
                    result.append({'key': iid, 'number': mapping.get('#', 0), 'name': mapping.get('Process Name', 'Process'), 'pid': int(pid_value) if str(pid_value).isdigit() else 0, 'direction': mapping.get('Direction', 'Both'), 'protocol': mapping.get('Protocol', ''), 'lport': mapping.get('Local Port', ''), 'dst_ip': mapping.get('Remote IP', ''), 'domain': '' if mapping.get('Remote Host', '—') == '—' else mapping.get('Remote Host', ''), 'dport': mapping.get('Remote Port', ''), 'signal': '' if mapping.get('Signal', '—') == '—' else mapping.get('Signal', ''), 'exe': mapping.get('Exe Path', '')})
        return result

    def block_process(self, tree=None, direction=None):
        tree = tree or self.tree
        rows = self.selected_connection_data(tree)
        paths = {}
        for row in rows:
            if row.get('exe'):
                paths.setdefault(normalize_path(row['exe']), row)
        if not paths:
            return
        prompt = f"How do you want to block {next(iter(paths.values()))['name']}?" if len(paths) == 1 else f'How do you want to block {len(paths)} selected processes?'
        direction = direction or self.ask_direction(prompt)
        if not direction:
            return
        for row in paths.values():
            self.block_executable(row['exe'], row['name'], direction, refresh=False, quiet=True)
        self.rules_changed()

    def allow_process(self, tree=None):
        tree = tree or self.tree
        rows = self.selected_connection_data(tree)
        seen = set()
        for row in rows:
            norm = normalize_path(row.get('exe'))
            if norm and norm not in seen:
                seen.add(norm)
                self.allow_executable(row['exe'], refresh=False, quiet=True)
        if seen:
            self.rules_changed()

    def rules_menu_allow(self):
        for _, values in self.selected_rows(self.rules_tree):
            if len(values) >= 6 and str(values[0]).casefold() not in {'global block', 'global allow'}:
                self.allow_executable(values[-1], refresh=False, quiet=True)
        self.rules_changed()

    def rules_menu_block(self, direction):
        for _, values in self.selected_rows(self.rules_tree):
            if len(values) < 6:
                continue
            if str(values[0]).casefold() in {'global block', 'global allow'}:
                continue
            path = values[-1]
            self.block_executable(path, os.path.splitext(os.path.basename(path))[0] or 'Process', direction, refresh=False, quiet=True)
        self.rules_changed()

    def remove_selected_rule(self, event=None):
        rows = self.selected_rows(self.rules_tree)
        if not rows:
            return
        changed = False
        for _, values in rows:
            if len(values) >= 6:
                changed |= self.remove_rule(values[0], values[-1], refresh=False)
        if changed:
            self.rules_changed()

    def remove_selected_connection_rules(self, tree):
        rows = self.selected_connection_data(tree)
        for row in rows:
            status = self.get_rule_status(row.get('exe', ''))
            if status:
                self.remove_rule(status, row['exe'], refresh=False)
            elif self.is_globally_blocked(row['dst_ip'], row.get('domain', '')):
                self.remove_rule('Global Block', row.get('domain') or row['dst_ip'], refresh=False)
            elif self.is_globally_allowed(row['dst_ip'], row.get('domain', '')):
                self.remove_rule('Global Allow', row.get('domain') or row['dst_ip'], refresh=False)
        self.rules_changed()

    def bulk_global(self, tree, allow, domain=False):
        targets = set()
        for _, values in self.selected_rows(tree):
            if len(values) < 8:
                continue
            candidate = str(values[7]).strip()
            if candidate in {'', '—'}:
                if allow and domain:
                    continue
                candidate = str(values[6]).strip()
            target = normalize_target(candidate)
            if target:
                targets.add(target)
        if not targets:
            messagebox.showinfo('Global Domain Rule' if domain else 'Global IP Rule', 'No domain was linked to the selected connection.' if domain else 'No valid target was selected.')
            return
        if not messagebox.askyesno('Global Rule', f"{('Allow' if allow else 'Block')} {len(targets)} selected target(s) globally?"):
            return
        for target in targets:
            self.add_global_rule(target, allow, refresh=False, quiet=True)
        self.rules_changed()

    def bulk_rule_global(self, allow):
        targets = {normalize_target(str(values[-1]).split(' (', 1)[0]) for _, values in self.selected_rows(self.rules_tree) if len(values) >= 6}
        for target in filter(None, targets):
            self.add_global_rule(target, allow, refresh=False, quiet=True)
        self.rules_changed()

    def _center_dialog(self, dialog, width=None, height=None):
        dialog.update_idletasks()
        width = max(1, int(width or dialog.winfo_reqwidth()))
        height = max(1, int(height or dialog.winfo_reqheight()))
        screen_width = dialog.winfo_screenwidth()
        screen_height = dialog.winfo_screenheight()
        x = max(0, (screen_width - width) // 2)
        y = max(0, (screen_height - height) // 2)
        dialog.geometry(f'{width}x{height}+{x}+{y}')

    def _theme_dialog(self, dialog):
        dialog.configure(bg=self.colors['frame'])

    def _show_details_dialog(self, title, text, tooltip):
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.resizable(False, False)
        dialog.withdraw()
        dialog.transient(self.root)
        self._theme_dialog(dialog)
        body = tk.Frame(dialog, bg=self.colors['frame'])
        body.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)
        label = tk.Label(body, text=text, justify=tk.LEFT, anchor=tk.NW, bg=self.colors['frame'], fg=self.colors['fg'], font=('Segoe UI', 10), padx=14, pady=12)
        label.pack(fill=tk.X)
        button = tk.Button(body, text='Close', command=dialog.destroy, bg=self.colors.get('button', '#757575'), fg='#ffffff', activebackground=self.colors.get('head', '#2d2d30'), activeforeground='#ffffff', relief='flat', font=('Segoe UI', 9, 'bold'), padx=12, pady=4)
        self._bind_button_hover(button)
        button.pack(pady=(2, 8))
        add_tooltip(button, tooltip)
        dialog.protocol('WM_DELETE_WINDOW', dialog.destroy)
        dialog.update_idletasks()
        max_width = max(520, int(dialog.winfo_screenwidth() * 0.85))
        requested_width = dialog.winfo_reqwidth()
        target_width = min(max(requested_width, 650), max_width)
        if requested_width > max_width:
            label.configure(wraplength=max_width - 60)
            dialog.update_idletasks()
            target_width = max_width
        self._center_dialog(dialog, target_width, dialog.winfo_reqheight())
        dialog.deiconify()
        dialog.lift()
        dialog.focus_force()

    def show_connection_details(self, tree):
        rows = self.selected_connection_data(tree)
        if not rows:
            return
        row = rows[0]
        norm = normalize_path(row.get('exe'))
        with self.lock:
            stats = self.proc_traffic.get(norm, {})
            active_count = sum((normalize_path(item.get('exe')) == norm for item in self.active_connections.values()))
        status = self.get_rule_status(row['exe']) or 'No managed app rule'
        policy = 'Global Block' if self.is_globally_blocked(row['dst_ip'], row.get('domain', '')) else 'Global Allow' if self.is_globally_allowed(row['dst_ip'], row.get('domain', '')) else 'None'
        text = f"Process: {row['name']}\nPID: {row['pid']}\nExecutable: {row['exe']}\n\nProtocol: {row['protocol']} ({row['direction']})\nLocal Port: {row['lport']}\nRemote: {row['dst_ip']}:{row['dport']}\nRemote Host: {row.get('domain') or 'Unresolved'}\nSignal: {row.get('signal') or 'None'}\n\nApplication Rule: {status}\nGlobal Policy: {policy}\nActive Connections: {active_count}\nProcess Download: {mb(stats.get('download', 0))}\nProcess Upload: {mb(stats.get('upload', 0))}"
        self._show_details_dialog('Connection Details', text, 'Close the Connection Details window.')

    def show_rule_details(self, tree):
        rows = self.selected_rows(tree)
        if not rows or len(rows[0][1]) < 6:
            return
        status, rule, direction, down, up, path = rows[0][1]
        extra = ''
        if str(status).casefold() in {'global block', 'global allow'}:
            target = normalize_target(str(path).split(' (', 1)[0])
            with self.lock:
                store = self.global_blocks if str(status).casefold() == 'global block' else self.global_allows
                data = store.get(target, {})
            extra = '\nResolved Addresses: ' + (', '.join(data.get('addresses', ())) or 'Unknown')
        text = f'Status: {status}\nRule: {rule}\nDirection: {direction}\nDownload: {down}\nUpload: {up}\nPath/Target: {path}{extra}'
        self._show_details_dialog('Rule Details', text, 'Close the Rule Details window.')

    def alert_details_from_event(self, event):
        iid = self.alerts_tree.identify_row(event.y)
        if not iid:
            return 'break'
        self.alerts_tree.selection_set(iid)
        self.alerts_tree.focus_set()
        self.alerts_tree.focus(iid)
        self._remember_selection_anchor(self.alerts_tree, iid)
        self.alert_details(iid)
        return 'break'

    def alert_details(self, iid):
        values = self.alerts_tree.item(iid, 'values')
        if not values:
            return
        text = f'Time: {values[0]}\nSeverity: {values[1]}\nProcess: {values[2]}\nPID: {values[3]}\nRemote: {values[4]}\nRemote Host: {values[5]}\n\nReason: {values[6]}'
        self._show_details_dialog('Alert Details', text, 'Close the Alert Details window.')

    def alert_context(self, values):
        remote = str(values[4])
        pid = int(values[3]) if str(values[3]).isdigit() else None
        with self.lock:
            matches = [dict(row) for row in self.active_connections.values() if pid is not None and row['pid'] == pid and (normalize_target(row['dst_ip']) == normalize_target(remote) or normalize_target(row.get('domain', '')) == normalize_target(remote))]
            if not matches and pid is not None:
                matches = [dict(row) for row in self.active_connections.values() if row['pid'] == pid]
        if matches:
            return (matches[0], matches[0]['dst_ip'])
        remote_ip = remote
        if ':' in remote:
            candidate, _, port = remote.rpartition(':')
            if candidate and port.isdigit() and is_ip(candidate):
                remote_ip = candidate
        return (None, remote_ip)

    def alert_action(self, allow, global_target, direction='both'):
        for _, values in self.selected_rows(self.alerts_tree):
            row, remote_ip = self.alert_context(values)
            if global_target:
                self.add_global_rule(remote_ip, allow, refresh=False, quiet=True)
            elif row and row.get('exe'):
                if allow:
                    self.allow_executable(row['exe'], refresh=False, quiet=True)
                else:
                    self.block_executable(row['exe'], row['name'], direction, refresh=False, quiet=True)
        self.rules_changed()

    def alert_global_domain(self, allow):
        targets = set()
        for _, values in self.selected_rows(self.alerts_tree):
            row, _ = self.alert_context(values)
            domain = (row or {}).get('domain', '')
            if not domain and len(values) > 5 and (values[5] not in {'', '—'}):
                domain = values[5]
            if domain and (not is_ip(domain)):
                targets.add(normalize_target(domain))
        if not targets:
            messagebox.showinfo('Global Domain Rule', 'No domain was linked to the selected alert.')
            return
        for target in targets:
            self.add_global_rule(target, allow, refresh=False, quiet=True)
        self.rules_changed()

    def remove_selected_alert_rules(self):
        changed = False
        for _, values in self.selected_rows(self.alerts_tree):
            row, remote_ip = self.alert_context(values)
            if row and row.get('exe'):
                status = self.get_rule_status(row['exe'])
                if status:
                    changed |= self.remove_rule(status, row['exe'], refresh=False)
        if changed:
            self.rules_changed()

    def export_connections(self, tree=None):
        tree = tree or self.tree
        rows = tree.get_children()
        if not rows:
            messagebox.showinfo('Export Connections', 'There are no visible connections.')
            return
        path = filedialog.asksaveasfilename(title='Export Live Connections', defaultextension='.csv', filetypes=[('CSV files', '*.csv'), ('All files', '*.*')])
        if not path:
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(tuple(tree['displaycolumns']))
                for iid in rows:
                    writer.writerow(self._display_values(tree, iid))
            messagebox.showinfo('Export Complete', f'Exported connections to:\n{path}')
        except Exception as exc:
            messagebox.showerror('Export Failed', str(exc))

    def export_rules(self):
        path = filedialog.asksaveasfilename(title='Export Managed Rules', defaultextension='.json', initialfile='firewall_rules.json', filetypes=[('JSON files', '*.json'), ('All files', '*.*')])
        if not path:
            return
        try:
            with self.lock:
                data = {'format': 'PyFirewall managed rules', 'version': 4, 'exported_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'rules': [{'action': 'Allow', 'direction': 'Both', 'path': path_value} for path_value in sorted(self.allowed_apps)] + [{'action': 'Block', 'direction': self._direction_from_flags(value), 'path': value['path']} for value in self.blocked_paths.values()], 'global_ip_blocks': [{'target': target, 'addresses': list(data.get('addresses', ()))} for target, data in sorted(self.global_blocks.items())], 'global_ip_allows': [{'target': target, 'addresses': list(data.get('addresses', ()))} for target, data in sorted(self.global_allows.items())]}
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            messagebox.showinfo('Export Complete', f'Exported managed rules to:\n{path}')
        except Exception as exc:
            messagebox.showerror('Export Failed', str(exc))

    def import_rules(self):
        path = filedialog.askopenfilename(title='Import Managed Rules', filetypes=[('JSON files', '*.json'), ('All files', '*.*')])
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError('Invalid rules file.')
            rules = data.get('rules', data.get('managed_rules', []))
            blocks = data.get('global_ip_blocks', []) or []
            allows = data.get('global_ip_allows', []) or []
            total = len(rules) + len(blocks) + len(allows)
            if not total:
                messagebox.showerror('Import Rules', 'No valid managed rules were found.')
                return
            if not messagebox.askyesno('Import Rules', f'Apply {total} imported rule(s)?'):
                return
            failures = []
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                path_value = display_path(rule.get('path', ''))
                if not path_value:
                    continue
                action = str(rule.get('action', 'Block')).casefold()
                if 'allow' in action:
                    if not self.allow_executable(path_value, refresh=False, quiet=True):
                        failures.append(path_value)
                else:
                    if not self.block_executable(path_value, os.path.splitext(os.path.basename(path_value))[0] or 'Process', direction_name(rule.get('direction', 'Both')), refresh=False, quiet=True):
                        failures.append(path_value)
            for entry in blocks:
                target = entry.get('target', '') if isinstance(entry, dict) else entry
                if target:
                    if not self.add_global_rule(target, False, refresh=False, quiet=True):
                        failures.append(target)
            for entry in allows:
                target = entry.get('target', '') if isinstance(entry, dict) else entry
                if target:
                    if not self.add_global_rule(target, True, refresh=False, quiet=True):
                        failures.append(target)
            self.rules_changed()
            if failures:
                messagebox.showerror('Import Incomplete', 'Failed rules:\n' + '\n'.join(failures))
            else:
                messagebox.showinfo('Import Complete', 'Imported rules were applied.')
        except Exception as exc:
            messagebox.showerror('Import Failed', str(exc))

    def open_windows_firewall(self):
        try:
            subprocess.Popen(['control.exe', '/name', 'Microsoft.WindowsFirewall'], creationflags=CREATE_NO_WINDOW)
        except Exception as exc:
            messagebox.showerror('Windows Firewall', str(exc))

    def target_traffic(self, target, addresses=()):
        with self.lock:
            return self._target_traffic_locked(target, addresses)

    def _target_traffic_locked(self, target, addresses=()):
        candidates = {normalize_target(target)}
        candidates.update((normalize_target(a) for a in addresses if normalize_target(a)))
        down = up = 0
        for ip, stats in self.ip_traffic.items():
            if ip in candidates:
                down += stats.get('download', 0)
                up += stats.get('upload', 0)
        return (down, up)

    def render_rule_traffic(self):
        with self.lock:
            proc_traffic = {key: dict(value) for key, value in self.proc_traffic.items()}
        for row in self.rule_rows:
            if row.get('global_type'):
                row['download'], row['upload'] = self.target_traffic(row['normalized_path'], row.get('addresses', ()))
            else:
                stats = proc_traffic.get(row['normalized_path'], {})
                row['download'] = stats.get('download', 0)
                row['upload'] = stats.get('upload', 0)

    def drain_ui_queue(self):
        while True:
            try:
                item = self.ui_queue.get_nowait()
            except queue.Empty:
                return
            if item[0] == 'dns':
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

    def drain_prompt_queue(self):
        with self.lock:
            if self.auto_prompt_active:
                return
        try:
            item = self.prompt_queue.get_nowait()
        except queue.Empty:
            return
        generation, key, proc_name, exe, pid, remote_ip, domain, direction, reason, detail = item
        with self.lock:
            current_generation = generation == self.auto_prompt_generation
        active = self._auto_block_active()
        has_app_rule = self.application_has_rule(exe)
        has_global_rule = self.is_globally_blocked(remote_ip, domain) or self.is_globally_allowed(remote_ip, domain)
        if not current_generation or not active or has_app_rule or has_global_rule:
            with self.firewall_lock:
                self.remove_auto_holds_locked(None if not active else normalize_path(exe))
            with self.lock:
                self.auto_prompt_keys.discard(key)
            return
        with self.lock:
            self.auto_prompt_active = True
            self.auto_prompt_key = key
        self.show_auto_prompt(generation, key, proc_name, exe, pid, remote_ip, reason, detail)

    def _auto_block_active(self):
        with self.lock:
            return self.log_alerts_only and self.auto_block_enabled and (not self.is_paused) and (not self.closed)

    def _auto_decision_worker(self, generation, key, exe, proc_name, choice, result_queue):
        """Apply a decision without calling Tk; the prompt owns result delivery."""
        ok = None
        try:
            with self.firewall_lock:
                with self.lock:
                    current = (not self.closed and generation == self.auto_prompt_generation
                               and self.auto_prompt_key == key)
                if current:
                    if choice == 'allow':
                        ok = self.allow_executable(exe, refresh=False, quiet=True, update_ui=False)
                    else:
                        ok = self.block_executable(exe, proc_name, 'in' if choice == 'in' else 'both',
                                                   refresh=False, quiet=True, update_ui=False)
        except Exception as exc:
            ok = False
            log_internal_error('auto_decision', exc)
            self.queue_alert('High', exe, '', '', f'Firewall decision failed: {exc}')
        finally:
            result_queue.put(ok)

    def show_auto_prompt(self, generation, key, proc_name, exe, pid, remote_ip, reason, detail):
        dialog = tk.Toplevel(self.root)
        with self.lock:
            self.auto_prompt_dialog = dialog
            self.auto_prompt_key = key
        dialog.title('Auto-Block Protection')
        dialog.resizable(False, False)
        dialog.withdraw()
        self._theme_dialog(dialog)
        message = f"{proc_name} reached an Auto-Block threshold.\n\nRemote target: {remote_ip}\nTrigger: {reason.title()}{(f' ({detail})' if detail else '')}\n\nTemporary protection is already blocking this executable while you decide."
        body = tk.Frame(dialog, bg=self.colors['frame'])
        body.pack(fill=tk.BOTH, expand=True, padx=20, pady=(16, 10))
        tk.Label(body, text=message, justify=tk.LEFT, anchor=tk.W, wraplength=470, bg=self.colors['frame'], fg=self.colors['fg'], font=('Segoe UI', 10)).pack(fill=tk.X)
        buttons = tk.Frame(dialog, bg=self.colors['frame'])
        buttons.pack(fill=tk.X, padx=16, pady=(0, 14))
        buttons.grid_columnconfigure((0, 1, 2), weight=1)

        finished = False
        decision_buttons = []
        result_queue = queue.Queue(maxsize=1)
        applying = tk.Label(body, text='', anchor=tk.W, bg=self.colors['frame'], fg=self.colors['fg'])
        applying.pack(fill=tk.X)

        def poll_decision():
            nonlocal finished
            if self.closed:
                return
            try:
                ok = result_queue.get_nowait()
            except queue.Empty:
                self.root.after(50, poll_decision)
                return
            with self.lock:
                current = (generation == self.auto_prompt_generation
                           and self.auto_prompt_dialog is dialog and self.auto_prompt_key == key)
            if ok:
                if current:
                    self._cancel_app_prompt(key)
            elif current and ok is False:
                finished = False
                for button in decision_buttons:
                    button.configure(state=tk.NORMAL)
                applying.configure(text='Could not apply decision. Please retry.')
                messagebox.showerror('Firewall Update Failed',
                                     'The decision could not be applied. Review Alerts for details and retry.', parent=dialog)
            # Also reconcile failed/cancelled work, whose start invalidated an
            # older rule refresh and whose rollback may have reconciled caches.
            self.rules_changed()

        def finish(choice):
            nonlocal finished
            if finished:
                return
            with self.lock:
                current = generation == self.auto_prompt_generation and not self.closed
            if not current:
                return
            finished = True
            for button in decision_buttons:
                button.configure(state=tk.DISABLED)
            applying.configure(text='Applying decision...')
            # Reject snapshots taken before this mutation; refresh on completion.
            with self.lock:
                self.rules_generation += 1
            worker = threading.Thread(target=self._auto_decision_worker,
                                      args=(generation, key, exe, proc_name, choice, result_queue),
                                      daemon=True, name='PyFirewall-Decision')
            try:
                worker.start()
            except Exception as exc:
                self.queue_alert('High', exe, pid, remote_ip, f'Could not start firewall decision: {exc}')
                result_queue.put(False)
            self.root.after(50, poll_decision)
        action_specs = (('Block In & Out', 'both', '#f44336', 'Block the executable for both incoming and outgoing traffic.'), ('Block Incoming Only', 'in', '#ff9800', 'Block incoming traffic while leaving outgoing traffic allowed.'), ('Allow All', 'allow', '#4CAF50', 'Remove the temporary block and allow the executable.'))
        for column, (label, choice, bg, tip) in enumerate(action_specs):
            button = tk.Button(buttons, text=label, command=lambda value=choice: finish(value), bg=bg, fg='white', activebackground=bg, activeforeground='white', relief='flat', font=('Segoe UI', 9, 'bold'), padx=10, pady=5)
            decision_buttons.append(button)
            self._bind_button_hover(button)
            button.grid(row=0, column=column, sticky='ew', padx=3, pady=(0, 6))
            add_tooltip(button, tip)
        cancel = tk.Button(buttons, text='Cancel (Block)', command=lambda: finish('both'), bg=self.colors.get('button', '#757575'), fg='#ffffff', activebackground=self.colors.get('head', '#2d2d30'), activeforeground='#ffffff', relief='flat', font=('Segoe UI', 9, 'bold'), padx=10, pady=5)
        decision_buttons.append(cancel)
        self._bind_button_hover(cancel)
        cancel.grid(row=1, column=0, columnspan=3, sticky='ew', padx=3, pady=(0, 0))
        add_tooltip(cancel, 'Dismiss the prompt and keep the executable blocked.')
        dialog.protocol('WM_DELETE_WINDOW', lambda: finish('both'))
        dialog.update_idletasks()
        self._center_dialog(dialog)
        dialog.deiconify()
        dialog.lift()
        dialog.focus_force()
        dialog.attributes('-topmost', True)

        def release_topmost():
            try:
                if dialog.winfo_exists():
                    dialog.attributes('-topmost', False)
            except tk.TclError:
                pass
        dialog.after(250, release_topmost)

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
        elif not self.capture_healthy:
            self.status_state.config(text='Capture failed' if self.capture_error is not None else 'Starting capture', fg='#f44336')
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
                self.render_active()
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
        self.active_tree.delete(*self.active_tree.get_children())

    def minimize_to_tray(self):
        if self.closed or self.tray_hidden:
            return
        try:
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
        with self.lock:
            self.closed = True
            self.sniffing = False
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
if __name__ == '__main__':
    root = tk.Tk()
    if os.path.exists(ICON_FILE):
        try:
            root.iconbitmap(default=ICON_FILE)
        except tk.TclError:
            pass
    app = FirewallMonitorApp(root)
    root.mainloop()
