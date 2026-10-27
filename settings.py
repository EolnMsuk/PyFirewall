"""Settings UI, saved preferences, reset behavior and support dialogs."""

import ctypes
import json
import os
import threading
import tkinter as tk
from collections import deque
from tkinter import messagebox, ttk

from constants import (
    CONFIG_FILE,
    CRYPTO_WALLETS,
    DEFAULT_CHECK_UPDATES_ON_STARTUP,
    DEFAULT_DARK_MODE,
    DEFAULT_LOG_ALERTS_ONLY,
    DEFAULT_MAX_CONNECTIONS_ALERTS,
    DEFAULT_RATE_THRESHOLD,
    DEFAULT_RATE_WINDOW,
    DEFAULT_UPLOAD_THRESHOLD_MB,
    ICON_FILE,
    SCRIPT_DIR,
    __version__,
)
from helpers import direction_name, direction_set, display_path, normalize_path, normalize_target
from widgets import add_tooltip

class SettingsMixin:
    """Methods composed into FirewallMonitorApp; state is owned by that application."""

    # Configuration persistence

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
            self.keep_notification_foreground = bool(config.get('keep_notification_foreground', True))
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
            self.check_updates_on_startup = config.get('check_updates_on_startup', DEFAULT_CHECK_UPDATES_ON_STARTUP) is True
            self.firewall_initialized = bool(config.get('firewall_initialized', False))
            for preference in ('column_orders', 'hidden_columns', 'column_widths'):
                layouts = config.get(preference, {})
                saved_rules = layouts.get('rules') if isinstance(layouts, dict) else None
                old_names = ('Rule / Application', 'Application / Domain IP')
                if isinstance(saved_rules, dict):
                    for old_name in old_names:
                        if old_name in saved_rules:
                            saved_rules.setdefault('Application & Global Rules', saved_rules.pop(old_name))
                elif isinstance(saved_rules, (list, tuple)):
                    layouts['rules'] = ['Application & Global Rules' if c in old_names else c
                                        for c in saved_rules]
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
                    self.column_orders[key] = list(dict.fromkeys(valid))
            hidden = config.get('hidden_columns', {})
            self.hidden_columns = {key: [c for c in hidden.get(key, []) if c in default]
                                   for key, default in self.default_column_orders.items()
                                   if isinstance(hidden, dict) and isinstance(hidden.get(key, []), list)}
            widths = config.get('column_widths', {})
            self.column_widths = {}
            if isinstance(widths, dict):
                for key, columns in self.default_column_orders.items():
                    saved = widths.get(key, {})
                    if isinstance(saved, dict):
                        self.column_widths[key] = {c: w for c, w in saved.items()
                                                   if c in columns and type(w) is int and 1 <= w <= 10000}
            size = config.get('window_size')
            self.window_size = (list(size) if isinstance(size, (list, tuple)) and len(size) == 2
                                and all(type(n) is int and 1 < n <= 30000 for n in size) else None)
            self.window_maximized = config.get('window_maximized', False) is True
            position = config.get('window_position')
            self.window_position = (list(position) if isinstance(position, (list, tuple)) and len(position) == 2
                                    and all(type(n) is int and -100000 <= n <= 100000 for n in position) else None)
            self.allowed_apps = {normalize_path(p) for p in config.get('allowed_apps', []) if normalize_path(p)}
            self.global_ports = self._parse_port_rules(config.get('global_port_rules', []))
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
                    self.global_blocks[target] = {'addresses': tuple((str(a) for a in addresses if str(a).strip())), 'direction': direction_name(entry.get('direction', 'Both') if isinstance(entry, dict) else 'Both')}
            for entry in config.get('global_ip_allows', []) or []:
                target = normalize_target(entry.get('target', '') if isinstance(entry, dict) else entry)
                if target and target not in self.global_blocks:
                    addresses = entry.get('addresses', []) if isinstance(entry, dict) else []
                    self.global_allows[target] = {'addresses': tuple((str(a) for a in addresses if str(a).strip())), 'direction': direction_name(entry.get('direction', 'Both') if isinstance(entry, dict) else 'Both')}
        self.rate_threshold_var.set(str(self.rate_threshold))
        self.rate_window_var.set(str(self.rate_window))
        self.upload_threshold_var.set(str(self.upload_threshold_mb))
        self.max_connections_alerts_var.set(str(self.max_connections_alerts))
        self.log_alerts_var.set(self.log_alerts_only)
        self.auto_block_var.set(self.auto_block_enabled)
        self.keep_notification_foreground_var.set(self.keep_notification_foreground)
        self.dark_mode_var.set(self.dark_mode)
        self.check_updates_on_startup_var.set(self.check_updates_on_startup)

    def save_settings(self):
        temp = CONFIG_FILE + '.tmp'
        try:
            with self.settings_io_lock:
                with self.lock:
                    managed = [{'action': 'Allow', 'direction': 'Both', 'path': path} for path in sorted(self.allowed_apps)]
                    managed += [{'action': 'Block', 'direction': self._direction_from_flags(data), 'path': data.get('path', normalized)} for normalized, data in sorted(self.blocked_paths.items())]
                    config = {'filter_all_enabled': self.filter_all_enabled, 'filter_all_saved_alerts': self.filter_all_saved_alerts, 'filter_all_saved_auto_block': self.filter_all_saved_auto_block, 'saved_rate_threshold': self.saved_rate_threshold, 'rate_threshold': self.rate_threshold, 'rate_window': self.rate_window, 'upload_threshold_mb': self.upload_threshold_mb, 'max_connections_alerts': self.max_connections_alerts, 'log_alerts_only_enabled': self.log_alerts_only, 'auto_block_enabled': self.auto_block_enabled, 'allowed_apps': sorted(self.allowed_apps), 'managed_rules': managed, 'global_ip_blocks': [{'target': target, 'addresses': list(data.get('addresses', ())), 'direction': data.get('direction', 'Both')} for target, data in sorted(self.global_blocks.items())], 'global_ip_allows': [{'target': target, 'addresses': list(data.get('addresses', ())), 'direction': data.get('direction', 'Both')} for target, data in sorted(self.global_allows.items())], 'global_port_rules': list(getattr(self, 'global_ports', {}).values()), 'hidden_columns': getattr(self, 'hidden_columns', {}), 'dark_mode': bool(self.dark_mode), 'firewall_initialized': self.firewall_initialized, 'column_orders': {key: list(order) for key, order in self.column_orders.items()}}
                    config['check_updates_on_startup'] = self.check_updates_on_startup
                    config['keep_notification_foreground'] = getattr(self, 'keep_notification_foreground', True)
                    config['column_widths'] = getattr(self, 'column_widths', {})
                    config['window_size'] = getattr(self, 'window_size', None)
                    config['window_position'] = getattr(self, 'window_position', None)
                    config['window_maximized'] = getattr(self, 'window_maximized', False)
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

    # Settings page and support dialogs

    def setup_settings_tab(self):
        # Keep settings management reachable on screens smaller than the content.
        canvas = self.settings_canvas = tk.Canvas(self.tab_settings, highlightthickness=0, bd=0,
                                                  bg=self.colors['frame'])
        scrollbar = ttk.Scrollbar(self.tab_settings, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        outer = tk.Frame(canvas, padx=30, pady=25)
        content = canvas.create_window((0, 0), window=outer, anchor=tk.NW)
        def update_scroll_region(_event=None):
            viewport_height = canvas.winfo_height()
            content_height = outer.winfo_reqheight()
            overflow = content_height > viewport_height
            # A scroll region smaller than the viewport lets Tk move the page
            # into blank space. Pin it to the viewport when everything fits.
            canvas.configure(scrollregion=(0, 0, canvas.winfo_width(),
                                           max(content_height, viewport_height)))
            if overflow:
                if not scrollbar.winfo_manager():
                    scrollbar.pack(side=tk.RIGHT, fill=tk.Y, before=canvas)
            else:
                scrollbar.pack_forget()
                canvas.yview_moveto(0)

        def resize_settings(event):
            canvas.itemconfigure(content, width=event.width)
            update_scroll_region()

        outer.bind('<Configure>', update_scroll_region)
        canvas.bind('<Configure>', resize_settings)

        def scroll_settings(event):
            if (str(event.widget).startswith(str(self.tab_settings) + '.')
                    and outer.winfo_height() > canvas.winfo_height() and event.delta):
                canvas.yview_scroll(-3 if event.delta > 0 else 3, 'units')
                return 'break'
        self.root.bind('<MouseWheel>', scroll_settings, add='+')
        self.settings_monitor_controls = tk.LabelFrame(
            outer, text='Monitor & Filter', padx=18, pady=14)
        self.settings_monitor_controls.pack(fill=tk.X, pady=(0, 18))
        self.settings_monitor_controls.columnconfigure(1, weight=1)
        self._make_monitor_controls(self.settings_monitor_controls, prefix='settings_', stacked=True)
        for row, description in enumerate((
                'Pause or Resume the live capture and threshold rules.',
                'Filter All Connections auto-blocks and prompts for every new process (requires Monitoring).')):
            tk.Label(self.settings_monitor_controls, text=description, fg=self.colors['muted'],
                     wraplength=600, justify=tk.LEFT).grid(row=row, column=1, sticky=tk.W,
                                                         padx=(18, 0), pady=(0, 12) if row == 0 else 0)
        frame = tk.LabelFrame(outer, text='Auto-Block Protection', padx=18, pady=14)
        frame.pack(fill=tk.X)
        self.chk_alerts = ttk.Checkbutton(frame, text='Enable Alerts (required for Auto-Block)', variable=self.log_alerts_var, command=self.on_log_alerts_changed)
        self.chk_alerts.grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=5)
        self.chk_auto = ttk.Checkbutton(frame, text='Enable Auto-Block Protection', variable=self.auto_block_var, command=self.on_auto_block_changed)
        self.chk_auto.grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=5)
        self.chk_foreground = ttk.Checkbutton(frame, text='Enable Keep Notification in Foreground',
                                            variable=self.keep_notification_foreground_var,
                                            command=self.on_notification_foreground_changed)
        self.chk_foreground.grid(row=2, column=0, columnspan=3, sticky=tk.W, pady=5)
        fields = (('Max Connections Threshold', self.rate_threshold_var, 'connections / process / target'), ('Time Window', self.rate_window_var, 'seconds'), ('Max Upload Threshold', self.upload_threshold_var, 'MB / process / target IP'))
        for row, (label, variable, suffix) in enumerate(fields, 3):
            tk.Label(frame, text=label).grid(row=row, column=0, sticky=tk.W, pady=6)
            entry = ttk.Entry(frame, textvariable=variable, width=10)
            entry.grid(row=row, column=1, sticky=tk.W, padx=(12, 0), pady=6)
            if row == 3:
                self.rate_threshold_entry = entry
            elif row == 4:
                self.rate_window_entry = entry
            tk.Label(frame, text=suffix, fg=self.colors['muted']).grid(row=row, column=2, sticky=tk.W, padx=8)
        tk.Label(frame, text='Max Connections / Alerts').grid(row=6, column=0, sticky=tk.W, pady=6)
        ttk.Entry(frame, textvariable=self.max_connections_alerts_var, width=10).grid(row=6, column=1, sticky=tk.W, padx=(12, 0), pady=6)
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


        venmo_url = 'https://venmo.com/u/rustonrails'
        github_url = 'https://github.com/EolnMsuk/PyFirewall'

        def open_support_link(url):
            try:
                os.startfile(url)
            except OSError:
                pass

        def bind_support_link(widget, url):
            widget.bind('<Button-1>', lambda _event: open_support_link(url))
            def copy_link():
                self.root.clipboard_clear()
                self.root.clipboard_append(url)

            def show_link_menu(event):
                menu = self._context_menu()
                menu.add_command(label='Copy Link', command=copy_link)
                menu.post(event.x_root, event.y_root)
                return 'break'

            widget.bind('<Button-3>', show_link_menu)

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

                    self.settings_icon_photo = icon_image.subsample(2, 2)

                    icon_label = tk.Label(
                        support,
                        image=self.settings_icon_photo,
                        bg=self.colors['frame'],
                        cursor='hand2',
                        borderwidth=0,
                        highlightthickness=0,
                        relief=tk.FLAT
                    )
                    icon_label.grid(row=0, column=0, rowspan=3, sticky=tk.W, padx=(0, 16))
                    bind_support_link(icon_label, github_url)
                    add_tooltip(icon_label, 'Open the PyFirewall GitHub page.')
        except (OSError, ValueError, struct.error, tk.TclError):
            pass

        donation_label = tk.Label(
            support,
            text='Donate via Venmo',
            bg=self.colors['frame'],
            fg=self.colors['select'],
            cursor='hand2',
            font=('Segoe UI', 10, 'underline')
        )
        donation_label.grid(row=0, column=1, sticky=tk.SW, pady=2)
        bind_support_link(donation_label, venmo_url)
        add_tooltip(donation_label, 'Open venmo.com/u/rustonrails in your default browser.')

        crypto_label = tk.Label(
            support, text='Donate via Crypto',
            bg=self.colors['frame'], fg=self.colors['select'], cursor='hand2',
            font=('Segoe UI', 10, 'underline'))
        crypto_label.grid(row=1, column=1, sticky=tk.W, pady=2)
        crypto_label.bind('<Button-1>', lambda _event: self.show_crypto_wallets())
        add_tooltip(crypto_label, 'View EolnMsuk’s crypto wallets and click an address to copy it for a donation.')

        github_label = tk.Label(
            support,
            text='PyFirewall GitHub',
            bg=self.colors['frame'],
            fg=self.colors['select'],
            cursor='hand2',
            font=('Segoe UI', 10, 'underline')
        )
        github_label.grid(row=2, column=1, sticky=tk.NW, pady=2)
        bind_support_link(github_label, github_url)
        add_tooltip(github_label, 'Open the PyFirewall GitHub repository.')
        for link in (donation_label, crypto_label, github_label):
            link._theme_foreground_key = 'select'

        management = tk.LabelFrame(outer, text='Manage Updates / Rules / Settings', padx=18, pady=14)
        management.pack(fill=tk.X)
        management.columnconfigure(1, weight=1)
        self.chk_updates = ttk.Checkbutton(management, text='Check for updates on startup',
                                          variable=self.check_updates_on_startup_var,
                                          command=self.on_update_setting_changed)
        self.chk_updates.grid(row=0, column=0, sticky=tk.W, pady=(0, 12))
        self.btn_check_updates = self._button(management, 'Check for Updates', self.check_for_updates, '#2196F3', pack=False,
                                             tooltip='Check GitHub for a newer version. No files are downloaded or installed.')
        self.btn_check_updates.grid(row=1, column=0, sticky=tk.E, pady=(0, 12))
        self._button(management, 'Export Rules', self.export_rules, pack=False).grid(
            row=2, column=0, sticky=tk.E, pady=(0, 12))
        self._button(management, 'Import Rules', self.import_rules, pack=False,
                     tooltip='Restore managed application, global IP/domain, and global port rules from a JSON backup file.').grid(
            row=3, column=0, sticky=tk.E, pady=(0, 12))
        self._button(management, 'Reset to Defaults', self.reset_to_defaults, '#ff9800', pack=False).grid(
            row=4, column=0, sticky=tk.E, pady=(0, 12))
        self._button(management, 'Uninstall PyFirewall', self.uninstall_pyfirewall, '#c62828', pack=False,
                     tooltip='Open the PyFirewall uninstaller with administrator privileges after confirmation.').grid(
            row=5, column=0, sticky=tk.E)
        for row, description in enumerate((
                'Check for updates at startup, prompts user when one is available.',
                f'Manually check for updates. PyFirewall v{__version__} is currently installed.',
                'Export managed global IP/domain, and global port rules to a JSON backup file.',
                'Import and apply managed global IP/domain, and global port rules from a JSON backup file.',
                'Reset settings to default and remove all PyFirewall rules.',
                'Launch the uninstaller, with options to keep or remove dependencies used / installed by PyFirewall.')):
            tk.Label(management, text=description, fg=self.colors['muted'], wraplength=700,
                     justify=tk.LEFT).grid(row=row, column=1, sticky=tk.W, padx=(18, 0),
                                          pady=(0, 12) if row < 5 else 0)
        support.pack(fill=tk.X, pady=(18, 0))
        self.update_auto_block_controls()

    def uninstall_pyfirewall(self):
        script = os.path.join(SCRIPT_DIR, 'Uninstall-PyFirewall.cmd')
        if not os.path.isfile(script):
            messagebox.showerror('Uninstall PyFirewall', f'The uninstall script was not found:\n{script}', parent=self.root)
            return
        if not messagebox.askyesno(
                'Uninstall PyFirewall',
                'Are you sure you want to uninstall PyFirewall?\n\n'
                'The uninstaller will let you choose what to remove, including optional dependencies '
                'such as Python, Npcap, psutil, and Scapy. You can keep dependencies used by other applications.\n\n'
                'Windows may ask for administrator permission. Continue?',
                icon='warning', parent=self.root):
            return
        try:
            # The interactive uninstaller owns subsequent choices and stops the
            # monitor when needed. Launch visibly without blocking Tk's loop.
            result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', script, None, SCRIPT_DIR, 1)
            if result <= 32:
                raise OSError(f'Windows could not launch the uninstaller (code {result}). '
                              'Administrator permission may have been declined.')
        except Exception as exc:
            messagebox.showerror('Uninstall PyFirewall', str(exc), parent=self.root)

    def show_crypto_wallets(self):
        existing = getattr(self, 'crypto_dialog', None)
        if existing is not None and existing.winfo_exists():
            existing.lift()
            existing.focus_set()
            return
        dialog = self.crypto_dialog = tk.Toplevel(self.root)
        dialog.withdraw()
        dialog.title('Donate via Crypto • EolnMsuk')
        dialog.transient(self.root)
        dialog._crypto_dialog = True
        self._theme_dialog(dialog)
        body = tk.Frame(dialog, bg=self.colors['frame'])
        body.pack(fill=tk.BOTH, expand=True, padx=18, pady=12)
        title = tk.Label(body, text='Support EolnMsuk - Click any wallet to copy its address',
                         bg=self.colors['frame'], fg='#cccccc', font=('Segoe UI', 10, 'bold'))
        title.pack(anchor=tk.W, pady=(0, 8))
        
        confirmation = tk.Label(body, text='Choose a wallet above.', anchor=tk.W,
                                bg=self.colors['frame'], fg=self.colors['select'])
        confirmation._theme_foreground_key = 'select'
        pending = None

        def copy_address(description, address):
            nonlocal pending
            self.root.clipboard_clear()
            self.root.clipboard_append(address)
            confirmation.configure(text=f'{description.split(" (", 1)[0]} address copied ✓')
            if pending is not None:
                dialog.after_cancel(pending)
            pending = dialog.after(2200, clear_confirmation)

        def clear_confirmation():
            nonlocal pending
            pending = None
            confirmation.configure(text='Click any wallet to copy its address.')

        def cancel_confirmation(event):
            nonlocal pending
            if event.widget is dialog and pending is not None:
                dialog.after_cancel(pending)
                pending = None

        dialog.bind('<Destroy>', cancel_confirmation, add='+')
        dialog.bind('<Escape>', lambda _event: dialog.destroy())

        def highlight_wallet(wallet, pressed):
            background = self.colors['head' if pressed else 'frame']
            wallet.configure(bg=background)

        for description, address in CRYPTO_WALLETS:
            row = tk.Frame(body, bg=self.colors['frame'], cursor='hand2', takefocus=True)
            row.pack(fill=tk.X, pady=3)
            network = tk.Label(row, text=description, anchor=tk.W, cursor='hand2',
                               bg=self.colors['frame'], fg=self.colors['select'],
                               font=('Segoe UI', 9, 'bold'))
            network._theme_foreground_key = 'select'
            network.pack(fill=tk.X)
            wallet = tk.Label(row, text=f'{address}  📋', anchor=tk.W, cursor='hand2',
                              bg=self.colors['frame'], fg=self.colors['wallet'],
                              font=('Consolas', 10), pady=3)
            wallet._theme_foreground_key = 'wallet'
            wallet.pack(fill=tk.X)

            def press(_event, w=wallet, d=description, a=address):
                highlight_wallet(w, True)
                copy_address(d, a)

            release = lambda _event, w=wallet: highlight_wallet(w, False)
            for widget in (row, network, wallet):
                widget.bind('<ButtonPress-1>', press)
                widget.bind('<ButtonRelease-1>', release)
                widget.bind('<Leave>', release)
            for key in ('Return', 'space'):
                row.bind(f'<KeyPress-{key}>', press)
                row.bind(f'<KeyRelease-{key}>', release)
            row.bind('<FocusOut>', release)
            add_tooltip(wallet, 'Click to copy only the wallet address to your clipboard.')
        confirmation.pack(fill=tk.X, pady=(8, 0))
        self._center_dialog(dialog)
        dialog.deiconify()

    # Monitoring controls and preferences

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
            text, color, state, fg = ('🔒  Filter All Connections ON', '#c62828', tk.NORMAL, '#ffffff')
        else:
            text, color, state, fg = ('🔓  Filter All Connections OFF', '#9E9E9E', tk.NORMAL, '#ffffff')
        for prefix in ('', 'settings_'):
            button = getattr(self, prefix + 'btn_filter', None)
            if button is not None:
                self._set_button_colors(button, getattr(self, prefix + 'filter_border', None), color, fg, state)
                button.configure(text=text)
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

    def update_pause_button(self, resume):
        pause_text = '▶  Resume Monitoring' if resume else '⏸  Pause Monitoring'
        pause_color = '#9E9E9E' if resume else '#2196F3'
        for prefix in ('', 'settings_'):
            button = getattr(self, prefix + 'btn_pause', None)
            if button is not None:
                self._set_button_colors(button, getattr(self, prefix + 'pause_border', None), pause_color, '#ffffff', tk.NORMAL)
                button.configure(text=pause_text)

    def toggle_pause(self):
        with self.lock:
            capture_failed = not self.capture_healthy and self.capture_error is not None
            # A failed capture displays Resume; clicking it must not pause retries.
            self.is_paused = False if capture_failed else not self.is_paused
            paused = self.is_paused
        if paused:
            self._invalidate_auto_prompts(close_dialog=True)
        self.update_pause_button(paused or capture_failed)
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

    # Serialized background settings changes

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

    def on_notification_foreground_changed(self):
        with self.lock:
            self.keep_notification_foreground = bool(self.keep_notification_foreground_var.get())
        dialog = self.auto_prompt_dialog
        if dialog is not None:
            try:
                dialog.attributes('-topmost', self.keep_notification_foreground)
                if self.keep_notification_foreground:
                    dialog.lift()
            except tk.TclError:
                pass
        self.save_settings()

    # History limits, applying settings and reset

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
                self.keep_notification_foreground = True
                self.dark_mode = DEFAULT_DARK_MODE
                self.check_updates_on_startup = DEFAULT_CHECK_UPDATES_ON_STARTUP
                self.allowed_apps.clear()
                self.blocked_paths.clear()
                self.global_blocks.clear()
                self.global_allows.clear()
                self.global_ports.clear()
                self.hidden_columns.clear()
                self.column_widths = {}
                self.window_size = None
                self.window_position = None
                self.window_maximized = False
                self.active_connections.clear()
                self.connection_rates.clear()
                self.proc_ip_upload.clear()
                self.proc_ip_upload_last_seen.clear()
                self.upload_alerted.clear()
                self.ip_traffic_last_seen.clear()
                self.proc_traffic.clear()
                self.ip_traffic.clear()
                self.pruned_target_traffic.clear()
                self.global_port_traffic.clear()
                self.total_download = self.total_upload = 0
                self.firewall_initialized = True
                self.column_orders = {key: list(order) for key, order in self.default_column_orders.items()}
            for tree_name, order_key in (('tree', 'monitor'), ('rules_tree', 'rules'), ('alerts_tree', 'alerts')):
                tree = getattr(self, tree_name, None)
                if tree is not None:
                    tree['displaycolumns'] = tuple(self.column_orders[order_key])
                    for column, width in getattr(tree, '_default_column_widths', {}).items():
                        tree.column(column, width=width)
                    tree._fill_column = None
            self.rate_threshold_var.set(str(self.rate_threshold))
            self.rate_window_var.set(str(DEFAULT_RATE_WINDOW))
            self.upload_threshold_var.set(str(DEFAULT_UPLOAD_THRESHOLD_MB))
            self.max_connections_alerts_var.set(str(DEFAULT_MAX_CONNECTIONS_ALERTS))
            self.log_alerts_var.set(DEFAULT_LOG_ALERTS_ONLY)
            self.auto_block_var.set(True)
            self.keep_notification_foreground_var.set(True)
            self.dark_mode_var.set(DEFAULT_DARK_MODE)
            self.apply_theme()
            for variable in (self.search_var, self.rule_search_var, self.alert_search_var):
                variable.set('')
            self.check_updates_on_startup_var.set(DEFAULT_CHECK_UPDATES_ON_STARTUP)
            self.clear_alerts()
            self.clear_list()
            self.update_pause_button(not self.capture_healthy and self.capture_error is not None)
            self.update_auto_block_controls()
            self.update_filter_ui()
            if self.startup_complete:
                self.render_all()
            self.save_settings()
            self.refresh_rules(force=True)
            self.update_status()
            self._fit_initial_window()
            messagebox.showinfo('Defaults Restored', 'PyFirewall-managed rules and saved settings were reset.')
        except Exception as exc:
            messagebox.showerror('Reset Failed', str(exc))
