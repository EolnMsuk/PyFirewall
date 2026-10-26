"""Connection, rule and alert views, context actions and import/export."""

import csv
import ctypes
import ipaddress
import json
import os
import psutil
import queue
import subprocess
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from constants import CREATE_NO_WINDOW, GLOBAL_PURPLE, GLOBAL_TEAL, GLOBAL_YELLOW
from helpers import (
    direction_name,
    direction_set,
    display_path,
    is_global_target,
    is_ip,
    log_internal_error,
    mb,
    normalize_path,
    normalize_target,
)
from widgets import add_tooltip

class ViewsMixin:
    """Methods composed into FirewallMonitorApp; state is owned by that application."""

    # Managed-rule refresh

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
            rows.append({'iid': f'app:allow:{path}', 'status': 'Allowed', 'rule': os.path.basename(path) or path, 'action': 'Allow', 'direction': 'Both', 'path': path, 'normalized_path': path, 'remote_port': 'All', 'local_port': 'All', 'protocol': 'TCP/UDP', 'download': 0, 'upload': 0})
        for path, data in sorted(blocked.items()):
            if path in allowed_normalized:
                continue
            direction = self._direction_from_flags(data)
            rows.append({'iid': f'app:block:{path}', 'status': 'Blocked' if direction != 'Inbound' else 'Blocked (In)', 'rule': os.path.basename(data['path']) or data['path'], 'action': 'Block', 'direction': direction, 'path': data['path'], 'normalized_path': path, 'remote_port': 'All', 'local_port': 'All', 'protocol': 'TCP/UDP', 'download': 0, 'upload': 0})
        for kind, collection in (('block', blocks), ('allow', allows)):
            global_text = 'Block' if kind == 'block' else 'Allow'
            for target, data in sorted(collection.items()):
                addresses = tuple(data.get('addresses', ()))
                rows.append({'iid': f'global:{kind}:{target}', 'status': 'Blocked (in) (Global)' if kind == 'block' and direction_name(data.get('direction', 'Both')) == 'Inbound' else f'Global {global_text}', 'rule': target, 'action': global_text, 'direction': data.get('direction', 'Both'), 'path': target if not addresses else f"{target} ({', '.join(addresses)})", 'normalized_path': target, 'addresses': addresses, 'global_type': kind, 'remote_port': '', 'local_port': '', 'protocol': 'TCP/UDP', 'download': 0, 'upload': 0})
        with self.lock:
            for key, rule in sorted(getattr(self, 'global_ports', {}).items()):
                target = rule.get('target', '')
                addresses = tuple(rule.get('addresses', ()))
                target_label = (f"{target} ({', '.join(addresses)})"
                                if target and not is_ip(target) and addresses else target)
                rows.append({'iid': f'port:{key}',
                             'status': 'Blocked (in) (Global)' if rule['action'] == 'Block' and direction_name(rule.get('direction', 'Both')) == 'Inbound' else f"{rule['action']}ed (Global)",
                             'rule': target_label,
                             'remote_port': rule['port'] if rule['scope'] == 'remote' and rule['port'] else '',
                             'local_port': rule['port'] if rule['scope'] == 'local' and rule['port'] else '',
                             'protocol': rule.get('protocol', 'TCP/UDP'),
                             'action': rule['action'], 'direction': rule.get('direction', 'Both'),
                             'path': key, 'normalized_path': key,
                             'global_type': rule['action'].lower(), 'is_port': True, 'download': 0, 'upload': 0})
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

    # Rule creation dialogs

    def _focus_rule_editor(self):
        """Reject another manual editor without making Auto-Block prompts modal."""
        dialog = getattr(self, 'rule_editor_dialog', None)
        if dialog is None or not dialog.winfo_exists():
            self.rule_editor_dialog = None
            return False
        dialog.deiconify()
        dialog.lift()
        dialog.focus_set()
        prompt = getattr(self, 'auto_prompt_dialog', None)
        if prompt is not None and prompt.winfo_exists():
            prompt.lift()
            prompt.focus_set()
        return True

    def _new_rule_editor(self):
        if self._focus_rule_editor():
            return None
        dialog = tk.Toplevel(self.root)
        self.rule_editor_dialog = dialog

        def release(event):
            if event.widget is dialog and self.rule_editor_dialog is dialog:
                self.rule_editor_dialog = None

        dialog.bind('<Destroy>', release, add='+')
        return dialog

    def add_custom_rule(self):
        if self._focus_rule_editor():
            return
        path = filedialog.askopenfilename(title='Select Executable', filetypes=[('Executable Files', '*.exe'), ('All files', '*.*')])
        if not path:
            return
        proc = os.path.splitext(os.path.basename(path))[0] or 'Process'
        self.edit_app_rule(path, proc)

    def add_monitor_rule(self):
        rows = self.selected_connection_data(self.tree)
        choice = self._choose_option('Create Rule', 'Choose a rule type:', (
            ('App Rule', 'app', '#4CAF50'), ('Global Rule', 'global', GLOBAL_PURPLE)))
        if choice == 'app':
            paths = {}
            for row in rows:
                if row.get('exe'):
                    paths.setdefault(normalize_path(row['exe']), row)
            if not paths:
                self.add_custom_rule()
            else:
                for row in paths.values():
                    self.edit_app_rule(row['exe'], row.get('name', 'Process'))
        elif choice == 'global':
            if rows:
                self.prompt_connection_globals(rows, True)
            else:
                self.add_global_rule_dialog()

    def _choose_option(self, title, prompt, choices, current=None):
        result = [None]
        dialog = self._new_rule_editor()
        if dialog is None:
            return None
        dialog.withdraw()
        dialog.title(title)
        dialog.transient(self.root)
        dialog.resizable(False, False)
        self._theme_dialog(dialog)
        ttk.Label(dialog, text=prompt, wraplength=420, padding=16).pack(fill=tk.X)
        def choose(value):
            result[0] = value
            dialog.destroy()
        for label, value, color in choices:
            selected_light = value == current and not self.dark_mode
            parent = dialog
            if selected_light:
                # Use a flat, explicitly colored border: Windows can draw
                # black top/left edges even for a grey SUNKEN frame.
                parent = tk.Frame(dialog, bg=self.colors['fg'], relief=tk.FLAT,
                                  borderwidth=0, highlightthickness=0)
                parent.pack(fill=tk.X, padx=16, pady=4)
            button = tk.Button(parent, text=label + (' (Current)' if value == current else ''), command=lambda v=value: choose(v),
                               bg=color, fg='#e8e8e8', relief=tk.SUNKEN if value == current else tk.FLAT,
                               font=('Segoe UI', 9, 'bold'), padx=16, pady=8)
            self._bind_button_hover(button)
            if selected_light:
                button.configure(relief=tk.FLAT, borderwidth=0, highlightthickness=0)
                button.pack(fill=tk.X, padx=2, pady=2)
            else:
                button.pack(fill=tk.X, padx=16, pady=4)
        ttk.Button(dialog, text='Cancel', command=dialog.destroy).pack(pady=12)
        dialog.bind('<Escape>', lambda _: dialog.destroy())
        self._position_dialog_near_pointer(dialog)
        dialog.deiconify()
        self.root.wait_window(dialog)
        return result[0]

    @staticmethod
    def _validate_global_rule_fields(target, port, scope):
        target, port = target.strip(), port.strip()
        if not target and not port:
            raise ValueError('At least one value (domain / IP or port number) needs to be set to create the rule.')
        targets = []
        if target:
            for value in target.split(','):
                value = normalize_target(value)
                if not value:
                    raise ValueError('Enter a domain or IP address between each comma.')
                if not is_global_target(value):
                    raise ValueError(f'Enter a valid domain or IP address: {value}')
                if value not in targets:
                    targets.append(value)
        if port and (not port.isdecimal() or not 1 <= int(port) <= 65535):
            raise ValueError('Port numbers must be integers from 1 to 65535.')
        return ', '.join(targets), int(port) if port else None, scope.lower()

    def _ask_global_rule_fields(self, initial=None):
        initial = initial or {}
        result = [None]
        dialog = self._new_rule_editor()
        if dialog is None:
            return None
        dialog.withdraw()
        dialog.title('Edit Global Rule' if initial.get('editing') else 'Add Global Rule')
        dialog.transient(self.root)
        dialog.resizable(False, False)
        self._theme_dialog(dialog)
        fields = ttk.Frame(dialog, padding=16)
        fields.pack(fill=tk.BOTH, expand=True)
        text_options = {} if self.dark_mode else {'foreground': '#222222'}
        ttk.Label(fields, text='Action:', **text_options).grid(row=0, column=0, sticky='w')
        action = ttk.Combobox(fields, values=('Allow', 'Block', 'Block Incoming'), state='readonly', width=30)
        action.set(initial.get('action', 'Allow'))
        action.grid(row=0, column=1, sticky='ew', pady=(0, 12))
        ttk.Label(fields, text='Domains or IP addresses:', **text_options).grid(row=1, column=0, sticky='w', padx=(0, 12))
        target = ttk.Entry(fields, width=36, **text_options)
        target.insert(0, initial.get('target', ''))
        target.grid(row=1, column=1, sticky='ew', pady=4)
        ttk.Label(fields, text='Port Number:', **text_options).grid(row=2, column=0, sticky='w')
        port_frame = ttk.Frame(fields)
        port_frame.grid(row=2, column=1, sticky='ew', pady=4)
        port = ttk.Entry(port_frame, width=8, **text_options)
        port.insert(0, str(initial.get('port') or ''))
        port.pack(side=tk.LEFT)
        ttk.Label(port_frame, text='(1-65535)', **text_options).pack(side=tk.LEFT, padx=6)
        scope = ttk.Combobox(port_frame, values=('Remote', 'Local'), state='readonly', width=10)
        scope.set(initial.get('scope', 'remote').title())
        scope.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        ttk.Label(fields, text='Protocol:', **text_options).grid(row=3, column=0, sticky='w')
        protocol = ttk.Combobox(fields, values=('TCP/UDP', 'TCP', 'UDP'), state='readonly', width=30)
        protocol.set(initial.get('protocol', 'TCP/UDP'))
        protocol.grid(row=3, column=1, sticky='ew', pady=4)
        ttk.Label(fields, text='Separate targets with commas; use start-end for IP ranges.', **text_options).grid(row=4, column=0, columnspan=2, sticky='w', pady=8)

        def submit():
            try:
                # Validate shared fields now; individual targets are processed independently.
                raw_target = target.get().strip()
                _, number, side = self._validate_global_rule_fields('192.0.2.1' if raw_target else '', port.get(), scope.get())
                result[0] = (raw_target, number, side, protocol.get(), action.get())
            except ValueError as exc:
                if not messagebox.askokcancel('Add Global Rule', str(exc), icon='warning', parent=dialog):
                    dialog.destroy()
                return
            dialog.destroy()

        buttons = ttk.Frame(fields)
        buttons.grid(row=5, column=1, pady=(12, 0))
        ttk.Button(buttons, text='Save', command=submit).pack(side=tk.LEFT, padx=4)
        ttk.Button(buttons, text='Cancel', command=dialog.destroy).pack(side=tk.LEFT, padx=4)
        dialog.bind('<Return>', lambda _: submit())
        dialog.bind('<Escape>', lambda _: dialog.destroy())
        self._position_dialog_near_pointer(dialog)
        dialog.deiconify()
        target.focus_set()
        self.root.wait_window(dialog)
        return result[0]

    def add_global_rule_dialog(self, initial=None, replace_rule=None):
        fields = self._ask_global_rule_fields(initial)
        if fields is None:
            return
        target, port, scope, protocol, action = fields
        entries, failures = [], []
        targets = dict.fromkeys(normalize_target(value) for value in target.split(',')) if target else ['']
        for value in targets:
            name = normalize_target(value)
            try:
                addresses = []
                if target:
                    if not name or not is_global_target(name):
                        raise ValueError('Not a valid domain or IP address.')
                    saved = initial.get('addresses', ()) if initial and name == initial.get('target') else ()
                    if initial and name != initial.get('target'):
                        saved = initial.get('target_addresses', {}).get(name, ())
                    addresses = list(self.resolve_global_target(name, saved))
                    if not addresses:
                        raise ValueError('No addresses found.')
                entry = {'target': name, 'port': port, 'scope': scope, 'protocol': protocol,
                         'action': 'Allow' if action == 'Allow' else 'Block', 'addresses': addresses}
                if action == 'Block Incoming':
                    entry['direction'] = 'Inbound'
                entries.append(entry)
            except Exception as exc:
                failures.append(f'{value.strip() or "(empty target)"}: {exc}')
        applied = False
        if entries:
            # A submission is one logical policy. Never merge other saved rules.
            group = dict(entries[0], target=', '.join(entry['target'] for entry in entries),
                         addresses=list(dict.fromkeys(address for entry in entries for address in entry['addresses'])))
            if len(entries) > 1:
                group['target_addresses'] = {entry['target']: entry['addresses'] for entry in entries}
            applied = self._apply_rule_batch([], port_updates=[group], replace_rule=replace_rule, report=not failures)
        if failures:
            summary = (f'{len(entries)} valid target(s) processed.' if applied else 'No rules were changed.')
            if entries and not applied:
                summary = 'The valid targets could not all be applied and saved. See the error details.'
            if replace_rule and not entries:
                summary += ' The existing rule was kept.'
            messagebox.showwarning('Global Rule Update', summary + '\n\nTargets not added:\n' + '\n'.join(failures), parent=self.root)

    def bulk_remote_ports(self, tree, allow):
        ports = set()
        for row in self.selected_connection_data(tree):
            raw = str(row.get('dport', ''))
            if str(row.get('protocol', '')).upper() in {'TCP', 'UDP'} and raw.isdecimal() and 1 <= int(raw) <= 65535:
                ports.add(int(raw))
        if not ports:
            messagebox.showinfo('Global Port Rule', 'No valid TCP/UDP remote port was selected.', parent=self.root)
            return
        self._apply_rule_batch([], port_updates=[{'scope': 'remote', 'port': port, 'action': 'Allow' if allow else 'Block'}
                                                 for port in sorted(ports)], report=True)

    def change_selected_ports(self, allow, direction='both'):
        self.prompt_selected_global_rules(allow, direction)

    def add_global_target(self, action):
        target = simpledialog.askstring(f'{action} Global Target', 'IP address or domain:', parent=self.root)
        if not target or not target.strip():
            return
        allow = action == 'Allow'
        direction = 'both' if allow else self.ask_direction(
            f'Choose how to block {target.strip()} globally across all processes.',
            block_labels=('Block All', 'Block Only Incoming'))
        if direction:
            self.add_global_rule(target.strip(), allow, direction=direction)

    def ask_direction(self, prompt, allow=False, block_labels=('Block In & Out', 'Block Incoming')):
        result = {'value': None}
        dialog = tk.Toplevel(self.root)
        dialog.title('Firewall Action')
        dialog.resizable(False, False)
        dialog.withdraw()
        dialog.transient(self.root)
        self._theme_dialog(dialog)
        tk.Label(dialog, text=prompt, wraplength=380, padx=18, pady=15, bg=self.colors['frame'], fg=self.colors['fg']).pack()
        buttons = tk.Frame(dialog, bg=self.colors['frame'])
        buttons.pack(fill=tk.X, padx=15, pady=5)

        def choose(value):
            result['value'] = value
            dialog.destroy()
        for text, value, color, tip in ((block_labels[0], 'both', '#c62828', 'Block incoming and outgoing traffic.'), (block_labels[1], 'in', '#ff9800', 'Block incoming traffic and leave outgoing traffic allowed.')):
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
        self._position_dialog_near_pointer(dialog)
        dialog.deiconify()
        dialog.lift()
        dialog.focus_force()
        self.root.wait_window(dialog)
        return result['value']

    # Sorting and table rendering

    def sort_tree(self, tree, column):
        states = ((self.tree, self.monitor_sort, self.render_monitor), (self.rules_tree, self.rule_sort, self.render_rules))
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
        return ' '.join(map(str, (row.get('name', ''), row.get('pid', ''), row.get('direction', ''), row.get('protocol', ''), row.get('lport', ''), row.get('dst_ip', ''), row.get('remote_host', row.get('domain', '')), row.get('dport', ''), mb(row.get('_down', 0)), mb(row.get('_up', 0)), row.get('signal', ''), row.get('exe', '')))).casefold()

    def sort_monitor_rows(self, rows, state):
        column, reverse = state
        fields = {'#': lambda r: r['number'], 'Process Name': lambda r: r['name'].casefold(), 'Status': lambda r: self.connection_status(r).casefold(), 'PID': lambda r: r['pid'], 'Direction': lambda r: r['direction'].casefold(), 'Protocol': lambda r: r['protocol'].casefold(), 'Local Port': lambda r: r['lport'], 'Remote IP': lambda r: r['dst_ip'].casefold(), 'Remote Host': lambda r: r.get('remote_host', r.get('domain', '')).casefold(), 'Remote Port': lambda r: r['dport'], 'Download (MB)': lambda r: r.get('_down', 0), 'Upload (MB)': lambda r: r.get('_up', 0), 'Signal': lambda r: r.get('signal', '').casefold(), 'Exe Path': lambda r: r['exe'].casefold()}
        rows.sort(key=fields.get(column, lambda r: ''), reverse=reverse)

    def _render_connections(self, tree, search_var, sort_state):
        if not isinstance(tree, ttk.Treeview):
            return
        search = search_var.get().casefold().strip()
        with self.lock:
            rows = [dict(row) for row in self.active_connections.values()]
            traffic = {key: dict(value) for key, value in self.proc_traffic.items()}
        for row in rows:
            row['remote_host'] = self.remote_host(row)
            data = traffic.get(normalize_path(row['exe']) or row['name'].casefold(), {})
            row['_down'] = data.get('download', 0)
            row['_up'] = data.get('upload', 0)
        if search:
            rows = [row for row in rows if search in self.search_text(row)]
        self.sort_monitor_rows(rows, sort_state)
        selected = set(tree.selection())
        tree.delete(*tree.get_children())
        for index, row in enumerate(rows):
            tree.insert('', tk.END, iid=row['key'], values=self.connection_values(row, include_status=True), tags=(self.connection_tag(row, index),))
        if selected:
            tree.selection_set([iid for iid in selected if tree.exists(iid)])

    def render_monitor(self):
        self._render_connections(self.tree, self.search_var, self.monitor_sort)

    def connection_values(self, row, include_status=True):
        values = {'#': row['number'], 'Process Name': row['name'], 'Status': self.connection_status(row),
                  'PID': row['pid'], 'Direction': row['direction'], 'Protocol': row['protocol'],
                  'Local Port': row['lport'], 'Remote IP': row['dst_ip'], 'Remote Host': self.remote_host(row) or '—',
                  'Remote Port': row['dport'], 'Download (MB)': mb(row.get('_down', 0)),
                  'Upload (MB)': mb(row.get('_up', 0)), 'Signal': row.get('signal') or '—', 'Exe Path': row['exe']}
        return tuple(values[c] for c in self.MONITOR_COLUMNS if include_status or c != 'Status')

    def connection_status(self, row):
        tag = self.connection_tag(row)
        with self.lock:
            if normalize_path(row.get('exe', '')) in self.auto_prompt_keys:
                return 'Blocked (Pending)'
        return {'global_allow': 'Allowed (Global)', 'global_block': 'Blocked (Global)',
                'global_block_in': 'Blocked (in) (Global)'}.get(tag, self.get_rule_status_display(row.get('exe', '')))

    def connection_tag(self, row, index=0):
        # Application blocks keep their process-level color, including pending
        # Auto-Block holds. A global allow never overrides a Windows block.
        with self.lock:
            if normalize_path(row.get('exe', '')) in self.auto_prompt_keys:
                return 'blocked'
        status = self.get_rule_status(row.get('exe', ''))
        if status == 'blocked_in':
            return 'blocked_in'
        if status in {'blocked_both', 'blocked_out'}:
            return 'blocked'
        remote = row.get('dst_ip', '')
        domain = row.get('domain', '')
        port_rules = self.matching_global_port_rules(row).values()
        port_blocks = [rule for rule in port_rules if rule['action'] == 'Block']
        if any(rule.get('direction', 'Both') == 'Both' for rule in port_blocks):
            return 'global_block'
        if self.is_globally_blocked(remote, domain, row.get('direction')):
            return self.global_block_tag(remote, domain, row.get('direction'))
        if port_blocks:
            return 'global_block_in'
        if any(rule['action'] == 'Allow' for rule in port_rules) or self.is_globally_allowed(remote, domain, row.get('direction')):
            return 'global_allow'
        if status == 'allowed':
            return 'allowed'
        return 'watch' if row.get('signal') else 'even' if index % 2 == 0 else 'odd'

    def alert_tag(self, values):
        row, remote_ip = self.alert_context(values)
        if row:
            tag = self.connection_tag(row)
            return '' if tag in {'even', 'odd', 'watch'} else tag
        if self.is_globally_blocked(remote_ip):
            return self.global_block_tag(remote_ip)
        if self.is_globally_allowed(remote_ip):
            return 'global_allow'
        return ''

    def global_block_tag(self, remote, domain='', direction=None):
        with self.lock:
            both = {target: data for target, data in self.global_blocks.items()
                    if direction_name(data.get('direction', 'Both')) == 'Both'}
            return 'global_block' if self._global_match(both, remote, domain, direction) else 'global_block_in'

    def render_rules(self):
        if not hasattr(self, 'rules_tree'):
            return
        search = self.rule_search_var.get().casefold().strip()
        rows = list(self.rule_rows)
        if search:
            rows = [row for row in rows if search in ' '.join(map(str, (row['status'], row['rule'], row['action'], row['direction'], row['path'], row.get('remote_port', ''), row.get('local_port', ''), row.get('protocol', ''), mb(row.get('download', 0)), mb(row.get('upload', 0))))).casefold()]
        column, reverse = self.rule_sort
        if column:
            fields = {'Status': lambda r: r['status'].casefold(), 'Application / Domain IP': lambda r: r['rule'].casefold(), 'Direction': lambda r: r['direction'].casefold(), 'Download (MB)': lambda r: r.get('download', 0), 'Upload (MB)': lambda r: r.get('upload', 0), 'Program Path': lambda r: r['path'].casefold()}
            for label, key in (('Remote Port', 'remote_port'), ('Local Port', 'local_port')):
                fields[label] = lambda r, key=key: int(r[key]) if str(r.get(key, '')).isdecimal() else -1
            fields['Protocol'] = lambda r: r.get('protocol', '').casefold()
            rows.sort(key=fields.get(column, lambda r: ''), reverse=reverse)
        selected = set(self.rules_tree.selection())
        self.rules_tree.delete(*self.rules_tree.get_children())
        for row in rows:
            tag = 'global_allow' if row.get('global_type') == 'allow' else ('global_block_in' if row['direction'] == 'Inbound' else 'global_block') if row.get('global_type') == 'block' else 'allowed' if row['status'] == 'Allowed' else 'blocked_in' if row['status'] == 'Blocked (In)' else 'blocked'
            down = '—' if row.get('is_port') else mb(row.get('download', 0))
            up = '—' if row.get('is_port') else mb(row.get('upload', 0))
            self.rules_tree.insert('', tk.END, iid=row['iid'], values=(row['status'], row['rule'], row['direction'], row.get('remote_port') or '—', row.get('local_port') or '—', row.get('protocol', ''), down, up, row['path']), tags=(tag,))
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
            remote_ip = normalize_target(remote)
            if not is_ip(remote_ip):
                candidate, _, port = remote_ip.rpartition(':')
                if port.isdecimal() and is_ip(candidate.strip('[]')):
                    remote_ip = candidate.strip('[]')
            host = host or (self.get_cached_dns(remote_ip) if is_ip(remote_ip) else '')
            host = self.remote_host({'dst_ip': remote_ip, 'domain': host})
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
        self.render_rules()
        self.render_alerts()

    # Alert delivery

    def queue_alert(self, severity, process, pid, remote, reason, connection=None):
        alert = (time.time(), severity, process, pid, remote, '', reason)
        self.alert_queue.put((*alert, dict(connection)) if connection else alert)

    def drain_alerts(self):
        changed = False
        for _ in range(100):
            try:
                alert = self.alert_queue.get_nowait()
            except queue.Empty:
                break
            alert_id = self.next_alert_id
            self.next_alert_id += 1
            if len(alert) == 8:
                self.alert_connections[alert_id] = alert[-1]
                alert = alert[:-1]
            self.alerts.append((alert_id, *alert))
            changed = True
        if changed:
            retained = {a[0] for a in self.alerts}
            self.alert_connections = {key: row for key, row in getattr(self, 'alert_connections', {}).items()
                                      if key in retained}
            self.render_alerts()

    def clear_alerts(self):
        self.alerts.clear()
        self.alert_connections = {}
        if hasattr(self, 'alerts_tree'):
            self.alerts_tree.delete(*self.alerts_tree.get_children())

    # Selection and context-menu actions

    def connection_global_rules(self, row):
        matches = []
        with self.lock:
            for kind, collection in (('block', self.global_blocks), ('allow', self.global_allows)):
                for target, data in sorted(collection.items()):
                    if self._global_match({target: data}, row.get('dst_ip', ''), row.get('domain', ''), row.get('direction')):
                        matches.append((kind, target, dict(data, target=target, action=kind.title())))
        matches.extend(('port', key, rule) for key, rule in sorted(self.matching_global_port_rules(row).items()))
        return matches

    def effective_connection_rule(self, row):
        """Use the same precedence as the displayed connection status."""
        tag = self.connection_tag(row)
        if tag.startswith('global_'):
            for rule in self.connection_global_rules(row):
                data = rule[2]
                rule_tag = ('global_allow' if data['action'] == 'Allow' else
                            'global_block_in' if direction_name(data.get('direction', 'Both')) == 'Inbound' else 'global_block')
                if rule_tag == tag:
                    return rule
        if self.application_has_rule(row.get('exe', '')) or tag == 'blocked':
            return ('app', row.get('exe', ''), {'status': self.get_rule_status(row.get('exe', ''))})
        return None

    def edit_global_rule(self, rule, action=None):
        kind, key, data = rule
        initial = dict(data, editing=True)
        initial['action'] = action or ('Allow' if data['action'] == 'Allow' else
                                      'Block Incoming' if direction_name(data.get('direction', 'Both')) == 'Inbound' else 'Block')
        self.add_global_rule_dialog(initial, (kind, key))

    @staticmethod
    def _global_action_label(allow, direction='both'):
        return 'Allow' if allow else 'Block Incoming' if direction_name(direction) == 'Inbound' else 'Block'

    def _connection_global_draft(self, row, action, scope='remote'):
        # The display may combine a passive DNS name with a reverse-DNS name.
        # Use the primary name, never the parenthesized display string.
        host = normalize_target(self.remote_host(row).split(' (', 1)[0])
        if not is_global_target(host) or is_ip(host):
            host = normalize_target(row.get('domain', ''))
        remote = normalize_target(row.get('dst_ip', ''))
        target = host if is_global_target(host) else remote
        raw_port = str(row.get('lport' if scope == 'local' else 'dport', ''))
        port = int(raw_port) if raw_port.isdecimal() and 1 <= int(raw_port) <= 65535 else None
        protocol = str(row.get('protocol', '')).upper()
        return {'target': target if is_global_target(target) else '', 'port': port,
                'scope': scope, 'protocol': protocol if protocol in {'TCP', 'UDP'} else 'TCP/UDP',
                'action': action, 'addresses': [remote] if is_ip(remote) else []}

    def prompt_connection_globals(self, rows, allow=None, direction='both'):
        """Review connection assignments or explicitly edit the saved policy."""
        action = self._global_action_label(allow, direction) if allow is not None else None
        existing, drafts = {}, {}
        for row in rows:
            matches = self.connection_global_rules(row)
            if matches:
                for kind, key, data in matches:
                    if action and not any(token in data.get('target', '') for token in (',', '/', '-')):
                        data = dict(data, **self._connection_global_draft(row, action, data.get('scope', 'remote')))
                    existing.setdefault((kind, key), (kind, key, data))
            elif action:
                draft = self._connection_global_draft(row, action)
                if not draft['target'] and draft['port'] is None:
                    continue
                identity = (draft['target'], draft['port'], draft['scope'], draft['protocol'])
                if identity in drafts:
                    draft['addresses'] = sorted(set(drafts[identity]['addresses']) | set(draft['addresses']))
                drafts[identity] = draft
        for rule in existing.values():
            self.edit_global_rule(rule, action=action)
        for draft in drafts.values():
            self.add_global_rule_dialog(draft)
        if not existing and not drafts:
            self._show_rule_result('Global Rule', 'No applicable global rule or valid target was selected.')

    def prompt_selected_global_rules(self, allow, direction='both'):
        action = self._global_action_label(allow, direction)
        for iid, values in self.selected_rows(self.rules_tree):
            if values and self._managed_rule_category(values[0], values[-1]) != 'app':
                self.edit_selected_managed_rule(iid, action=action)

    def edit_connection_app_rules(self, rows):
        paths = {}
        for row in rows:
            path = row.get('exe', '')
            if self.application_has_rule(path):
                paths.setdefault(normalize_path(path), row)
        for row in paths.values():
            self.edit_app_rule(row['exe'], row.get('name', 'Process'))

    def edit_app_rule(self, path, name='Process'):
        if not path:
            messagebox.showinfo('App Rule', 'The executable path is unavailable. No rule was changed.', parent=self.root)
            return
        status = self.get_rule_status_display(path) if self.application_has_rule(path) else 'No existing rule'
        current = {'allowed': 'allow', 'blocked_both': 'both', 'blocked_in': 'in'}.get(self.get_rule_status(path))
        action = self._choose_option('App Rule', f'{name}\n{path}\n\nCurrent rule: {status}\nChoose the application rule:', (
            ('Allow', 'allow', '#4CAF50'), ('Block', 'both', '#c62828'), ('Block Incoming', 'in', '#ff9800')), current=current)
        if action:
            self._apply_rule_batch([(path, action == 'allow', 'both' if action == 'allow' else action, False)], report=True)

    def edit_connection_rule(self, row):
        rule = self.effective_connection_rule(row)
        if rule and rule[0] != 'app':
            self.edit_global_rule(rule)
        elif rule:
            self.edit_app_rule(row.get('exe', ''), row.get('name', 'Process'))
        else:
            choice = self._choose_option('Create Rule', 'This connection has no managed rule. Choose a rule type:', (
                ('App Rule', 'app', '#4CAF50'), ('Global Rule', 'global', GLOBAL_PURPLE)))
            if choice == 'app':
                self.edit_app_rule(row.get('exe', ''), row.get('name', 'Process'))
            elif choice == 'global':
                self.add_global_rule_dialog(self._connection_global_draft(row, 'Allow'))

    def edit_selected_managed_rule(self, iid, action=None):
        row = next((row for row in self.rule_rows if row['iid'] == iid), None)
        if not row:
            return
        key = row['normalized_path']
        if row.get('is_port'):
            with self.lock:
                data = dict(self.global_ports.get(key, {}))
            if data:
                self.edit_global_rule(('port', key, data), action=action)
        elif row.get('global_type'):
            kind = row['global_type']
            with self.lock:
                data = dict((self.global_allows if kind == 'allow' else self.global_blocks).get(key, {}))
            self.edit_global_rule((kind, key, dict(data, target=key, action=kind.title())), action=action)
        else:
            self.edit_app_rule(row['path'], row['rule'])

    def alert_connection_row(self, values, iid=None):
        if iid and str(iid).startswith('alert_'):
            alert_id = str(iid)[6:]
            saved = getattr(self, 'alert_connections', {}).get(int(alert_id)) if alert_id.isdecimal() else None
            if saved:
                result = dict(saved)
                if len(values) > 5 and is_global_target(values[5]):
                    result['domain'] = normalize_target(values[5])
                return result
        row, remote = self.alert_context(values)
        # A PID fallback may supply an executable but must not replace the alert endpoint.
        if row and remote in {normalize_target(row.get('dst_ip')), normalize_target(row.get('domain'))}:
            result = dict(row)
            if len(values) > 5 and is_global_target(values[5]):
                result['domain'] = normalize_target(values[5])
            return result
        return {'exe': (row or {}).get('exe', ''), 'name': values[2], 'dst_ip': remote,
                'domain': values[5] if len(values) > 5 and is_global_target(values[5]) else '',
                'direction': None, 'protocol': '', 'lport': '', 'dport': ''}

    def change_connection_globals(self, rows, allow, direction='both'):
        self.prompt_connection_globals(rows, allow, direction)

    def remove_connection_rule(self, row):
        rule = self.effective_connection_rule(row)
        if not rule:
            messagebox.showinfo('Remove Rule', 'No managed rule is applied to this connection.', parent=self.root)
            return False
        kind, key, data = rule
        status = 'App' if kind == 'app' else 'Global Port ' + data['action'] if kind == 'port' else 'Global ' + data['action']
        return self._remove_rules_with_feedback([(status, key)])

    def _remove_rules_with_feedback(self, requests):
        requests = list(requests)
        if not requests:
            self._show_rule_result('Remove Rule', 'No applicable rules were selected. No rules were removed.')
            return False
        return self._remove_rule_batch(requests)

    def _show_rule_result(self, title, text):
        messagebox.showinfo(title, text, parent=self.root)

    def selected_rows(self, tree):
        return [(iid, tree.item(iid, 'values')) for iid in tree.selection() if tree.item(iid, 'values')]

    def open_file_location_from_tree(self, tree, iid):
        if not iid or not tree.exists(iid):
            return
        values = tree.item(iid, 'values')
        path = ''
        if tree is self.tree:
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
            if self._managed_rule_category(status, mapping.get('Program Path', '')) == 'app':
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

    def connection_rule_tags(self, row):
        """Highlight every applicable policy, independently of status precedence."""
        status = self.get_rule_status(row.get('exe', ''))
        tags = set()
        direction = direction_name(row.get('direction'))
        if status == 'allowed':
            tags.add('allowed')
        elif status == 'blocked_both' or (status == 'blocked_out' and direction != 'Inbound'):
            tags.add('blocked')
        elif status == 'blocked_in' and direction != 'Outbound':
            tags.add('blocked_in')
        for _, _, rule in self.connection_global_rules(row):
            tags.add('global_allow' if rule['action'] == 'Allow' else
                     'global_block_in' if direction_name(rule.get('direction')) == 'Inbound' else 'global_block')
        return tags

    def show_connection_menu(self, event, tree):
        if self._show_header_menu(event, tree):
            return 'break'
        iid = self._focus_menu_row(tree, event)
        if not iid:
            return
        menu = self._context_menu()
        rows = self.selected_connection_data(tree)
        focused = next((row for row in rows if row.get('key') == iid), rows[0] if rows else {})
        menu.rule_tag = self.connection_tag(focused)
        menu.rule_tags = self.connection_rule_tags(focused)
        actions = (('Allow Process', lambda: self.allow_process(tree), 'allowed'), ('Block Incoming', lambda: self.block_process(tree, 'in'), 'blocked_in'), ('Block Process', lambda: self.block_process(tree, 'both'), 'blocked'))
        for label, command, tag in actions:
            self._menu_rule_command(menu, label, command, tag)
        has_app = any(self.application_has_rule(row.get('exe', '')) for row in rows)
        has_global = any(self.connection_global_rules(row) for row in rows)
        if has_app:
            menu.add_command(label='Remove App Rule', command=lambda: self.remove_selected_connection_rules(tree), foreground=self.colors.get('muted', '#a8a8a8'))
        menu.add_separator()
        self._global_menu_commands(menu, lambda allow, direction: self.prompt_connection_globals(rows, allow, direction))
        if has_global:
            menu.add_command(label='Remove Global Rule', command=lambda: self.remove_selected_connection_global_rules(tree), foreground=self.colors.get('muted', '#a8a8a8'))
        menu.add_separator()
        menu.add_command(label='Copy IP Domain', command=lambda: self.copy_connection_endpoints(tree))
        menu.add_command(label='Copy details', command=lambda: self.copy_connection_details(tree))
        menu.add_command(label='Connection details', command=lambda: self.show_connection_details(tree))
        menu.add_command(label='Open file location', command=lambda iid=iid: self.open_file_location_from_tree(tree, iid))
        menu.post(event.x_root, event.y_root)

    def show_rules_menu(self, event):
        if self._show_header_menu(event, self.rules_tree):
            return 'break'
        iid = self._focus_menu_row(self.rules_tree, event)
        if not iid:
            return
        values = self.rules_tree.item(iid, 'values')
        status = str(values[0]).casefold() if values else ''
        menu = self._context_menu()
        direction = str(values[2]) if len(values) > 2 else 'Both'
        category = self._managed_rule_category(status, values[-1] if values else '')
        global_port = category == 'port'
        global_rule = category != 'app'
        menu.rule_tag = ('global_allow' if 'allow' in status else 'global_block_in' if direction == 'Inbound' else 'global_block') if global_rule else ('allowed' if 'allow' in status else 'blocked_in' if direction == 'Inbound' else 'blocked')
        if global_port:
            self._global_menu_commands(menu, self.change_selected_ports, assigned=True)
        elif global_rule:
            self._global_menu_commands(menu, self.prompt_selected_global_rules, assigned=True)
        else:
            actions = (('Allow Process', self.rules_menu_allow, 'allowed'), ('Block Incoming', lambda: self.rules_menu_block('in'), 'blocked_in'), ('Block Process', lambda: self.rules_menu_block('both'), 'blocked'))
            for label, command, tag in actions:
                self._menu_rule_command(menu, label, command, tag)
        menu.add_separator()
        menu.add_command(label='Edit Global Rule' if global_rule else 'Edit App Rule',
                         command=lambda: self.edit_selected_managed_rule(iid), foreground=self.colors.get('muted', '#a8a8a8'))
        menu.add_command(label='Remove Rule', command=self.remove_selected_rule, foreground=self.colors.get('muted', '#a8a8a8'))
        menu.add_separator()
        menu.add_command(label='Copy IP Domain', command=lambda: self.copy_rule_endpoints(self.rules_tree))
        menu.add_command(label='Copy details', command=lambda: self.copy_rule_details(self.rules_tree))
        menu.add_command(label='Rule details', command=lambda: self.show_rule_details(self.rules_tree))
        if not global_rule:
            menu.add_command(label='Open file location', command=lambda iid=iid: self.open_file_location_from_tree(self.rules_tree, iid))
        menu.post(event.x_root, event.y_root)

    def show_alert_menu(self, event):
        if self._show_header_menu(event, self.alerts_tree):
            return 'break'
        iid = self._focus_menu_row(self.alerts_tree, event)
        if not iid:
            return
        menu = self._context_menu()
        values = self.alerts_tree.item(iid, 'values')
        menu.rule_tag = self.connection_tag(self.alert_connection_row(values, iid))
        menu.rule_tags = self.connection_rule_tags(self.alert_connection_row(values, iid))
        rows = [self.alert_connection_row(v, key) for key, v in self.selected_rows(self.alerts_tree)]
        has_global = any(self.connection_global_rules(row) for row in rows)
        actions = (('Allow Process', lambda: self.alert_action(True, False), 'allowed'), ('Block Incoming', lambda: self.alert_action(False, False, 'in'), 'blocked_in'), ('Block Process', lambda: self.alert_action(False, False, 'both'), 'blocked'))
        for label, command, tag in actions:
            self._menu_rule_command(menu, label, command, tag)
        has_app = any(self.application_has_rule(row.get('exe', '')) for row in rows)
        if has_app:
            menu.add_command(label='Remove App Rule', command=self.remove_selected_alert_rules, foreground=self.colors.get('muted', '#a8a8a8'))
        menu.add_separator()
        self._global_menu_commands(menu, lambda allow, direction: self.prompt_connection_globals(rows, allow, direction))
        if has_global:
            menu.add_command(label='Remove Global Rule', command=lambda: self.remove_connection_globals(rows), foreground=self.colors.get('muted', '#a8a8a8'))
        menu.add_separator()
        menu.add_command(label='Copy IP Domain', command=lambda: self.copy_connection_endpoints(self.alerts_tree))
        menu.add_command(label='Copy details', command=lambda: self.copy_connection_details(self.alerts_tree))
        menu.add_command(label='Connection details', command=lambda: self.show_connection_details(self.alerts_tree))
        menu.add_command(label='Open file location', command=lambda iid=iid: self.open_file_location_from_tree(self.alerts_tree, iid))
        menu.post(event.x_root, event.y_root)

    def _global_menu_commands(self, menu, callback, assigned=False):
        self._menu_rule_command(menu, 'Allow Connection', lambda: callback(True, 'both'), 'global_allow')
        self._menu_rule_command(menu, 'Block Incoming', lambda: callback(False, 'in'), 'global_block_in')
        self._menu_rule_command(menu, 'Block Connection', lambda: callback(False, 'both'), 'global_block')

    def _display_values(self, tree, iid):
        mapping = dict(zip(tree['columns'], tree.item(iid, 'values')))
        return tuple((mapping.get(column, '') for column in tree['displaycolumns']))

    def tree_details_from_event(self, event, tree):
        if self._autosize_header(event, tree):
            return 'break'
        iid = tree.identify_row(event.y)
        if iid:
            tree.selection_set(iid)
            tree.focus_set()
            tree.focus(iid)
            self._remember_selection_anchor(tree, iid)
            rows = self.selected_connection_data(tree)
            if rows:
                origin = (event.x_root, event.y_root) if hasattr(event, 'x_root') else None
                self._invoke_near_pointer(lambda: self.edit_connection_rule(rows[0]), origin)

    def rule_details_from_event(self, event):
        if self._autosize_header(event, self.rules_tree):
            return 'break'
        iid = self.rules_tree.identify_row(event.y)
        if iid:
            self.rules_tree.selection_set(iid)
            self.rules_tree.focus_set()
            self.rules_tree.focus(iid)
            self._remember_selection_anchor(self.rules_tree, iid)
            origin = (event.x_root, event.y_root) if hasattr(event, 'x_root') else None
            self._invoke_near_pointer(lambda: self.edit_selected_managed_rule(iid), origin)

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
            self._show_rule_result('Rule Update', 'No executable path was available. No rules were changed.')
            return
        prompt = f"How do you want to block {next(iter(paths.values()))['name']}?" if len(paths) == 1 else f'How do you want to block {len(paths)} selected processes?'
        direction = direction or self.ask_direction(prompt)
        if not direction:
            return
        self._apply_rule_batch(((row['exe'], False, direction, False) for row in paths.values()), report=True)

    def allow_process(self, tree=None):
        tree = tree or self.tree
        rows = self.selected_connection_data(tree)
        self._apply_rule_batch(((row.get('exe'), True, 'both', False) for row in rows), report=True)

    def rules_menu_allow(self):
        self._apply_selected_rule_kind(True, global_target=False)

    def rules_menu_block(self, direction):
        self._apply_selected_rule_kind(False, direction, global_target=False)

    def _apply_selected_rule_kind(self, allow, direction='both', global_target=True):
        requests, skipped = [], []
        for _, values in self.selected_rows(self.rules_tree):
            if len(values) < 6:
                continue
            category = self._managed_rule_category(values[0], values[-1])
            if category == 'port':
                skipped.append(values[-1])
                continue
            is_global = category == 'global'
            if is_global != global_target:
                skipped.append(values[-1])
                continue
            target = str(values[-1]).split(' (', 1)[0] if is_global else values[-1]
            requests.append((target, allow, direction, global_target))
        self._warn_inapplicable_rules(skipped, global_target)
        self._apply_rule_batch(requests, report=True)

    def remove_selected_rule(self, event=None):
        rows = self.selected_rows(self.rules_tree)
        self._remove_rules_with_feedback((values[0], values[-1]) for _, values in rows if len(values) >= 6)

    def remove_selected_connection_rules(self, tree):
        rows = self.selected_connection_data(tree)
        requests = []
        for row in rows:
            status = self.get_rule_status(row.get('exe', ''))
            if status:
                requests.append((status, row['exe']))
        self._remove_rules_with_feedback(requests)

    def remove_selected_connection_global_rules(self, tree):
        self.remove_connection_globals(self.selected_connection_data(tree))

    def remove_connection_globals(self, rows):
        requests = set()
        for row in rows:
            for kind, key, data in self.connection_global_rules(row):
                requests.add((('Global Port ' if kind == 'port' else 'Global ') + data['action'], key))
        self._remove_rules_with_feedback(sorted(requests))

    @staticmethod
    def _connection_global_targets(remote_ip, domain=''):
        # Keep the observed address even when DNS resolves to a different address now.
        return {normalize_target(value) for value in (remote_ip, domain)
                if value and str(value).strip() not in {'', '\u2014', '-'}
                and is_global_target(value)}

    def bulk_global(self, tree, allow, domain=False, direction='both'):
        self._apply_connection_global_targets(self.selected_connection_data(tree), allow, direction)

    def _apply_connection_global_targets(self, rows, allow, direction='both'):
        targets = {}
        for row in rows:
            remote = normalize_target(row.get('dst_ip'))
            host = normalize_target(row.get('domain'))
            target = host if is_global_target(host) else remote
            if not is_global_target(target):
                continue
            observed = targets.setdefault(target, set())
            try:
                observed.add(str(ipaddress.ip_address(remote)))
            except ValueError:
                pass
        # A selection can contain both a cached-host row and an IP-only row for
        # the same endpoint. The domain entry already includes that observed IP.
        domain_addresses = {address for target, addresses in targets.items()
                            if not is_ip(target) for address in addresses}
        targets = {target: addresses for target, addresses in targets.items()
                   if target not in domain_addresses}
        if not targets:
            messagebox.showinfo('Global IP/Domain Rule', 'No valid IP or domain was selected.')
            return
        self._apply_rule_batch(((target, allow, direction, True) for target in sorted(targets)),
                               observed_addresses=targets, report=True)

    def bulk_rule_global(self, allow, direction='both'):
        self._apply_selected_rule_kind(allow, direction, global_target=True)

    # Details and alert actions

    def _connection_rule_descriptions(self, row):
        """List every matching managed policy, without collapsing by precedence."""
        rules = []
        norm = normalize_path(row.get('exe', ''))
        with self.lock:
            if norm in self.allowed_apps:
                rules.append('App Rule: Allow | Direction: Both')
            blocked = self.blocked_paths.get(norm, {})
            if blocked:
                direction = self._direction_from_flags(blocked)
                if direction_set(row.get('direction', 'Both')) <= direction_set(direction):
                    rules.append(f'App Rule: Block | Direction: {direction}')
            if norm in self.auto_prompt_keys:
                rules.append('Auto-Block: Temporary Block | Direction: Both | Pending decision')
        for kind, key, data in self.connection_global_rules(row):
            fields = [f"Global Rule: {data['action']}",
                      f"Target: {data.get('target') or 'Any address'}"]
            if kind == 'port':
                fields.append(f"{data['scope'].title()} Port: {data['port']}" if data['port'] else 'Ports: Any')
                fields.append(f"Protocol: {data.get('protocol', 'TCP/UDP')}")
            else:
                fields.extend(('Ports: Any', 'Protocol: Any'))
            fields.append(f"Direction: {direction_name(data.get('direction', 'Both'))}")
            if data.get('addresses'):
                fields.append('Addresses: ' + ', '.join(data['addresses']))
            rules.append(' | '.join(fields))
        return rules

    def _connection_details_text(self, row):
        norm = normalize_path(row.get('exe'))
        with self.lock:
            stats = self.proc_traffic.get(norm, {})
            active_count = sum((normalize_path(item.get('exe')) == norm for item in self.active_connections.values()))
        text = f"Process: {row['name']}\nPID: {row['pid']}\nExecutable: {row['exe']}\n\nProtocol: {row['protocol']} ({row['direction']})\nLocal Port: {row['lport']}\nRemote: {row['dst_ip']}:{row['dport']}\nRemote Host: {self.remote_host(row) or 'Unresolved'}\nSignal: {row.get('signal') or 'None'}\n\nActive Connections: {active_count}\nProcess Download: {mb(stats.get('download', 0))}\nProcess Upload: {mb(stats.get('upload', 0))}"
        text += f'\nDisplayed Status: {self.connection_status(row)}'
        rules = self._connection_rule_descriptions(row)
        text += '\n\nMatching PyFirewall rules:\n'
        text += '\n'.join(f'{index}. {rule}' for index, rule in enumerate(rules, 1)) or 'None'
        return text

    def copy_connection_details(self, tree):
        rows = self._selected_connection_detail_rows(tree)
        if rows:
            self.copy_text('\n\n---\n\n'.join(self._connection_details_text(row) for row in rows))

    def copy_connection_endpoints(self, tree):
        rows = self._selected_connection_detail_rows(tree)
        if rows:
            self.copy_text('\n'.join('\t'.join(value for value in
                (row.get('dst_ip', ''), self.remote_host(row)) if value and value != '\u2014') for row in rows))

    def _selected_connection_detail_rows(self, tree):
        if tree is getattr(self, 'alerts_tree', None):
            rows = []
            for iid, values in self.selected_rows(tree):
                row = self.alert_connection_row(values, iid)
                row.setdefault('name', values[2] if len(values) > 2 else 'Process')
                row.setdefault('pid', int(values[3]) if len(values) > 3 and str(values[3]).isdigit() else 0)
                row.setdefault('protocol', '')
                row.setdefault('direction', '')
                row.setdefault('lport', '')
                row.setdefault('dport', '')
                row.setdefault('signal', '')
                row.setdefault('dst_ip', values[4] if len(values) > 4 else '')
                row.setdefault('exe', '')
                if len(values) > 5 and values[5] and values[5] != '—':
                    row['display_host'] = values[5]
                rows.append(row)
            return rows
        return self.selected_connection_data(tree)

    def show_connection_details(self, tree):
        rows = self._selected_connection_detail_rows(tree)
        if not rows:
            return
        row = rows[0]
        text = self._connection_details_text(row)
        self._show_details_dialog('Connection details', text, 'Close the Connection Details window.', actions=(
            ('Copy Info', lambda: self.copy_text(text), None),
            ('Open File Location', lambda: self.open_file_location(row.get('exe', '')), None)))

    def copy_text(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def _rule_details_text(self, tree, rows=None):
        rows = self.selected_rows(tree) if rows is None else rows
        if not rows or len(rows[0][1]) < 6:
            return None
        values = rows[0][1]
        status, rule, direction = values[:3]
        down, up, path = values[-3:]
        extra = ''
        if self._managed_rule_category(status, path) == 'global':
            target = normalize_target(str(path).split(' (', 1)[0])
            with self.lock:
                store = self.global_allows if str(status).casefold() == 'global allow' else self.global_blocks
                data = store.get(target, {})
            extra = '\nResolved Addresses: ' + (', '.join(data.get('addresses', ())) or 'Unknown')
        if len(values) == len(self.RULE_COLUMNS):
            extra += f'\nRemote Port: {values[3] or "-"}\nLocal Port: {values[4] or "-"}\nProtocol: {values[5]}'
        return f'Status: {status}\nRule: {rule}\nDirection: {direction}\nDownload: {down}\nUpload: {up}\nPath/Target: {path}{extra}'

    def copy_rule_details(self, tree):
        texts = [self._rule_details_text(tree, [row]) for row in self.selected_rows(tree)]
        if any(texts):
            self.copy_text('\n\n---\n\n'.join(text for text in texts if text))

    def copy_rule_endpoints(self, tree):
        lines = []
        for _, values in self.selected_rows(tree):
            if len(values) < 6:
                continue
            status, path = str(values[0]).casefold(), str(values[-1])
            with self.lock:
                category = self._managed_rule_category(status, path)
                if category == 'port':
                    rule = getattr(self, 'global_ports', {}).get(path, {})
                    target = rule.get('target', '')
                elif category == 'global':
                    target = normalize_target(path.split(' (', 1)[0])
                    rule = (self.global_allows if status == 'global allow' else self.global_blocks).get(target, {})
                else:
                    continue  # Application rules have no remote endpoints.
                targets = [part.strip() for part in target.split(',') if part.strip()]
                addresses = list(dict.fromkeys([*rule.get('addresses', ()), *(part for part in targets if is_ip(part))]))
                hosts = [part for part in targets if not is_ip(part)]
                line = '\t'.join(part for part in (', '.join(addresses), ', '.join(hosts)) if part)
                if line:
                    lines.append(line)
        if lines:
            self.copy_text('\n'.join(lines))

    def show_rule_details(self, tree):
        text = self._rule_details_text(tree)
        if text is not None:
            self._show_details_dialog('Rule Details', text, 'Close the Rule Details window.',
                                      actions=(('Copy Info', lambda: self.copy_text(text), None),))

    def alert_details_from_event(self, event):
        if self._autosize_header(event, self.alerts_tree):
            return 'break'
        iid = self.alerts_tree.identify_row(event.y)
        if not iid:
            return 'break'
        self.alerts_tree.selection_set(iid)
        self.alerts_tree.focus_set()
        self.alerts_tree.focus(iid)
        self._remember_selection_anchor(self.alerts_tree, iid)
        origin = (event.x_root, event.y_root) if hasattr(event, 'x_root') else None
        self._invoke_near_pointer(lambda: self.edit_connection_rule(
            self.alert_connection_row(self.alerts_tree.item(iid, 'values'), iid)), origin)
        return 'break'

    def alert_details(self, iid):
        values = self.alerts_tree.item(iid, 'values')
        if not values:
            return
        text = f'Time: {values[0]}\nSeverity: {values[1]}\nProcess: {values[2]}\nPID: {values[3]}\nRemote: {values[4]}\nRemote Host: {values[5]}\n\nReason: {values[6]}'
        self._show_details_dialog('Alert Details', text, 'Close the Alert Details window.')

    def alert_context(self, values):
        remote = normalize_target(values[4]) if len(values) > 4 else ''
        remote_ip = remote
        remote_port = None
        # A bare IPv6 address must not be mistaken for an address:port pair.
        if remote and not is_ip(remote):
            candidate, _, port = remote.rpartition(':')
            candidate = candidate.strip('[]')
            if candidate and port.isdigit() and is_ip(candidate):
                remote_ip = normalize_target(candidate)
                remote_port = int(port)
        pid = int(values[3]) if len(values) > 3 and str(values[3]).isdigit() else None
        with self.lock:
            matches = [dict(row) for row in self.active_connections.values()
                       if pid is not None and row['pid'] == pid and
                       (normalize_target(row['dst_ip']) == remote_ip or
                        normalize_target(row.get('domain', '')) == remote)
                       and (remote_port is None or str(row.get('dport')) == str(remote_port))]
            # Only process actions need this fallback; global actions use the alert's endpoint.
            if not matches and pid is not None:
                matches = [{key: row[key] for key in ('exe', 'name', 'pid') if key in row}
                           for row in self.active_connections.values() if row['pid'] == pid]
        return (matches[0] if matches else None, remote_ip)

    def alert_action(self, allow, global_target, direction='both'):
        if global_target:
            return self.alert_global_domain(allow, direction)
        requests = []
        for _, values in self.selected_rows(self.alerts_tree):
            row, _ = self.alert_context(values)
            if row and row.get('exe'):
                requests.append((row['exe'], allow, direction, False))
        self._apply_rule_batch(requests, report=True)

    def alert_global_domain(self, allow, direction='both'):
        rows = [self.alert_connection_row(values, iid) for iid, values in self.selected_rows(self.alerts_tree)]
        self._apply_connection_global_targets(rows, allow, direction)

    def remove_selected_alert_rules(self):
        requests = []
        for _, values in self.selected_rows(self.alerts_tree):
            row, remote_ip = self.alert_context(values)
            if row and row.get('exe'):
                status = self.get_rule_status(row['exe'])
                if status:
                    requests.append((status, row['exe']))
        self._remove_rules_with_feedback(requests)

    # Data export and rule import

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
                data = {'format': 'PyFirewall managed rules', 'version': 6, 'global_port_rules': list(getattr(self, 'global_ports', {}).values()), 'exported_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'rules': [{'action': 'Allow', 'direction': 'Both', 'path': path_value} for path_value in sorted(self.allowed_apps)] + [{'action': 'Block', 'direction': self._direction_from_flags(value), 'path': value['path']} for value in self.blocked_paths.values()], 'global_ip_blocks': [{'target': target, 'addresses': list(data.get('addresses', ())), 'direction': data.get('direction', 'Both')} for target, data in sorted(self.global_blocks.items())], 'global_ip_allows': [{'target': target, 'addresses': list(data.get('addresses', ())), 'direction': data.get('direction', 'Both')} for target, data in sorted(self.global_allows.items())]}
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
            ports = list(self._parse_port_rules(data.get('global_port_rules', [])).values())
            if not all(isinstance(entries, list) for entries in (rules, blocks, allows)):
                raise ValueError('Rule collections must be JSON arrays.')
            requests = []
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                path_value = display_path(rule.get('path', ''))
                if path_value:
                    requests.append((path_value, 'allow' in str(rule.get('action', 'Block')).casefold(),
                                     direction_name(rule.get('direction', 'Both')), False))
            for entries, allow in ((blocks, False), (allows, True)):
                for entry in entries:
                    target = entry.get('target', '') if isinstance(entry, dict) else entry
                    if isinstance(target, str) and normalize_target(target):
                        requests.append((target, allow, entry.get('direction', 'both') if isinstance(entry, dict) else 'both', True))
            if not requests and not ports:
                messagebox.showerror('Import Rules', 'No valid managed rules were found.')
                return
            if not messagebox.askyesno('Import Rules', f'Apply {len(requests) + len(ports)} imported rule(s)?'):
                return
            options = {'port_updates': ports} if ports else {}
            if not self._apply_rule_batch(requests, quiet=True, **options):
                messagebox.showerror('Import Incomplete', 'The rule batch could not be applied. See Alerts for details.')
        except Exception as exc:
            messagebox.showerror('Import Failed', str(exc))

    def open_windows_firewall(self):
        try:
            subprocess.Popen(['mmc.exe', 'wf.msc'], creationflags=CREATE_NO_WINDOW)
        except Exception as exc:
            messagebox.showerror('Windows Firewall', str(exc))

    # Traffic display refresh

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
