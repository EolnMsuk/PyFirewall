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
                rows.append({'iid': f'global:{kind}:{target}', 'status': f'Global {global_text}', 'rule': f'Global IP {global_text}', 'action': global_text, 'direction': data.get('direction', 'Both'), 'path': target if not addresses else f"{target} ({', '.join(addresses)})", 'normalized_path': target, 'addresses': addresses, 'global_type': kind, 'download': 0, 'upload': 0})
        with self.lock:
            for key, rule in sorted(getattr(self, 'global_ports', {}).items()):
                rows.append({'iid': f'port:{key}', 'status': f"Global Port {rule['action']}",
                             'rule': f"{rule['scope'].title()} Port {rule['port']} (TCP/UDP)",
                             'action': rule['action'], 'direction': 'Both', 'path': key, 'normalized_path': key,
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
        self.render_active()

    # Rule creation dialogs

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

    def _choose_option(self, title, prompt, choices):
        result = [None]
        dialog = tk.Toplevel(self.root)
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
            button = tk.Button(dialog, text=label, command=lambda v=value: choose(v),
                               bg=color, fg='#171717', relief=tk.FLAT, padx=16, pady=8)
            self._bind_button_hover(button)
            button.pack(fill=tk.X, padx=16, pady=4)
        ttk.Button(dialog, text='Cancel', command=dialog.destroy).pack(pady=12)
        dialog.bind('<Escape>', lambda _: dialog.destroy())
        self._center_dialog(dialog)
        dialog.deiconify()
        self.root.wait_window(dialog)
        return result[0]

    def add_global_rule_dialog(self):
        kind = self._choose_option('Add Global Rule', 'Choose a global rule type:', (
            ('Global IP Domain Rule', 'ip', GLOBAL_PURPLE), ('Global Port Rule', 'port', GLOBAL_PURPLE)))
        if kind == 'port':
            scope = self._choose_option('Global Port Rule', 'Which port should this rule match?', (
                ('Remote Port', 'remote', GLOBAL_PURPLE), ('Local Port', 'local', GLOBAL_PURPLE)))
            if not scope:
                return
            port = simpledialog.askinteger('Global Port Rule', f'{scope.title()} port number (1–65535):',
                                           minvalue=1, maxvalue=65535, parent=self.root)
            if port is None:
                return
            action = self._choose_option('Global Port Rule',
                                        f'{scope.title()} port {port} (TCP and UDP, both directions). Existing blocks still apply.', (
                ('Allow All (Globally)', 'Allow', GLOBAL_TEAL), ('Block All (Globally)', 'Block', GLOBAL_PURPLE)))
            if action:
                self.apply_global_port_rules([{'scope': scope, 'port': port, 'action': action}])
            return
        if kind != 'ip':
            return
        target = simpledialog.askstring('Global IP Domain Rule', 'IP address or domain:', parent=self.root)
        if not target or not target.strip():
            return
        action = self._choose_option('Global IP Domain Rule', target.strip(), (
            ('Allow All (Globally)', 'allow', GLOBAL_TEAL), ('Block (Globally)', 'both', GLOBAL_PURPLE),
            ('Block Incoming (Globally)', 'in', GLOBAL_YELLOW)))
        if action:
            self.add_global_rule(target.strip(), action == 'allow', direction='both' if action == 'allow' else action)

    def bulk_remote_ports(self, tree, allow):
        ports = set()
        for row in self.selected_connection_data(tree):
            raw = str(row.get('dport', ''))
            if str(row.get('protocol', '')).upper() in {'TCP', 'UDP'} and raw.isdecimal() and 1 <= int(raw) <= 65535:
                ports.add(int(raw))
        if not ports:
            messagebox.showinfo('Global Port Rule', 'No valid TCP/UDP remote port was selected.', parent=self.root)
            return
        self.apply_global_port_rules([{'scope': 'remote', 'port': port, 'action': 'Allow' if allow else 'Block'}
                                      for port in sorted(ports)])

    def change_selected_ports(self, allow):
        entries = []
        with self.lock:
            for _, values in self.selected_rows(self.rules_tree):
                if values and str(values[0]).casefold() in {'global port allow', 'global port block'}:
                    rule = self.global_ports.get(str(values[-1]))
                    if rule:
                        entries.append(dict(rule, action='Allow' if allow else 'Block'))
        if entries:
            self.apply_global_port_rules(entries)

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
        self._center_dialog(dialog)
        dialog.deiconify()
        dialog.lift()
        dialog.focus_force()
        self.root.wait_window(dialog)
        return result['value']

    # Sorting and table rendering

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
        fields = {'#': lambda r: r['number'], 'Process Name': lambda r: r['name'].casefold(), 'Status': lambda r: self.connection_status(r).casefold(), 'PID': lambda r: r['pid'], 'Direction': lambda r: r['direction'].casefold(), 'Protocol': lambda r: r['protocol'].casefold(), 'Local Port': lambda r: r['lport'], 'Remote IP': lambda r: r['dst_ip'].casefold(), 'Remote Host': lambda r: r.get('domain', '').casefold(), 'Remote Port': lambda r: r['dport'], 'Download (MB)': lambda r: r.get('_down', 0), 'Upload (MB)': lambda r: r.get('_up', 0), 'Signal': lambda r: r.get('signal', '').casefold(), 'Exe Path': lambda r: r['exe'].casefold()}
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
            tree.insert('', tk.END, iid=row['key'], values=self.connection_values(row, include_status=True), tags=(self.connection_tag(row, index),))
        if selected:
            tree.selection_set([iid for iid in selected if tree.exists(iid)])

    def render_monitor(self):
        self._render_connections(self.tree, self.search_var, self.monitor_sort)

    def render_active(self):
        self._render_connections(self.active_tree, self.active_search_var, self.active_sort, active_only=True)

    def connection_values(self, row, include_status=True):
        values = {'#': row['number'], 'Process Name': row['name'], 'Status': self.connection_status(row),
                  'PID': row['pid'], 'Direction': row['direction'], 'Protocol': row['protocol'],
                  'Local Port': row['lport'], 'Remote IP': row['dst_ip'], 'Remote Host': row.get('domain') or '—',
                  'Remote Port': row['dport'], 'Download (MB)': mb(row.get('_down', 0)),
                  'Upload (MB)': mb(row.get('_up', 0)), 'Signal': row.get('signal') or '—', 'Exe Path': row['exe']}
        return tuple(values[c] for c in self.MONITOR_COLUMNS if include_status or c != 'Status')

    def connection_status(self, row):
        tag = self.connection_tag(row)
        with self.lock:
            if normalize_path(row.get('exe', '')) in self.auto_prompt_keys:
                return 'Blocked (Pending)'
        return {'global_allow': 'Allowed (Global)', 'global_block': 'Blocked (Global)',
                'global_block_in': 'Blocked (Global In)'}.get(tag, self.get_rule_status_display(row.get('exe', '')))

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
        port_action = self.global_port_action(row)
        if port_action == 'Block':
            return 'global_block'
        if self.is_globally_blocked(remote, domain, row.get('direction')):
            return self.global_block_tag(remote, domain, row.get('direction'))
        if port_action == 'Allow' or self.is_globally_allowed(remote, domain, row.get('direction')):
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
            rows = [row for row in rows if search in ' '.join(map(str, (row['status'], row['rule'], row['action'], row['direction'], row['path'], mb(row.get('download', 0)), mb(row.get('upload', 0))))).casefold()]
        column, reverse = self.rule_sort
        if column:
            fields = {'Status': lambda r: r['status'].casefold(), 'Rule / Application': lambda r: r['rule'].casefold(), 'Direction': lambda r: r['direction'].casefold(), 'Download (MB)': lambda r: r.get('download', 0), 'Upload (MB)': lambda r: r.get('upload', 0), 'Program Path': lambda r: r['path'].casefold()}
            rows.sort(key=fields.get(column, lambda r: ''), reverse=reverse)
        selected = set(self.rules_tree.selection())
        self.rules_tree.delete(*self.rules_tree.get_children())
        for row in rows:
            tag = 'global_allow' if row.get('global_type') == 'allow' else ('global_block_in' if row['direction'] == 'Inbound' else 'global_block') if row.get('global_type') == 'block' else 'allowed' if row['status'] == 'Allowed' else 'blocked_in' if row['status'] == 'Blocked (In)' else 'blocked'
            down = '—' if row.get('is_port') else mb(row.get('download', 0))
            up = '—' if row.get('is_port') else mb(row.get('upload', 0))
            self.rules_tree.insert('', tk.END, iid=row['iid'], values=(row['status'], row['rule'], row['direction'], down, up, row['path']), tags=(tag,))
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

    # Alert delivery

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

    # Selection and context-menu actions

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
            if status not in {'global block', 'global allow', 'global port block', 'global port allow'}:
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
        if self._show_header_menu(event, tree):
            return 'break'
        iid = self._focus_menu_row(tree, event)
        if not iid:
            return
        menu = self._context_menu()
        actions = (('Allow Process', lambda: self.allow_process(tree), 'allowed'), ('Block Process', lambda: self.block_process(tree, 'both'), 'blocked'), ('Block Incoming', lambda: self.block_process(tree, 'in'), 'blocked_in'))
        for label, command, tag in actions:
            self._menu_rule_command(menu, label, command, tag)
        menu.add_separator()
        self._global_menu_commands(menu, lambda allow, direction: self.bulk_global(tree, allow, direction=direction))
        menu.add_separator()
        self._menu_rule_command(menu, 'Allow Remote Port (Global)', lambda: self.bulk_remote_ports(tree, True), 'global_allow')
        self._menu_rule_command(menu, 'Block Remote Port (Global)', lambda: self.bulk_remote_ports(tree, False), 'global_block')
        menu.add_separator()
        menu.add_command(label='Open File Location', command=lambda iid=iid: self.open_file_location_from_tree(tree, iid))
        menu.add_command(label='Connection Details', command=lambda: self.show_connection_details(tree))
        menu.add_command(label='Copy Row', command=lambda: self.copy_rows(tree))
        menu.add_separator()
        menu.add_command(label='Remove App Rule', command=lambda: self.remove_selected_connection_rules(tree))
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
        if status in {'global port block', 'global port allow'}:
            self._menu_rule_command(menu, 'Allow Port (Global)', lambda: self.change_selected_ports(True), 'global_allow')
            self._menu_rule_command(menu, 'Block Port (Global)', lambda: self.change_selected_ports(False), 'global_block')
        elif status in {'global block', 'global allow'}:
            self._global_menu_commands(menu, self.bulk_rule_global)
        else:
            actions = (('Allow Process', self.rules_menu_allow, 'allowed'), ('Block Process', lambda: self.rules_menu_block('both'), 'blocked'), ('Block Incoming', lambda: self.rules_menu_block('in'), 'blocked_in'))
            for label, command, tag in actions:
                self._menu_rule_command(menu, label, command, tag)
        menu.add_separator()
        if status not in {'global block', 'global allow', 'global port block', 'global port allow'}:
            menu.add_command(label='Open File Location', command=lambda iid=iid: self.open_file_location_from_tree(self.rules_tree, iid))
        menu.add_command(label='Rule Details', command=lambda: self.show_rule_details(self.rules_tree))
        menu.add_command(label='Copy Row', command=lambda: self.copy_rows(self.rules_tree))
        menu.add_separator()
        menu.add_command(label='Remove Rule', command=self.remove_selected_rule)
        menu.post(event.x_root, event.y_root)

    def show_alert_menu(self, event):
        if self._show_header_menu(event, self.alerts_tree):
            return 'break'
        iid = self._focus_menu_row(self.alerts_tree, event)
        if not iid:
            return
        menu = self._context_menu()
        actions = (('Allow Process', lambda: self.alert_action(True, False), 'allowed'), ('Block Process', lambda: self.alert_action(False, False, 'both'), 'blocked'), ('Block Incoming', lambda: self.alert_action(False, False, 'in'), 'blocked_in'))
        for label, command, tag in actions:
            self._menu_rule_command(menu, label, command, tag)
        menu.add_separator()
        self._global_menu_commands(menu, self.alert_global_domain)
        menu.add_separator()
        menu.add_command(label='Open File Location', command=lambda iid=iid: self.open_file_location_from_tree(self.alerts_tree, iid))
        menu.add_command(label='Alert Details', command=lambda iid=iid: self.alert_details(iid))
        menu.add_command(label='Copy Row', command=lambda: self.copy_rows(self.alerts_tree))
        menu.add_separator()
        menu.add_command(label='Remove App Rule', command=self.remove_selected_alert_rules)
        menu.post(event.x_root, event.y_root)

    def _global_menu_commands(self, menu, callback):
        self._menu_rule_command(menu, 'Allow IP Domain (Global)', lambda: callback(True, 'both'), 'global_allow')
        self._menu_rule_command(menu, 'Block IP Domain (Global)', lambda: callback(False, 'both'), 'global_block')
        self._menu_rule_command(menu, 'Block IP Domain (Global) Incoming', lambda: callback(False, 'in'), 'global_block_in')

    def _display_values(self, tree, iid):
        mapping = dict(zip(tree['columns'], tree.item(iid, 'values')))
        return tuple((mapping.get(column, '') for column in tree['displaycolumns']))

    def copy_rows(self, tree):
        rows = [self._display_values(tree, iid) for iid in tree.selection()]
        if rows:
            self.root.clipboard_clear()
            self.root.clipboard_append('\n'.join(('\t'.join(map(str, row)) for row in rows)))

    def tree_details_from_event(self, event, tree):
        if self._autosize_header(event, tree):
            return 'break'
        iid = tree.identify_row(event.y)
        if iid:
            tree.selection_set(iid)
            tree.focus_set()
            tree.focus(iid)
            self._remember_selection_anchor(tree, iid)
            self.show_connection_details(tree)

    def rule_details_from_event(self, event):
        if self._autosize_header(event, self.rules_tree):
            return 'break'
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
        self._apply_rule_batch((row['exe'], False, direction, False) for row in paths.values())

    def allow_process(self, tree=None):
        tree = tree or self.tree
        rows = self.selected_connection_data(tree)
        self._apply_rule_batch((row.get('exe'), True, 'both', False) for row in rows)

    def rules_menu_allow(self):
        self._apply_selected_rule_kind(True, global_target=False)

    def rules_menu_block(self, direction):
        self._apply_selected_rule_kind(False, direction, global_target=False)

    def _apply_selected_rule_kind(self, allow, direction='both', global_target=True):
        requests, skipped = [], []
        for _, values in self.selected_rows(self.rules_tree):
            if len(values) < 6:
                continue
            if str(values[0]).casefold() in {'global port block', 'global port allow'}:
                skipped.append(values[-1])
                continue
            is_global = str(values[0]).casefold() in {'global block', 'global allow'}
            if is_global != global_target:
                skipped.append(values[-1])
                continue
            target = str(values[-1]).split(' (', 1)[0] if is_global else values[-1]
            requests.append((target, allow, direction, global_target))
        self._warn_inapplicable_rules(skipped, global_target)
        self._apply_rule_batch(requests)

    def remove_selected_rule(self, event=None):
        rows = self.selected_rows(self.rules_tree)
        self._remove_rule_batch((values[0], values[-1]) for _, values in rows if len(values) >= 6)

    def remove_selected_connection_rules(self, tree):
        rows = self.selected_connection_data(tree)
        requests = []
        for row in rows:
            status = self.get_rule_status(row.get('exe', ''))
            if status:
                requests.append((status, row['exe']))
            elif self.is_globally_blocked(row['dst_ip'], row.get('domain', ''), row.get('direction')):
                requests.append(('Global Block', row.get('domain') or row['dst_ip']))
            elif self.is_globally_allowed(row['dst_ip'], row.get('domain', ''), row.get('direction')):
                requests.append(('Global Allow', row.get('domain') or row['dst_ip']))
        self._remove_rule_batch(requests)

    @staticmethod
    def _connection_global_targets(remote_ip, domain=''):
        # Keep the observed address even when DNS resolves to a different address now.
        return {normalize_target(value) for value in (remote_ip, domain)
                if value and str(value).strip() not in {'', '\u2014', '-'}
                and is_global_target(value)}

    def bulk_global(self, tree, allow, domain=False, direction='both'):
        targets = {}
        for row in self.selected_connection_data(tree):
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
        scope = ' (incoming only)' if direction_name(direction) == 'Inbound' else ''
        if not messagebox.askyesno('Global Rule', f"{('Allow' if allow else 'Block')} {len(targets)} selected IP/domain target(s) globally{scope}?"):
            return
        self._apply_rule_batch(((target, allow, direction, True) for target in sorted(targets)),
                               observed_addresses=targets)

    def bulk_rule_global(self, allow, direction='both'):
        self._apply_selected_rule_kind(allow, direction, global_target=True)

    # Details and alert actions

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
        policy = 'Global Block' if self.is_globally_blocked(row['dst_ip'], row.get('domain', ''), row.get('direction')) else 'Global Allow' if self.is_globally_allowed(row['dst_ip'], row.get('domain', ''), row.get('direction')) else 'None'
        port_policy = self.global_port_action(row) or 'None'
        text = f"Process: {row['name']}\nPID: {row['pid']}\nExecutable: {row['exe']}\n\nProtocol: {row['protocol']} ({row['direction']})\nLocal Port: {row['lport']}\nRemote: {row['dst_ip']}:{row['dport']}\nRemote Host: {row.get('domain') or 'Unresolved'}\nSignal: {row.get('signal') or 'None'}\n\nApplication Rule: {status}\nGlobal Policy: {policy}\nActive Connections: {active_count}\nProcess Download: {mb(stats.get('download', 0))}\nProcess Upload: {mb(stats.get('upload', 0))}"
        text += f'\nGlobal Port Rule: {port_policy}\nDisplayed Status: {self.connection_status(row)}'
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
        if self._autosize_header(event, self.alerts_tree):
            return 'break'
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
        remote = normalize_target(values[4]) if len(values) > 4 else ''
        remote_ip = remote
        # A bare IPv6 address must not be mistaken for an address:port pair.
        if remote and not is_ip(remote):
            candidate, _, port = remote.rpartition(':')
            candidate = candidate.strip('[]')
            if candidate and port.isdigit() and is_ip(candidate):
                remote_ip = normalize_target(candidate)
        pid = int(values[3]) if len(values) > 3 and str(values[3]).isdigit() else None
        with self.lock:
            matches = [dict(row) for row in self.active_connections.values()
                       if pid is not None and row['pid'] == pid and
                       (normalize_target(row['dst_ip']) == remote_ip or
                        normalize_target(row.get('domain', '')) == remote)]
            # Only process actions need this fallback; global actions use the alert's endpoint.
            if not matches and pid is not None:
                matches = [dict(row) for row in self.active_connections.values() if row['pid'] == pid]
        return (matches[0] if matches else None, remote_ip)

    def alert_action(self, allow, global_target, direction='both'):
        if global_target:
            return self.alert_global_domain(allow, direction)
        requests = []
        for _, values in self.selected_rows(self.alerts_tree):
            row, _ = self.alert_context(values)
            if row and row.get('exe'):
                requests.append((row['exe'], allow, direction, False))
        self._apply_rule_batch(requests)

    def alert_global_domain(self, allow, direction='both'):
        targets = set()
        for _, values in self.selected_rows(self.alerts_tree):
            row, remote = self.alert_context(values)
            domain = values[5] if len(values) > 5 else ''
            # Never substitute a different connection merely because its PID matches.
            if row and remote in {normalize_target(row.get('dst_ip')), normalize_target(row.get('domain'))}:
                domain = domain if is_global_target(domain) else row.get('domain', '')
                targets.update(self._connection_global_targets(row.get('dst_ip'), domain))
            targets.update(self._connection_global_targets(remote, domain))
        if not targets:
            messagebox.showinfo('Global IP/Domain Rule', 'No valid IP or domain was linked to the selected alert.')
            return
        self._apply_rule_batch((target, allow, direction, True) for target in sorted(targets))

    def remove_selected_alert_rules(self):
        requests = []
        for _, values in self.selected_rows(self.alerts_tree):
            row, remote_ip = self.alert_context(values)
            if row and row.get('exe'):
                status = self.get_rule_status(row['exe'])
                if status:
                    requests.append((status, row['exe']))
        self._remove_rule_batch(requests)

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
            else:
                messagebox.showinfo('Import Complete', 'Imported rules were applied.')
        except Exception as exc:
            messagebox.showerror('Import Failed', str(exc))

    def open_windows_firewall(self):
        try:
            subprocess.Popen(['control.exe', '/name', 'Microsoft.WindowsFirewall'], creationflags=CREATE_NO_WINDOW)
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
