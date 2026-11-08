"""Temporary protection, threshold decisions and Auto-Block prompts."""

import queue
import threading
import tkinter as tk
from tkinter import messagebox

from helpers import log_internal_error, normalize_path
from widgets import add_tooltip

class AutoBlockMixin:
    """Methods composed into FirewallMonitorApp; state is owned by that application."""

    # Threshold handling and temporary holds

    def _detection_token_locked(self):
        return (getattr(self, 'detection_epoch', 0), self.auto_prompt_generation,
                getattr(self, 'rate_threshold', None), getattr(self, 'rate_window', None),
                getattr(self, 'upload_threshold_mb', None), self.log_alerts_only,
                self.auto_block_enabled, self.is_paused, getattr(self, 'sniffing', True), self.closed)

    def _threshold_current(self, row):
        with self.lock:
            return row.get('_detection_token') == self._detection_token_locked()

    def _threshold_connection(self, exe, remote_ip, domain, direction, key, connection=None):
        if connection is None:
            with self.lock:
                connection = getattr(self, 'active_connections', {}).get(key, {})
        return dict(connection, exe=exe, dst_ip=remote_ip, domain=domain, direction=direction, key=key)

    def _threshold_has_rule(self, row):
        return self.connection_has_rule(row.get('exe'), row.get('dst_ip', ''), row.get('domain', ''),
                                        row.get('direction'), row.get('lport'), row.get('dport'),
                                        row.get('protocol', 'TCP'))

    def handle_threshold(self, proc_name, exe, pid, remote_ip, domain, direction, key, reason, detail, connection=None):
        row = self._threshold_connection(exe, remote_ip, domain, direction, key, connection)
        with self.lock:
            row.setdefault('_detection_token', self._detection_token_locked())
        if not self._threshold_current(row):
            return
        if self.global_port_action(row):
            # A matching port is already managed; do not add a new application
            # hold because of this connection. Existing application blocks stay.
            self.queue_alert('High', proc_name, pid, remote_ip,
                             f'{reason.title()} threshold reached; a global port rule applies. Existing application and IP blocks remain in effect.', connection=row)
            return
        status = self.get_rule_status(exe)
        app_rule_exists = (status in {'allowed', 'blocked_both'} or
                           status == 'blocked_in' and str(direction).lower() in {'in', 'incoming', 'inbound'} or
                           status == 'blocked_out' and str(direction).lower() in {'out', 'outgoing', 'outbound'})
        globally_blocked = self.is_globally_blocked(remote_ip, domain, direction)
        globally_allowed = self.is_globally_allowed(remote_ip, domain, direction)
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
                text = f"{reason.title()} threshold reached for {remote_ip}{(f' ({detail})' if detail else '')}; temporary protection was requested."
        self.queue_alert('High', proc_name, pid, remote_ip, text, connection=row)
        with self.lock:
            active = self.log_alerts_only and self.auto_block_enabled and (not self.is_paused)
        if active and not globally_blocked and not globally_allowed and not app_rule_exists:
            self.start_auto_block(proc_name, exe, pid, remote_ip, domain, direction, key, reason, detail, row)

    def install_auto_hold(self, proc_name, exe, remote_ip='', domain='', prompt_generation=None, direction='both', connection=None):
        norm = normalize_path(exe)
        if not norm:
            return False
        try:
            with self.firewall_lock:
                self._require_valid_policy_settings()
                with self.lock:
                    if not self.log_alerts_only or not self.auto_block_enabled or self.is_paused or self.closed:
                        return False
                    if norm in self.allowed_apps:
                        return False
                    if prompt_generation is not None and prompt_generation != self.auto_prompt_generation:
                        return False
                    if self.is_globally_blocked(remote_ip, domain, direction) or self.is_globally_allowed(remote_ip, domain, direction):
                        return False
                    if connection is not None and (not self._threshold_current(connection) or self._threshold_has_rule(connection)):
                        return False
                records = self.get_firewall_rules()
                self._reconcile_native_rules_locked(records)
                row = connection or self._threshold_connection(exe, remote_ip, domain, direction, '')
                if self._threshold_has_rule(row):
                    return False
                # Keep a cleanup obligation even if native installation or its
                # own rollback fails partway through.
                with self.lock:
                    if not hasattr(self, 'auto_hold_owners'):
                        self.auto_hold_owners = {}
                    self.auto_hold_owners[norm] = prompt_generation
                self.delete_rule_names((r['name'] for r in records if r['is_hold'] and r['normalized_path'] == norm))
                self.add_app_rules(proc_name, exe, 'both', kind='AutoHold')
                with self.lock:
                    if not hasattr(self, 'auto_hold_owners'):
                        self.auto_hold_owners = {}
                    self.auto_hold_owners[norm] = prompt_generation
            return True
        except Exception as exc:
            log_internal_error('install_auto_hold', exc)
            return False

    # Prompt cancellation and publication

    def _dismiss_auto_dialog(self, dialog):
        if dialog is None:
            return
        if threading.get_ident() != getattr(self, 'ui_thread_id', threading.main_thread().ident):
            self.ui_queue.put(('close_dialog', dialog))
            return
        try:
            dialog.destroy()
        except tk.TclError:
            pass

    def _cancel_app_prompt(self, norm):
        dialog = None
        with self.lock:
            self.auto_prompt_keys.discard(norm)
            getattr(self, 'auto_prompt_connections', {}).pop(norm, None)
            getattr(self, 'auto_decision_saves', {}).pop(norm, None)
            getattr(self, 'auto_hold_owners', {}).pop(norm, None)
            getattr(self, 'auto_hold_cleanup', {}).pop(norm, None)
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
        self._dismiss_auto_dialog(dialog)

    def _invalidate_auto_prompts(self, close_dialog=False):
        dialog = None
        with self.lock:
            if not hasattr(self, 'auto_hold_cleanup'):
                self.auto_hold_cleanup = {}
            self.auto_hold_cleanup.update(getattr(self, 'auto_hold_owners', {}))
            self.auto_prompt_generation += 1
            self.detection_epoch = getattr(self, 'detection_epoch', 0) + 1
            self.connection_rates.clear()
            self.upload_alerted.clear()
            self.auto_prompt_keys.clear()
            getattr(self, 'auto_prompt_connections', {}).clear()
            getattr(self, 'auto_decision_saves', {}).clear()
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
        self._dismiss_auto_dialog(dialog)

    def start_auto_block(self, proc_name, exe, pid, remote_ip, domain, direction, key, reason, detail, connection=None):
        row = self._threshold_connection(exe, remote_ip, domain, direction, key, connection)
        with self.lock:
            row.setdefault('_detection_token', self._detection_token_locked())
        if hasattr(self, 'native_jobs') and threading.current_thread() is not self.native_worker:
            self._queue_native_job('Auto-Block hold', lambda: self.start_auto_block(
                proc_name, exe, pid, remote_ip, domain, direction, key, reason, detail, row),
                key=('hold', normalize_path(exe) or key, key, row['_detection_token']))
            return
        with self.firewall_lock:
            self._start_auto_block_locked(proc_name, exe, pid, remote_ip, domain, direction, key, reason, detail, row)

    def _start_auto_block_locked(self, proc_name, exe, pid, remote_ip, domain, direction, key, reason, detail, connection=None):
        prompt_key = normalize_path(exe) or key
        row = self._threshold_connection(exe, remote_ip, domain, direction, key, connection)
        with self.lock:
            if not self._threshold_current(row):
                return
            if self._threshold_has_rule(row) or getattr(self, 'settings_load_error', None):
                return
            if not self.log_alerts_only or not self.auto_block_enabled or self.is_paused or self.closed:
                return
            if prompt_key in self.auto_prompt_keys:
                return
            if len(self.auto_prompt_keys) >= 128:
                self.queue_alert('High', proc_name, pid, remote_ip,
                                 'Auto-Block prompt capacity reached. Resolve pending decisions; this hold was not installed.')
                return
            generation = self.auto_prompt_generation
            self.auto_prompt_keys.add(prompt_key)
        if not self.install_auto_hold(proc_name, exe, remote_ip, domain, generation, direction, row):
            with self.lock:
                needs_cleanup = prompt_key in getattr(self, 'auto_hold_owners', {})
            if needs_cleanup:
                self._release_auto_hold_locked(prompt_key, generation)
            with self.lock:
                current = generation == self.auto_prompt_generation
                self.auto_prompt_keys.discard(prompt_key)
                active_now = self.log_alerts_only and self.auto_block_enabled and (not self.is_paused) and (not self.closed)
            if current and active_now and not self._threshold_has_rule(row):
                self.queue_alert('High', proc_name, pid, remote_ip, 'Threshold reached, but the temporary Auto-Block hold could not be installed.')
            return
        with self.lock:
            if not hasattr(self, 'auto_hold_owners'):
                self.auto_hold_owners = {}
            self.auto_hold_owners[prompt_key] = generation
            if not self._threshold_current(row) or generation != self.auto_prompt_generation or self.closed or self.is_paused or not self.log_alerts_only or not self.auto_block_enabled:
                stale = True
            else:
                stale = False
                if not hasattr(self, 'auto_prompt_connections'):
                    self.auto_prompt_connections = {}
                self.auto_prompt_connections[prompt_key] = (generation, row)
                self.prompt_queue.put((generation, prompt_key, proc_name, exe, pid, remote_ip, domain, direction, reason, detail))
        if stale:
            self._release_auto_hold_locked(prompt_key, generation)
            with self.lock:
                self.auto_prompt_keys.discard(prompt_key)
            return

    def _release_auto_hold_locked(self, path, generation):
        """Retire only this owner; a newer hold may already occupy the path."""
        with self.lock:
            owner = getattr(self, 'auto_hold_owners', {}).get(path)
            if owner is not None and owner != generation:
                if getattr(self, 'auto_hold_cleanup', {}).get(path) == generation:
                    self.auto_hold_cleanup.pop(path, None)
                return True
        try:
            self.remove_auto_holds_locked(path)
        except Exception as exc:
            with self.lock:
                if not hasattr(self, 'auto_hold_cleanup'):
                    self.auto_hold_cleanup = {}
                self.auto_hold_cleanup[path] = generation
            log_internal_error('release_auto_hold', exc)
            self.queue_alert('High', path, '', '', f'Could not release cancelled temporary block: {exc}')
            return False
        with self.lock:
            if getattr(self, 'auto_hold_owners', {}).get(path) == generation:
                self.auto_hold_owners.pop(path, None)
            if getattr(self, 'auto_hold_cleanup', {}).get(path) == generation:
                self.auto_hold_cleanup.pop(path, None)
        return True

    def release_auto_holds(self):
        with self.firewall_lock:
            self.remove_auto_holds_locked()
            self._invalidate_auto_prompts(close_dialog=True)
            with self.lock:
                getattr(self, 'auto_hold_owners', {}).clear()
                getattr(self, 'auto_hold_cleanup', {}).clear()

    # UI dispatch and background decisions

    def drain_prompt_queue(self):
        with self.lock:
            if self.auto_prompt_active:
                return
        try:
            item = self.prompt_queue.get_nowait()
        except queue.Empty:
            return
        generation, key, proc_name, exe, pid, remote_ip, domain, direction, reason, detail = item
        # Never wait for native work on Tk. Obsolete holds remain represented by
        # their owner until the worker can retire them.
        if not self.firewall_lock.acquire(blocking=False):
            self.prompt_queue.put(item)
            return
        try:
            with self.lock:
                current_generation = generation == self.auto_prompt_generation and key in self.auto_prompt_keys
                saved = getattr(self, 'auto_prompt_connections', {}).get(key)
                row = saved[1] if saved and saved[0] == generation else self._threshold_connection(exe, remote_ip, domain, direction, key)
            if not current_generation or not self._auto_block_active() or self._threshold_has_rule(row):
                with self.lock:
                    self.auto_hold_cleanup[normalize_path(exe)] = generation
                if not hasattr(self, 'native_jobs'):
                    self._release_auto_hold_locked(normalize_path(exe), generation)
                with self.lock:
                    if generation == self.auto_prompt_generation:
                        self.auto_prompt_keys.discard(key)
                        getattr(self, 'auto_prompt_connections', {}).pop(key, None)
                return
            with self.lock:
                self.auto_prompt_active = True
                self.auto_prompt_key = key
        finally:
            self.firewall_lock.release()
        self.show_auto_prompt(generation, key, proc_name, exe, pid, remote_ip, reason, detail)

    def _auto_block_active(self):
        with self.lock:
            return (self.log_alerts_only and self.auto_block_enabled and not self.is_paused
                    and not self.closed and not getattr(self, 'settings_load_error', None))

    def _auto_decision_worker(self, generation, key, exe, proc_name, choice, result_queue):
        """Apply a decision without calling Tk; the prompt owns result delivery."""
        ok = None
        norm = normalize_path(exe)
        def own_commit():
            pending = getattr(self, 'auto_decision_saves', {}).get(key)
            return (pending is not None and pending[0] == generation
                    and pending[2] == getattr(self, 'app_policy_versions', {}).get(norm))
        def committed(version):
            if not hasattr(self, 'auto_decision_saves'):
                self.auto_decision_saves = {}
            self.auto_decision_saves[key] = (generation, choice, version)
        def current_decision():
            with self.lock:
                saved = getattr(self, 'auto_prompt_connections', {}).get(key)
                return (generation == self.auto_prompt_generation and self.auto_prompt_key == key
                        and self._auto_block_active()
                        and (own_commit() or not (saved and saved[0] == generation and self._threshold_has_rule(saved[1]))))
        current_decision.committed = committed
        try:
            with self.firewall_lock:
                with self.lock:
                    current = (not self.closed and generation == self.auto_prompt_generation
                               and self.auto_prompt_key == key and self._auto_block_active())
                    saved = getattr(self, 'auto_prompt_connections', {}).get(key)
                if current and own_commit() and self.auto_decision_saves[key][1] == choice:
                    # This operation already committed. Retry durability only;
                    # its own cached policy must not supersede its failed save.
                    self._persist_rule_changes()
                    ok = True
                    return
                if current and not own_commit() and saved and saved[0] == generation and self._threshold_has_rule(saved[1]):
                    if self._release_auto_hold_locked(normalize_path(exe), generation):
                        self._cancel_app_prompt(key)
                    else:
                        ok = False
                    current = False
                if current:
                    if choice == 'allow':
                        ok = self.allow_executable(exe, refresh=False, quiet=True, update_ui=False, decision_guard=current_decision)
                    else:
                        ok = self.block_executable(exe, proc_name, 'in' if choice == 'in' else 'both',
                                                   refresh=False, quiet=True, update_ui=False, decision_guard=current_decision)
        except Exception as exc:
            ok = False
            log_internal_error('auto_decision', exc)
            self.queue_alert('High', exe, '', '', f'Firewall decision failed: {exc}')
        finally:
            result_queue.put(ok)

    # Decision dialog

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
                pending_save = key in getattr(self, 'auto_decision_saves', {})
                text = ('Decision applied but not saved. Retry the same choice to save it.' if pending_save
                        else 'Could not apply decision. Please retry.')
                applying.configure(text=text)
                messagebox.showerror('Firewall Update Failed',
                                     text + '\nReview Alerts for details.', parent=dialog)
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
            with self.lock:
                self.rules_generation += 1
            try:
                if hasattr(self, 'native_jobs'):
                    if not self._queue_native_job('Auto-Block decision', lambda: self._auto_decision_worker(
                            generation, key, exe, proc_name, choice, result_queue)):
                        result_queue.put(False)
                else:
                    threading.Thread(target=self._auto_decision_worker,
                                     args=(generation, key, exe, proc_name, choice, result_queue),
                                     daemon=True, name='PyFirewall-Decision').start()
            except Exception as exc:
                self.queue_alert('High', exe, pid, remote_ip, f'Could not start firewall decision: {exc}')
                result_queue.put(False)
            self.root.after(50, poll_decision)
        action_specs = (('Block In & Out', 'both', '#c62828', 'Block the executable for both incoming and outgoing traffic.'), ('Block Incoming', 'in', '#ff9800', 'Block incoming traffic while leaving outgoing traffic allowed.'), ('Allow All', 'allow', '#4CAF50', 'Remove the temporary block and allow the executable.'))
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
                    dialog.attributes('-topmost', getattr(self, 'keep_notification_foreground', True))
            except tk.TclError:
                pass
        dialog.after(250, release_topmost)
