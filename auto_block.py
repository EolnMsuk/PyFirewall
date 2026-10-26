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

    def handle_threshold(self, proc_name, exe, pid, remote_ip, domain, direction, key, reason, detail):
        with self.lock:
            row = getattr(self, 'active_connections', {}).get(key, {})
        if self.global_port_action(row):
            # A matching port is already managed; do not add a new application
            # hold because of this connection. Existing application blocks stay.
            self.queue_alert('High', proc_name, pid, remote_ip,
                             f'{reason.title()} threshold reached; a global port rule applies. Existing application and IP blocks remain in effect.', connection=row)
            return
        app_rule_exists = self.application_has_rule(exe)
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
                text = f"{reason.title()} threshold reached for {remote_ip}{(f' ({detail})' if detail else '')}; the process was blocked pending your decision."
        self.queue_alert('High', proc_name, pid, remote_ip, text, connection=row)
        with self.lock:
            active = self.log_alerts_only and self.auto_block_enabled and (not self.is_paused)
        if active and not globally_blocked and not globally_allowed and not app_rule_exists:
            self.start_auto_block(proc_name, exe, pid, remote_ip, domain, direction, key, reason, detail)

    def install_auto_hold(self, proc_name, exe, remote_ip='', domain='', prompt_generation=None, direction='both'):
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
                    if self._global_match(self.global_blocks, remote_ip, domain, direction) or self._global_match(self.global_allows, remote_ip, domain, direction):
                        return False
                records = self.get_firewall_rules()
                if any((not r['is_global']) and (not r['is_hold']) and r['normalized_path'] == norm for r in records):
                    return False
                self.delete_rule_names((r['name'] for r in records if r['is_hold'] and r['normalized_path'] == norm))
                self.add_app_rules(proc_name, exe, 'both', kind='AutoHold')
            return True
        except Exception:
            return False

    # Prompt cancellation and publication

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
            if self.global_port_action(getattr(self, 'active_connections', {}).get(key, {})):
                return
            if not self.log_alerts_only or not self.auto_block_enabled or self.is_paused or self.closed:
                return
            if prompt_key in self.auto_prompt_keys:
                return
            generation = self.auto_prompt_generation
            self.auto_prompt_keys.add(prompt_key)
        if not self.install_auto_hold(proc_name, exe, remote_ip, domain, generation, direction):
            with self.lock:
                current = generation == self.auto_prompt_generation
                self.auto_prompt_keys.discard(prompt_key)
                active_now = self.log_alerts_only and self.auto_block_enabled and (not self.is_paused) and (not self.closed)
            if current and active_now and (not self.application_has_rule(exe)) and (not self.is_globally_blocked(remote_ip, domain, direction)) and (not self.is_globally_allowed(remote_ip, domain, direction)):
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
        with self.lock:
            current_generation = generation == self.auto_prompt_generation
        active = self._auto_block_active()
        has_app_rule = self.application_has_rule(exe)
        has_global_rule = self.is_globally_blocked(remote_ip, domain, direction) or self.is_globally_allowed(remote_ip, domain, direction)
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
                applying.configure(text='Could not apply decision. Please retry.')
                messagebox.showerror('Firewall Update Failed',
                                     'The decision could not be applied. Review Alerts for details and retry.', parent=dialog)
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
            worker = threading.Thread(target=self._auto_decision_worker,
                                      args=(generation, key, exe, proc_name, choice, result_queue),
                                      daemon=True, name='PyFirewall-Decision')
            try:
                worker.start()
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
