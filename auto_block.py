"""Temporary protection, threshold decisions and Auto-Block prompts."""

import queue
import copy
import threading
import time
from collections import OrderedDict
import tkinter as tk
from tkinter import messagebox

from helpers import direction_name, log_internal_error, normalize_path
from widgets import sync_tooltip_stacking

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
        cached = row.get('_coverage')
        if cached and cached[0] == self._policy_revision_locked():
            return cached[1]
        if self.lock._is_owned():
            # Unknown coverage retains requests/holds. Callers refresh detached
            # endpoints outside the lock before admitting or retiring work.
            return False
        row['_coverage'] = self._connection_coverage(row)
        return row['_coverage'][1]

    def _connection_coverage(self, row, snapshot=None):
        snapshot = snapshot if snapshot is not None else self._matching_snapshot()
        revision, _ = snapshot
        matching = self.matching_global_port_rules(row, snapshot)
        with self.lock:
            keys = frozenset(key for key in matching if self._policy_verified('port', key))
            status = self.get_rule_status(row.get('exe'))
        direction = direction_name(row.get('direction'))
        covered = bool(keys) or status in {'allowed', 'blocked_both'} or status == 'blocked_in' and direction == 'Inbound' or status == 'blocked_out' and direction == 'Outbound'
        return revision, covered, keys

    def _refresh_pending_coverage(self, key=None):
        with self.lock:
            rows = [row for path, pending in getattr(self, 'auto_pending_requests', {}).items()
                    if key is None or path == key for row in pending.values()]
            rows.extend(saved[1] for path, saved in getattr(self, 'auto_prompt_connections', {}).items() if key is None or path == key)
            rows.extend(saved[1] for (path, _), saved in getattr(self, 'auto_detection_requests', {}).items() if key is None or path == key)
        snapshot = self._matching_snapshot()
        values = [(row, self._connection_coverage(row, snapshot)) for row in rows]
        with self.lock:
            if snapshot[0] == self._policy_revision_locked():
                for row, coverage in values:
                    row['_coverage'] = coverage

    @staticmethod
    def _auto_request_identity(row):
        return (str(row.get('dst_ip', '')).casefold(), str(row.get('lport', '')), str(row.get('dport', '')),
                str(row.get('protocol', '')).upper(), direction_name(row.get('direction')))

    def _admit_auto_request_locked(self, row, reason='connection', detail=''):
        """Admission is capture-side state, independent of a discardable worker job."""
        key = normalize_path(row.get('exe'))
        if not key or self._threshold_has_rule(row) or not self._auto_block_active():
            return False
        if not hasattr(self, 'auto_pending_requests'):
            self.auto_pending_requests = {}
        identity = self._auto_request_identity(row)
        pending = self.auto_pending_requests.get(key, {})
        if identity in pending:
            return True
        if (len(pending) >= 128 or sum(map(len, self.auto_pending_requests.values())) >= 2048
                or key not in self.auto_pending_requests and len(self.auto_pending_requests) >= 128):
            self.dropped_auto_requests = getattr(self, 'dropped_auto_requests', 0) + 1
            return False
        self.auto_request_serial = getattr(self, 'auto_request_serial', 0) + 1
        snapshot = copy.deepcopy(row)
        snapshot.update(_request_id=self.auto_request_serial, _prompt_reason=reason, _prompt_detail=detail)
        self.auto_pending_requests.setdefault(key, {})[identity] = snapshot
        self.auto_prompt_keys.add(key)
        return True

    def _observe_auto_request_locked(self, row, now):
        """Bounded detection-window snapshots also cover sub-threshold arrivals."""
        if not self._auto_block_active() or self._threshold_has_rule(row):
            return
        if not hasattr(self, 'auto_detection_requests'):
            self.auto_detection_requests = OrderedDict()
        history = self.auto_detection_requests
        window = getattr(self, 'rate_window', 5.0)
        while history and now - next(iter(history.values()))[0] > window:
            history.popitem(last=False)
        key = normalize_path(row.get('exe'))
        identity = (key, self._auto_request_identity(row))
        history.pop(identity, None)
        if len(history) >= 2048:
            history.popitem(last=False)
        history[identity] = (now, copy.deepcopy(row))
        if key in self.auto_prompt_keys:
            self._admit_auto_request_locked(row)

    def _auto_request_id_locked(self, key):
        saved = getattr(self, 'auto_prompt_connections', {}).get(key)
        return saved[1].get('_request_id') if saved else None

    def _publish_auto_request_locked(self, key, generation):
        if key in self.auto_prompt_connections or getattr(self, 'auto_hold_ready', {}).get(key) != generation:
            return
        pending = getattr(self, 'auto_pending_requests', {}).get(key, {})
        for row in pending.values():
            if not self._threshold_has_rule(row):
                self.auto_prompt_connections[key] = (generation, row)
                self.prompt_queue.put((generation, key, row.get('name', 'Process'), row['exe'], row.get('pid', 0),
                                       row.get('dst_ip', ''), row.get('domain', ''), row.get('direction'),
                                       row.get('_prompt_reason', 'connection'), row.get('_prompt_detail', ''), row['_request_id']))
                return

    def _remaining_auto_requests_locked(self, key, request_id=None):
        return [row for row in getattr(self, 'auto_pending_requests', {}).get(key, {}).values()
                if row.get('_request_id') != request_id and not self._threshold_has_rule(row)]

    def _finish_auto_request(self, key, generation, request_id=None):
        """Close exactly this request; later requests retain their application hold."""
        self._refresh_pending_coverage(key)
        with self.lock:
            if generation != self.auto_prompt_generation or self._auto_request_id_locked(key) != request_id:
                return
            pending = getattr(self, 'auto_pending_requests', {}).get(key, {})
            for identity, row in list(pending.items()):
                if self._threshold_has_rule(row):
                    pending.pop(identity)
                elif row.get('_request_id') == request_id:
                    # An incoming-only app choice can leave this outgoing request unresolved.
                    self.auto_request_serial = getattr(self, 'auto_request_serial', 0) + 1
                    pending[identity] = dict(row, _request_id=self.auto_request_serial)
            self.auto_prompt_connections.pop(key, None)
            getattr(self, 'auto_decision_saves', {}).pop(key, None)
            getattr(self, 'auto_decision_errors', {}).pop(key, None)
            if pending:
                if self.auto_hold_cleanup.get(key) == generation and self.auto_hold_owners.get(key) == generation:
                    self.auto_hold_cleanup.pop(key, None)
                self._publish_auto_request_locked(key, generation)
            else:
                getattr(self, 'auto_pending_requests', {}).pop(key, None)
                self.auto_prompt_keys.discard(key)
        self._dismiss_auto_dialog((generation, key, request_id))

    def _schedule_auto_hold(self, key, generation):
        self._refresh_pending_coverage(key)
        with self.lock:
            if (generation != self.auto_prompt_generation or key not in self.auto_prompt_keys
                    or getattr(self, 'auto_hold_ready', {}).get(key) == generation):
                return
            pending = getattr(self, 'auto_pending_requests', {}).get(key, {})
            for identity, candidate in list(pending.items()):
                if self._threshold_has_rule(candidate):
                    pending.pop(identity)
            if not pending:
                self.auto_prompt_keys.discard(key)
                getattr(self, 'auto_pending_requests', {}).pop(key, None)
                return
            row = next(iter(pending.values()))
        args = (row.get('name', 'Process'), row['exe'], row.get('pid', 0), row['dst_ip'],
                row.get('domain', ''), row.get('direction'), row.get('key', ''),
                row.get('_prompt_reason', 'connection'), row.get('_prompt_detail', ''), row)
        if hasattr(self, 'native_jobs') and threading.current_thread() is not self.native_worker:
            self._queue_native_job('Auto-Block hold', lambda: self._install_pending_auto_hold(*args),
                                   key=('hold', key, generation))
        else:
            self._install_pending_auto_hold(*args)

    def _install_pending_auto_hold(self, *args):
        with self.firewall_lock:
            self._start_auto_block_locked(*args)

    def _reconcile_auto_requests(self, owners, generation):
        """A saved manual policy retires only requests it actually covers."""
        ok = True
        for key in owners:
            self._refresh_pending_coverage(key)
            with self.lock:
                if generation != self.auto_prompt_generation or self.auto_hold_owners.get(key, owners[key]) != owners[key]:
                    continue
                saved = self.auto_prompt_connections.get(key)
                pending = getattr(self, 'auto_pending_requests', {}).get(key, {})
                active = saved[1] if saved and saved[0] == generation else None
                uncovered = any(not self._threshold_has_rule(row) for row in pending.values())
                uncovered = uncovered or active is not None and not self._threshold_has_rule(active)
            if not uncovered:
                with self.lock:
                    has_hold = key in self.auto_hold_owners or key in self.auto_hold_cleanup
                if has_hold and not self._release_auto_hold_locked(key, owners[key], resolve_prompt=True):
                    ok = False
                    continue
                self._cancel_app_prompt(key, owners[key])
            elif active is not None and self._threshold_has_rule(active):
                self._finish_auto_request(key, generation, active.get('_request_id'))
        return ok

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
                row = connection or self._threshold_connection(exe, remote_ip, domain, direction, '')
                row['_coverage'] = self._connection_coverage(row)
                with self.lock:
                    if not self.log_alerts_only or not self.auto_block_enabled or self.is_paused or self.closed:
                        return False
                    if norm in self.allowed_apps:
                        return False
                    if prompt_generation is not None and prompt_generation != self.auto_prompt_generation:
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

    def _dismiss_auto_dialog(self, identity):
        if threading.get_ident() != getattr(self, 'ui_thread_id', threading.main_thread().ident):
            self.ui_queue.put(('close_auto_dialog', identity))
            return
        self._close_auto_dialog(identity)

    def _close_auto_dialog(self, identity):
        current = getattr(self, 'auto_prompt_identity', None)
        if current is None:
            return
        if identity[0] == 'before':
            if current[0] >= identity[1]:
                return
        elif identity != current:
            return
        dialog = self.auto_prompt_dialog
        self.auto_prompt_details = self.auto_prompt_dialog = self.auto_prompt_key = None
        self.auto_prompt_identity = None
        self.auto_prompt_active = False
        try:
            if dialog is not None:
                dialog.destroy()
        except tk.TclError:
            pass

    def _cancel_app_prompt(self, norm, generation=None):
        with self.lock:
            if generation is not None and (generation != self.auto_prompt_generation
                    or getattr(self, 'auto_hold_owners', {}).get(norm, generation) != generation):
                return
            identity = (self.auto_prompt_generation, norm, self._auto_request_id_locked(norm))
            self.auto_prompt_keys.discard(norm)
            getattr(self, 'auto_prompt_connections', {}).pop(norm, None)
            getattr(self, 'auto_pending_requests', {}).pop(norm, None)
            history = getattr(self, 'auto_detection_requests', {})
            for identity in [identity for identity in history if identity[0] == norm]:
                history.pop(identity, None)
            getattr(self, 'auto_decision_saves', {}).pop(norm, None)
            getattr(self, 'auto_decision_errors', {}).pop(norm, None)
            owner = getattr(self, 'auto_hold_owners', {}).pop(norm, None)
            if owner is not None:
                # Cancellation retires protection; failed cleanup remains a worker obligation.
                self.auto_hold_cleanup[norm] = owner
            getattr(self, 'auto_hold_ready', {}).pop(norm, None)
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
        self._dismiss_auto_dialog(identity)

    def _invalidate_auto_prompts(self, close_dialog=False):
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
            getattr(self, 'auto_pending_requests', {}).clear()
            getattr(self, 'auto_detection_requests', {}).clear()
            getattr(self, 'auto_decision_saves', {}).clear()
            getattr(self, 'auto_decision_errors', {}).clear()
            generation = self.auto_prompt_generation
            while True:
                try:
                    self.prompt_queue.get_nowait()
                except queue.Empty:
                    break
        if close_dialog:
            self._dismiss_auto_dialog(('before', generation))

    def start_auto_block(self, proc_name, exe, pid, remote_ip, domain, direction, key, reason, detail, connection=None):
        row = self._threshold_connection(exe, remote_ip, domain, direction, key, connection)
        row['_coverage'] = self._connection_coverage(row)
        self._refresh_pending_coverage(normalize_path(exe))
        with self.lock:
            row.setdefault('_detection_token', self._detection_token_locked())
            row.setdefault('name', proc_name)
            row.setdefault('pid', pid)
            if not self._threshold_current(row):
                return
            prompt_key = normalize_path(exe)
            generation = self.auto_prompt_generation
            dropped = getattr(self, 'dropped_auto_requests', 0)
            if prompt_key not in self.auto_prompt_keys:
                now = time.monotonic()
                for (path, _), (seen, snapshot) in getattr(self, 'auto_detection_requests', {}).items():
                    if path == prompt_key and now - seen <= getattr(self, 'rate_window', 5.0):
                        self._admit_auto_request_locked(snapshot, reason, detail)
            self._admit_auto_request_locked(row, reason, detail)
            overflow = getattr(self, 'dropped_auto_requests', 0) > dropped
        if overflow:
            self.queue_alert('High', proc_name, pid, remote_ip, 'Auto-Block request capacity reached. Resolve pending requests; additional requests were not admitted.')
        self._schedule_auto_hold(prompt_key, generation)

    def _start_auto_block_locked(self, proc_name, exe, pid, remote_ip, domain, direction, key, reason, detail, connection=None):
        prompt_key = normalize_path(exe) or key
        row = self._threshold_connection(exe, remote_ip, domain, direction, key, connection)
        row['_coverage'] = self._connection_coverage(row)
        with self.lock:
            if not self._threshold_current(row):
                return
            if self._threshold_has_rule(row) or getattr(self, 'settings_load_error', None):
                return
            if not self.log_alerts_only or not self.auto_block_enabled or self.is_paused or self.closed:
                return
            if getattr(self, 'auto_hold_ready', {}).get(prompt_key) == self.auto_prompt_generation:
                self._publish_auto_request_locked(prompt_key, self.auto_prompt_generation)
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
                if not hasattr(self, 'auto_hold_ready'):
                    self.auto_hold_ready = {}
                self.auto_hold_ready[prompt_key] = generation
                if self.auto_hold_cleanup.get(prompt_key) == generation:
                    self.auto_hold_cleanup.pop(prompt_key, None)
                if not hasattr(self, 'auto_prompt_connections'):
                    self.auto_prompt_connections = {}
                self._publish_auto_request_locked(prompt_key, generation)
        if stale:
            self._release_auto_hold_locked(prompt_key, generation)
            with self.lock:
                self.auto_prompt_keys.discard(prompt_key)
            return

    def _release_auto_hold_locked(self, path, generation, resolve_prompt=False):
        """Retire only this owner; a newer hold may already occupy the path."""
        with self.lock:
            pending = getattr(self, 'auto_decision_saves', {}).get(path)
            if (not resolve_prompt and pending and pending['kind'] == 'port'
                    and pending['generation'] == generation == self.auto_prompt_generation
                    and self._auto_request_id_locked(path) == pending.get('request_id')):
                # A failed active connection decision retains its hold until
                # verification/save/cleanup is retried through that prompt.
                return False
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
            self.queue_alert('High', path, '', '', f'Could not release temporary block: {exc}')
            return False
        with self.lock:
            if getattr(self, 'auto_hold_owners', {}).get(path) == generation:
                self.auto_hold_owners.pop(path, None)
            if getattr(self, 'auto_hold_ready', {}).get(path) == generation:
                self.auto_hold_ready.pop(path, None)
            if getattr(self, 'auto_hold_cleanup', {}).get(path) == generation:
                self.auto_hold_cleanup.pop(path, None)
        return True

    def release_auto_holds(self):
        with self.firewall_lock:
            self.remove_auto_holds_locked()
            self._invalidate_auto_prompts(close_dialog=True)
            with self.lock:
                getattr(self, 'auto_hold_owners', {}).clear()
                getattr(self, 'auto_hold_ready', {}).clear()
                getattr(self, 'auto_hold_cleanup', {}).clear()

    # UI dispatch and background decisions

    def drain_prompt_queue(self):
        self._refresh_pending_coverage()
        with self.lock:
            waiting = [(key, self.auto_prompt_generation) for key in self.auto_prompt_keys
                       if key not in self.auto_prompt_connections]
        for key, generation in waiting:
            self._schedule_auto_hold(key, generation)
            with self.lock:
                self._publish_auto_request_locked(key, generation)
        with self.lock:
            if self.auto_prompt_active:
                return
        try:
            item = self.prompt_queue.get_nowait()
        except queue.Empty:
            return
        generation, key, proc_name, exe, pid, remote_ip, domain, direction, reason, detail = item[:10]
        request_id = item[10] if len(item) > 10 else None
        # Never wait for native work on Tk. Obsolete holds remain represented by
        # their owner until the worker can retire them.
        if not self.firewall_lock.acquire(blocking=False):
            self.prompt_queue.put(item)
            return
        try:
            with self.lock:
                current_generation = generation == self.auto_prompt_generation and key in self.auto_prompt_keys
                saved = getattr(self, 'auto_prompt_connections', {}).get(key)
                if request_id is not None and (not saved or saved[1].get('_request_id') != request_id):
                    return
                row = saved[1] if saved and saved[0] == generation else self._threshold_connection(exe, remote_ip, domain, direction, key)
            if not current_generation or not self._auto_block_active() or self._threshold_has_rule(row):
                with self.lock:
                    remaining = self._remaining_auto_requests_locked(key, row.get('_request_id')) if current_generation else []
                    if not remaining:
                        self.auto_hold_cleanup.setdefault(normalize_path(exe), generation)
                if not remaining and not hasattr(self, 'native_jobs'):
                    self._release_auto_hold_locked(normalize_path(exe), generation)
                if current_generation:
                    self._finish_auto_request(key, generation, row.get('_request_id'))
                return
            with self.lock:
                self.auto_prompt_active = True
                self.auto_prompt_key = key
                self.auto_prompt_identity = (generation, key, row.get('_request_id'))
        finally:
            self.firewall_lock.release()
        self.show_auto_prompt(generation, key, proc_name, exe, pid, remote_ip, reason, detail)

    def _auto_block_active(self):
        with self.lock:
            return (self.log_alerts_only and self.auto_block_enabled and not self.is_paused
                    and not self.closed and not getattr(self, 'settings_load_error', None))

    def _auto_decision_worker(self, generation, key, exe, proc_name, choice, result_queue, request_id=None):
        """Apply a decision without calling Tk; the prompt owns result delivery."""
        ok = None
        norm = normalize_path(exe)
        self._refresh_pending_coverage(key)
        with self.lock:
            if request_id is None:
                request_id = self._auto_request_id_locked(key)
            def same_request():
                return (generation == self.auto_prompt_generation and self.auto_prompt_key == key
                        and self._auto_request_id_locked(key) == request_id)
            if same_request():
                getattr(self, 'auto_decision_errors', {}).pop(key, None)
        def own_commit():
            pending = getattr(self, 'auto_decision_saves', {}).get(key)
            if pending is None or pending['generation'] != generation or pending.get('request_id') != request_id:
                return False
            if pending['kind'] == 'app':
                return pending['version'] == getattr(self, 'app_policy_versions', {}).get(norm)
            policy_key = pending['policy_key']
            policy = getattr(self, 'global_ports', {}).get(policy_key)
            return policy is pending['policy'] and policy == pending['snapshot']
        def committed(version):
            if not hasattr(self, 'auto_decision_saves'):
                self.auto_decision_saves = {}
            self.auto_decision_saves[key] = {'generation': generation, 'request_id': request_id, 'choice': choice,
                                           'kind': 'app', 'version': version, 'saved': False}
        def committed_port(policy_key, policy):
            if not hasattr(self, 'auto_decision_saves'):
                self.auto_decision_saves = {}
            # The actual committed object plus detached contents distinguish a
            # replacement (even an identical one) and an in-place policy edit.
            self.auto_decision_saves[key] = {'generation': generation, 'request_id': request_id, 'choice': choice,
                                           'kind': 'port', 'policy_key': policy_key,
                                           'policy': policy, 'snapshot': copy.deepcopy(policy), 'saved': False}
        def other_policy(row):
            pending = self.auto_decision_saves[key]
            if pending['kind'] != 'port':
                return False
            status = self.get_rule_status(row.get('exe'))
            direction = direction_name(row.get('direction'))
            app_applies = (status in {'allowed', 'blocked_both'}
                           or status == 'blocked_in' and direction == 'Inbound'
                           or status == 'blocked_out' and direction == 'Outbound')
            coverage = row.get('_coverage')
            return (bool(coverage and coverage[0] == self._policy_revision_locked()
                         and any(rule_key != pending['policy_key'] for rule_key in coverage[2])) or app_applies)
        def current_decision():
            with self.lock:
                saved = getattr(self, 'auto_prompt_connections', {}).get(key)
                pending = getattr(self, 'auto_decision_saves', {}).get(key)
                owned = own_commit()
                return (same_request()
                        and self._auto_block_active()
                        and (owned and not (saved and saved[0] == generation and other_policy(saved[1]))
                             or pending is None and not (saved and saved[0] == generation and self._threshold_has_rule(saved[1]))))
        current_decision.committed = committed
        current_decision.committed_port = committed_port
        def verify_owned_connection():
            pending = self.auto_decision_saves[key]
            if pending['kind'] != 'port':
                return
            # Ownership survives a refresh failure or native drift. It does not
            # authorize releasing the hold until the owned filters verify again.
            expected = self._port_firewall_rules({pending['policy_key']: pending['snapshot']})
            try:
                state = self._enforcement_for(expected, self.get_firewall_rules())
            except Exception as exc:
                raise RuntimeError(f'Could not verify the connection decision. Temporary protection remains; retry the same choice. {exc}') from exc
            with self.lock:
                if not own_commit():
                    raise RuntimeError('The connection decision changed during verification. Retry to resolve the prompt safely.')
                if hasattr(self, 'rule_enforcement'):
                    self.rule_enforcement['port', pending['policy_key']] = state
            if state != 'Verified':
                raise RuntimeError('The connection decision is not verified in Windows Firewall. Temporary protection remains. Restore the rule in Managed Rules or retry the same choice after verification succeeds.')
        def finish_commit():
            pending = self.auto_decision_saves[key]
            verify_owned_connection()
            if not pending['saved']:
                self._persist_rule_changes()
                pending['saved'] = True
            self._refresh_pending_coverage(key)
            with self.lock:
                if self.closed or not same_request():
                    return None
                if not current_decision():
                    raise RuntimeError('The connection decision or protection state changed while saving. Retry the same choice to resolve the prompt safely.')
            if pending['kind'] == 'port':
                verify_owned_connection()
            with self.lock:
                remaining = self._remaining_auto_requests_locked(key)
                owned_hold = norm in getattr(self, 'auto_hold_owners', {}) or norm in getattr(self, 'auto_hold_cleanup', {})
                if remaining and self.auto_hold_cleanup.get(norm) == generation and self.auto_hold_owners.get(norm) == generation:
                    self.auto_hold_cleanup.pop(norm, None)
            return True if remaining or not owned_hold else self._release_auto_hold_locked(norm, generation, resolve_prompt=True)
        try:
            with self.firewall_lock:
                with self.lock:
                    current = not self.closed and same_request() and self._auto_block_active()
                    saved = copy.deepcopy(getattr(self, 'auto_prompt_connections', {}).get(key))
                    pending = getattr(self, 'auto_decision_saves', {}).get(key)
                    owned = own_commit()
                    superseded = bool(pending and not owned)
                    if owned and saved and saved[0] == generation:
                        superseded = other_policy(saved[1])
                if current and (superseded or not owned and saved and saved[0] == generation and self._threshold_has_rule(saved[1])):
                    with self.lock:
                        remaining = self._remaining_auto_requests_locked(key, request_id)
                    if remaining or self._release_auto_hold_locked(normalize_path(exe), generation, resolve_prompt=True):
                        self._finish_auto_request(key, generation, request_id)
                    else:
                        ok = False
                    current = False
                if current:
                    if owned:
                        if pending['choice'] != choice:
                            raise ValueError('A decision is already applied. Retry the same choice to finish saving it and releasing temporary protection.')
                        ok = finish_commit()
                    elif choice in {'allow_connection', 'block_connection'}:
                        if not saved or saved[0] != generation:
                            raise ValueError('The triggering connection is unavailable. Use an application decision or retry after a complete connection is captured.')
                        self._apply_auto_connection_rule(saved[1], exe, choice == 'allow_connection', current_decision)
                        ok = finish_commit()
                    elif choice == 'allow':
                        ok = self.allow_executable(exe, refresh=False, quiet=True, update_ui=False, decision_guard=current_decision)
                    elif choice in {'in', 'both'}:
                        ok = self.block_executable(exe, proc_name, 'in' if choice == 'in' else 'both',
                                                   refresh=False, quiet=True, update_ui=False, decision_guard=current_decision)
                    else:
                        raise ValueError('Unknown Auto-Block decision.')
                    if ok and choice in {'allow', 'in', 'both'} and own_commit():
                        self.auto_decision_saves[key]['saved'] = True
                        ok = finish_commit()
        except Exception as exc:
            ok = False
            with self.lock:
                if same_request():
                    if not hasattr(self, 'auto_decision_errors'):
                        self.auto_decision_errors = {}
                    self.auto_decision_errors[key] = str(exc)
            log_internal_error('auto_decision', exc)
            self.queue_alert('High', exe, '', '', f'Firewall decision failed: {exc}')
        finally:
            result_queue.put(ok)

    # Decision dialog

    def _auto_prompt_endpoint_identity(self, row):
        return (self._host_endpoint(row), row.get('direction'), row.get('key'), self._flow_identity(row))

    def _auto_prompt_details_current_locked(self, state):
        if (state is not getattr(self, 'auto_prompt_details', None) or state['answered'] or self.closed
                or state['generation'] != self.auto_prompt_generation
                or self.auto_prompt_key != state['key'] or self.auto_prompt_dialog is not state['dialog']):
            return False
        saved = getattr(self, 'auto_prompt_connections', {}).get(state['key'])
        if state['source'] is None:
            return saved is None
        return (saved is not None and saved[0] == state['generation'] and saved[1] is state['source']
                and self._auto_prompt_endpoint_identity(saved[1]) == state['identity'])

    def _refresh_auto_prompt_host(self, ips=None, discover=False):
        """Enrich only the active, never-selected dialog; enforcement owns its own snapshot."""
        with self.lock:
            state = getattr(self, 'auto_prompt_details', None)
            if state is None or not self._auto_prompt_details_current_locked(state):
                return
            row = copy.deepcopy(state['row'])
            if ips is not None and row.get('dst_ip') not in ips:
                return
        # Never take dns_lock under the application lock or resolve on Tk.
        host = self._retain_remote_host(row, discover=discover and hasattr(self, 'dns_queue'))
        with self.lock:
            if not self._auto_prompt_details_current_locked(state) or not host or host == state['host']:
                return
        try:
            widget = state['host_widget']
            widget.configure(state=tk.NORMAL)
            widget.delete('1.0', tk.END)
            widget.insert('1.0', host)
            widget.configure(state=tk.DISABLED)
            state['row'] = row
            state['host'] = host
        except tk.TclError:
            self.auto_prompt_details = None

    def show_auto_prompt(self, generation, key, proc_name, exe, pid, remote_ip, reason, detail):
        dialog = tk.Toplevel(self.root)
        self._diagnostic_event('Auto-Block prompt opened', dialog)
        with self.lock:
            self.auto_prompt_dialog = dialog
            self.auto_prompt_key = key
            saved = getattr(self, 'auto_prompt_connections', {}).get(key)
            source = saved[1] if saved and saved[0] == generation else None
            endpoint = copy.deepcopy(source) if source is not None else {'exe': exe, 'pid': pid, 'dst_ip': remote_ip}
            request_id = endpoint.get('_request_id')
        dialog.title('Auto-Block Protection')
        dialog.resizable(False, False)
        dialog.withdraw()
        self._theme_dialog(dialog)
        message = f"{proc_name} reached an Auto-Block threshold.\nTrigger: {reason.title()}{(f' ({detail})' if detail else '')}\n\nTemporary protection is already blocking this executable while you decide."
        body, host_widget = self._connection_rule_body(dialog, message, endpoint)
        state = {'generation': generation, 'key': key, 'dialog': dialog, 'source': source,
                 'identity': self._auto_prompt_endpoint_identity(endpoint), 'row': endpoint,
                 'host_widget': host_widget, 'host': '', 'answered': False}
        with self.lock:
            self.auto_prompt_details = state
        self.auto_prompt_identity = (generation, key, request_id)
        topmost_after = None
        poll_after = None
        def destroyed(event):
            if event.widget is dialog:
                self._diagnostic_event('Auto-Block prompt destroyed', dialog)
                for callback in (topmost_after, poll_after):
                    if callback is not None:
                        try:
                            dialog.after_cancel(callback)
                        except tk.TclError:
                            pass
                with self.lock:
                    if getattr(self, 'auto_prompt_details', None) is state:
                        self.auto_prompt_details = None
        dialog.bind('<Destroy>', destroyed, add='+')
        self._refresh_auto_prompt_host(discover=True)
        finished = False
        decision_buttons = []
        result_queue = queue.Queue(maxsize=1)
        applying = tk.Label(body, text='', anchor=tk.W, justify=tk.LEFT, wraplength=470,
                            bg=self.colors['frame'], fg=self.colors['fg'])
        applying.pack(fill=tk.X)

        def poll_decision():
            nonlocal finished, poll_after
            poll_after = None
            if self.closed or not dialog.winfo_exists():
                return
            try:
                ok = result_queue.get_nowait()
            except queue.Empty:
                poll_after = dialog.after(50, poll_decision)
                return
            with self.lock:
                current = (generation == self.auto_prompt_generation
                           and self.auto_prompt_dialog is dialog and self.auto_prompt_key == key
                           and self._auto_request_id_locked(key) == request_id)
            if ok:
                if current:
                    self._finish_auto_request(key, generation, request_id)
            elif current and ok is False:
                finished = False
                for button in decision_buttons:
                    button.configure(state=tk.NORMAL)
                pending_save = getattr(self, 'auto_decision_saves', {}).get(key)
                error = getattr(self, 'auto_decision_errors', {}).get(key)
                text = (error if error else
                        'Decision saved, but temporary protection could not be released. Retry the same choice to finish.'
                        if pending_save and pending_save['saved'] else
                        'Decision applied but not saved. Retry the same choice to save it.' if pending_save else
                        'Could not apply decision. Please retry.')
                applying.configure(text=text)
                messagebox.showerror('Firewall Update Failed',
                                     text + '\nReview Alerts for details.', parent=dialog)
            self.rules_changed()

        def finish(choice):
            nonlocal finished, poll_after
            if finished:
                return
            with self.lock:
                current = (generation == self.auto_prompt_generation and not self.closed
                           and self.auto_prompt_dialog is dialog and self.auto_prompt_key == key
                           and self._auto_request_id_locked(key) == request_id)
                if current:
                    state['answered'] = True  # Stay frozen even when a failed choice becomes retryable.
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
                            generation, key, exe, proc_name, choice, result_queue, request_id=request_id)):
                        result_queue.put(False)
                else:
                    threading.Thread(target=self._auto_decision_worker,
                                     args=(generation, key, exe, proc_name, choice, result_queue),
                                     kwargs={'request_id': request_id},
                                     daemon=True, name='PyFirewall-Decision').start()
            except Exception as exc:
                self.queue_alert('High', exe, pid, remote_ip, f'Could not start firewall decision: {exc}')
                result_queue.put(False)
            poll_after = dialog.after(50, poll_decision)
        decision_buttons = self._connection_rule_actions(
            dialog, finish, lambda: finish('both'), cancel_label='Cancel (Block)',
            cancel_tip='Dismiss the prompt and keep the executable blocked.',
            allow_tip='Remove the temporary block and allow the executable. Matching global blocks still take precedence.')
        dialog.protocol('WM_DELETE_WINDOW', lambda: finish('both'))
        dialog.update_idletasks()
        self._center_dialog(dialog)
        dialog.deiconify()
        dialog.lift()
        dialog.focus_force()
        dialog.attributes('-topmost', True)

        def release_topmost():
            nonlocal topmost_after
            topmost_after = None
            try:
                if dialog.winfo_exists():
                    dialog.attributes('-topmost', getattr(self, 'keep_notification_foreground', True))
                    sync_tooltip_stacking(dialog)
            except tk.TclError:
                pass
        topmost_after = dialog.after(250, release_topmost)
