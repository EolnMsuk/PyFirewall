"""Best-effort local diagnostics. Importing this module installs no hooks/threads."""

import faulthandler
import json
import sys
import threading
import time
import traceback

import helpers
from constants import FAULT_LOG_FILE, UI_DIAGNOSTIC_LOG_FILE


class RuntimeDiagnostics:
    """Tk caches state; an independent observer reads only detached plain values."""

    def __init__(self, *, interval=1.0, stale_after=10.0):
        self.interval = interval
        self.stale_after = stale_after
        self.root = self.application = None
        self.tk_hook = None
        self.state = {'lifecycle': 'startup', 'phase': 'startup'}
        self.breadcrumbs = ()
        self.last_beat = time.monotonic()
        self.last_observed = self.last_beat
        self.resume_until = 0.0
        self.active = self.stalled = False
        self.stop_event = threading.Event()
        self.write_lock = threading.Lock()
        self.observer = self.after_id = None
        self.fault_file = None
        self.installed = False

    def install(self):
        if self.installed:
            return
        self.installed = True
        self.old_thread_hook = threading.excepthook
        self.old_state_provider = helpers.ERROR_STATE_PROVIDER
        self.state_provider = self.state_text
        helpers.ERROR_STATE_PROVIDER = self.state_provider

        def thread_error(args):
            if args.exc_type is not SystemExit:
                self.report_exception('thread:' + args.thread.name, args.exc_value, args.exc_traceback)
            # Retain the interpreter/host's normal uncaught-exception behavior.
            self.old_thread_hook(args)

        self.thread_hook = thread_error
        threading.excepthook = self.thread_hook

    def enable_faults(self):
        if self.fault_file is not None or faulthandler.is_enabled():
            return
        try:
            # Rotate only before enabling: its descriptor must stay open and stable.
            helpers.rotate_diagnostic_log(FAULT_LOG_FILE)
            self.fault_file = open(FAULT_LOG_FILE, 'a', encoding='utf-8')
            faulthandler.enable(file=self.fault_file, all_threads=True)
        except Exception:
            if self.fault_file is not None:
                self.fault_file.close()
                self.fault_file = None

    def attach(self, root):
        self.root = root
        self.old_tk_hook = root.report_callback_exception

        def callback_error(_kind, exc, tb):
            self.report_exception('tk_callback', exc, tb)
            self.old_tk_hook(_kind, exc, tb)

        self.tk_hook = callback_error
        root.report_callback_exception = self.tk_hook

    def report_exception(self, context, exc, tb):
        try:
            if not helpers.log_internal_error(context, exc, traceback_obj=tb):
                self._write(context, ''.join(traceback.format_exception(type(exc), exc, tb, limit=40)))
        except Exception:
            pass

    def state_text(self):
        return json.dumps({'ui': self.state, 'breadcrumbs': self.breadcrumbs}, ensure_ascii=True)

    def transaction(self, operation_id, stage):
        """Worker-published ordinary data; the observer never touches the app."""
        self.state = dict(self.state, transaction={'id': operation_id, 'stage': str(stage)[:40]})

    def phase(self, name):
        self.state = dict(self.state, phase=str(name)[:100])

    def event(self, name, widget=None):
        # Widget identities only, never entry text, packet payloads or keystrokes.
        entry = (round(time.monotonic(), 3), str(name)[:100], str(widget or '')[:160])
        self.breadcrumbs = (*self.breadcrumbs[-31:], entry)

    def _sample_ui(self):
        try:
            app, root = self.application, self.root
            notebook = getattr(app, 'notebook', None)
            tab = notebook.tab(notebook.select(), 'text') if notebook is not None else ''
            dialogs = [str(child)[:160] for child in root.winfo_children()
                       if child.winfo_class() == 'Toplevel'][:12]
            self.state = dict(self.state, tab=str(tab)[:80], focus=str(root.focus_get()),
                              grab=str(root.grab_current()), dialogs=dialogs,
                              native_operation=getattr(app, 'native_operation_label', None))
        except Exception:
            pass

    def start_ui(self, application):
        self.application = application
        self.focus_bindings = []
        for pattern in ('<FocusIn>', '<FocusOut>'):
            token = self.root.bind(pattern, lambda e, p=pattern: self.event(p, e.widget), add='+')
            self.focus_bindings.append((pattern, token))
        self._heartbeat()
        self.observer = threading.Thread(target=self._observe, daemon=True, name='PyFirewall-Diagnostics')
        self.observer.start()

    def activate(self):
        self.last_beat = time.monotonic()
        self.active = True
        self.state = dict(self.state, lifecycle='running')

    def _heartbeat(self):
        self.after_id = None
        if self.stop_event.is_set():
            return
        self.last_beat = time.monotonic()
        self._sample_ui()
        self.after_id = self.root.after(round(self.interval * 1000), self._heartbeat)

    def _observe(self):
        while not self.stop_event.wait(self.interval):
            self.check_stall()

    def check_stall(self, now=None):
        """No Tk, application objects, queues or application locks on this path."""
        now = time.monotonic() if now is None else now
        gap = now - self.last_observed
        self.last_observed = now
        if gap > max(5.0, self.stale_after / 2):
            # Observer suspension (including system sleep) earns a fresh grace period.
            self.resume_until = now + self.stale_after
        if self.stop_event.is_set() or not self.active or now < self.resume_until:
            return
        age = now - self.last_beat
        if age >= self.stale_after and not self.stalled:
            self.stalled = True
            self._write(f'UI heartbeat stale for {age:.1f}s', stacks=True)
        elif age < self.stale_after and self.stalled:
            self.stalled = False
            self._write('UI heartbeat recovered')

    @staticmethod
    def _stacks():
        frames = sys._current_frames()
        parts = []
        try:
            # Bound frames/output even if an unrelated library creates many threads.
            for ident, frame in list(frames.items())[:100]:
                parts.append(f'\nThread {ident}:\n' + ''.join(traceback.format_stack(frame, limit=40)))
            if len(frames) > 100:
                parts.append(f'\n{len(frames) - 100} additional threads omitted.\n')
            return ''.join(parts)[:196608]
        finally:
            frames.clear()

    def _write(self, context, detail='', *, stacks=False):
        if not self.write_lock.acquire(blocking=False):
            return
        try:
            helpers.rotate_diagnostic_log(UI_DIAGNOSTIC_LOG_FILE)
            with open(UI_DIAGNOSTIC_LOG_FILE, 'a', encoding='utf-8') as output:
                output.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {context}\n")
                output.write(self.state_text()[:16384] + '\n' + detail[:65536] + '\n')
                if stacks:
                    output.write(self._stacks())
        except Exception:
            pass
        finally:
            self.write_lock.release()

    def shutdown(self):
        self._sample_ui()
        self.event('shutdown')
        self._write('Tk shutdown snapshot')
        self.active = False
        self.state = dict(self.state, lifecycle='shutdown')
        self.stop_ui()

    def stop_ui(self):
        self.stop_event.set()
        if self.after_id is not None:
            try:
                self.root.after_cancel(self.after_id)
            except Exception:
                pass
            self.after_id = None
        for pattern, token in getattr(self, 'focus_bindings', ()):
            try:
                self.root.unbind(pattern, token)
            except Exception:
                pass
        self.focus_bindings = []

    def close(self):
        self.stop_ui()
        # No observer join on Tk; it owns no persistent handles/application locks.
        if self.tk_hook is not None and self.root.report_callback_exception is self.tk_hook:
            self.root.report_callback_exception = self.old_tk_hook
        if self.installed:
            if threading.excepthook is self.thread_hook:
                threading.excepthook = self.old_thread_hook
            if helpers.ERROR_STATE_PROVIDER is self.state_provider:
                helpers.ERROR_STATE_PROVIDER = self.old_state_provider
            self.installed = False
        # The observer may finish after Tk. Its retained state must be ordinary
        # data, including final releases of the UI hook's bound root reference.
        self.root = self.application = None
        self.tk_hook = self.old_tk_hook = None
        if self.fault_file is not None:
            try:
                faulthandler.disable()
            except Exception:
                # Keep the descriptor alive if disabling fails; never close it
                # while a fault handler might still use it.
                return
            try:
                self.fault_file.close()
            except Exception:
                pass
            self.fault_file = None
