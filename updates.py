"""Optional release checks and their UI notifications."""

import json
import os
import re
import threading
import tkinter as tk
import urllib.request
from tkinter import messagebox, ttk

from constants import LATEST_RELEASE_API, LATEST_RELEASE_PAGE, __version__

def check_latest_release():
    """Return (release version, is newer), or None if the check is unavailable.

    Only stable numeric release tags are compared; never use response URLs or
    assets to launch programs, download files, or replace this installation.
    """
    try:
        request = urllib.request.Request(LATEST_RELEASE_API, headers={
            'Accept': 'application/vnd.github+json',
            'User-Agent': f'PyFirewall/{__version__}',
        })
        with urllib.request.urlopen(request, timeout=10) as response:
            release = json.load(response)
        version = release['tag_name'].lstrip('v')
        if release.get('draft') or release.get('prerelease'):
            return None
        if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', version):
            return None
        latest = tuple(int(part) for part in version.split('.'))
        current = tuple(int(part) for part in __version__.split('.'))
        length = max(len(latest), len(current))
        newer = latest + (0,) * (length - len(latest)) > current + (0,) * (length - len(current))
        return version, newer
    except Exception:
        # Offline, timeout, rate limiting, and malformed responses are harmless.
        return None


class UpdatesMixin:
    """Methods composed into FirewallMonitorApp; state is owned by that application."""

    def on_update_setting_changed(self):
        with self.lock:
            self.check_updates_on_startup = bool(self.check_updates_on_startup_var.get())
        if not self.save_settings():
            messagebox.showerror('Settings Not Saved', 'Could not save the startup update preference. Please try again.', parent=self.root)

    def check_for_updates(self, manual=True):
        """Start one network worker; all Tk work stays on the UI thread."""
        if self.closed:
            return
        if self.update_dialog is not None:
            self.update_dialog.lift()
            return
        if self.update_check_running:
            self.update_check_manual = self.update_check_manual or manual
            return
        self.update_check_running = True
        self.update_check_manual = manual
        try:
            threading.Thread(target=self._update_check_worker, daemon=True,
                             name='PyFirewall-UpdateCheck').start()
        except Exception:
            self._finish_update_check(None)

    def _update_check_worker(self):
        result = check_latest_release()
        self.ui_queue.put(('update_check', result))

    def _finish_update_check(self, result):
        manual = self.update_check_manual
        self.update_check_running = False
        self.update_check_manual = False
        if self.closed:
            return
        if result is None:
            if manual:
                messagebox.showinfo('Check for Updates',
                                    'Could not check for updates. You may be offline or GitHub may be temporarily unavailable or rate limiting requests. Please try again later.',
                                    parent=self.root)
        elif result[1]:
            self._show_update_prompt(result[0])
        elif manual:
            messagebox.showinfo('Check for Updates',
                                f'You are already on the latest version of PyFirewall ({__version__}); no newer release is available.',
                                parent=self.root)

    def _show_update_prompt(self, version):
        # Do not wait_window here: monitoring and the UI queue must keep running.
        if self.tray_hidden:
            self.show_from_tray()
        dialog = self.update_dialog = tk.Toplevel(self.root)
        dialog.withdraw()
        dialog.title('PyFirewall Update Available')
        dialog.transient(self.root)
        dialog.resizable(False, False)
        self._theme_dialog(dialog)
        ttk.Label(dialog, text=f'PyFirewall {version} is available. You are using {__version__}.\n\n'
                  'To update, open the release page to download the updated PyFirewall.zip, extract the folder PyFirewall to desktop, open it and copy its contents. '
                  'Then paste / replace all the files inside of your old PyFirewall folder. Close PyFirewall from the system tray and relaunch from the desktop shortcut.', wraplength=440, padding=16).pack(fill=tk.X)

        def cancel():
            self.update_dialog = None
            dialog.destroy()

        def open_release_page():
            cancel()
            try:
                os.startfile(LATEST_RELEASE_PAGE)
            except OSError:
                messagebox.showerror('Could Not Open Release Page',
                                     f'Please open this address in your browser:\n{LATEST_RELEASE_PAGE}', parent=self.root)

        ttk.Button(dialog, text='Open Release Page', command=open_release_page).pack(fill=tk.X, padx=16, pady=4)
        cancel_button = ttk.Button(dialog, text='Cancel', command=cancel)
        cancel_button.pack(fill=tk.X, padx=16, pady=(4, 16))
        dialog.protocol('WM_DELETE_WINDOW', cancel)
        dialog.bind('<Escape>', lambda _event: cancel())
        self._center_dialog(dialog)
        dialog.deiconify()
        cancel_button.focus_set()
