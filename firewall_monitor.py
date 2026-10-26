"""PyFirewall entry point. Importing this module never launches the application."""

import ctypes
import hashlib
import os
import socket
import subprocess
import sys
import time

from constants import __version__

_MUTEX_HANDLE = None


def instance_key():
    return hashlib.sha1(os.path.normcase(os.path.abspath(__file__)).encode()).hexdigest()


def instance_activation_port():
    """Give each installed copy a stable loopback port for window activation."""
    return 35000 + (int(instance_key()[:8], 16) % 20000)


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
    name = 'Local\\PyFirewall_' + instance_key()
    _MUTEX_HANDLE = ctypes.windll.kernel32.CreateMutexW(None, False, name)
    if not _MUTEX_HANDLE:
        return True
    if ctypes.windll.kernel32.GetLastError() == 183:
        activate_existing_instance()
        return False
    return True


def activate_existing_instance():
    """Ask the running copy to restore and foreground its main window."""
    deadline = time.monotonic() + 2.0
    while True:
        try:
            with socket.create_connection(('127.0.0.1', instance_activation_port()), timeout=0.25) as connection:
                connection.sendall(b'SHOW')
                return True
        except OSError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.1)


def main():
    """Elevate and start one GUI instance when explicitly launched."""
    if os.name != 'nt':
        raise SystemExit('This application requires Windows.')
    hide_console()
    elevate()
    if not acquire_single_instance():
        return

    # Delay application/dependency imports until after the startup guards.
    try:
        from app import FirewallMonitorApp
    except ImportError as exc:
        raise SystemExit(f'Missing dependency or application module: {exc}. '
                         'Keep all PyFirewall files together and install psutil, scapy, and Npcap first.') from exc
    import tkinter as tk
    from constants import ICON_FILE

    root = tk.Tk()
    if os.path.exists(ICON_FILE):
        try:
            root.iconbitmap(default=ICON_FILE)
        except tk.TclError:
            pass
    application = FirewallMonitorApp(root, activation_port=instance_activation_port())
    root.mainloop()


if __name__ == '__main__':
    main()
