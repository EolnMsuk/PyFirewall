"""PyFirewall entry point. Importing this module never launches the application."""

import ctypes
import hashlib
import os
import socket
import subprocess
import sys
import time
import threading
from ctypes import wintypes

from constants import __version__, NATIVE_OWNER_MUTEX

_MUTEX_HANDLE = None


def instance_key():
    return hashlib.sha1(NATIVE_OWNER_MUTEX.encode()).hexdigest()


def instance_activation_port():
    """All copies in one session activate its owner; other sessions report it."""
    session = wintypes.DWORD()
    get_session = ctypes.windll.kernel32.ProcessIdToSessionId
    get_session.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    get_session.restype = wintypes.BOOL
    if not get_session(os.getpid(), ctypes.byref(session)):
        raise OSError('Could not determine the Windows session for activation.')
    return 35000 + session.value % 20000


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
    name = NATIVE_OWNER_MUTEX
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    get_last_error = kernel32.GetLastError
    get_last_error.argtypes = []
    get_last_error.restype = wintypes.DWORD
    handle = kernel32.CreateMutexW(None, True, name)
    error = get_last_error()
    if not handle:
        from helpers import log_internal_error
        failure = OSError(error, 'Could not acquire the PyFirewall single-instance mutex')
        log_internal_error('single_instance', failure)
        raise SystemExit(str(failure))
    if error == 183:
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        result = kernel32.WaitForSingleObject(handle, 0)
        if result not in (0, 0x80):
            kernel32.CloseHandle(handle)
            if result != 0x102:
                raise SystemExit('Could not acquire the machine-wide PyFirewall policy owner.')
            if not activate_existing_instance():
                ctypes.windll.user32.MessageBoxW(None,
                    'PyFirewall or its installer already owns Windows Firewall on this machine. '
                    'It may be running in another Windows session. Exit that copy or finish setup before launching another.',
                    'PyFirewall Already Running', 0x40)
            return False
    _MUTEX_HANDLE = handle
    return True


def release_single_instance():
    global _MUTEX_HANDLE
    if _MUTEX_HANDLE is not None:
        kernel32 = ctypes.windll.kernel32
        kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
        kernel32.ReleaseMutex.restype = wintypes.BOOL
        kernel32.ReleaseMutex(_MUTEX_HANDLE)
        kernel32.CloseHandle(_MUTEX_HANDLE)
        _MUTEX_HANDLE = None


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
    application = None
    try:
        application = FirewallMonitorApp(root, activation_port=instance_activation_port())
        root.mainloop()
    finally:
        worker = getattr(application, 'native_worker', None)
        if isinstance(worker, threading.Thread) and worker.is_alive():
            if not application.closed:
                application.on_closing()
            # Even an exceptional mainloop exit cannot release native ownership
            # while a transaction or profile restoration is still running.
            worker.join()
        release_single_instance()


if __name__ == '__main__':
    main()
