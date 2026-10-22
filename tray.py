"""Windows system-tray icon, menu commands and message-loop lifecycle."""

import ctypes
import os
import threading
from ctypes import wintypes

from constants import ICON_FILE

class PyFirewallSystemTray:
    WM_TRAYICON = 1024 + 1
    WM_CLOSE = 16
    WM_DESTROY = 2
    WM_NULL = 0
    WM_RBUTTONUP = 517
    WM_LBUTTONDBLCLK = 515
    NIM_ADD = 0
    NIM_DELETE = 2
    NIF_MESSAGE = 1
    NIF_ICON = 2
    NIF_TIP = 4
    MF_STRING = 0
    MF_GRAYED = 1
    TPM_LEFTALIGN = 0
    TPM_BOTTOMALIGN = 32
    TPM_RETURNCMD = 256
    TPM_NONOTIFY = 128
    ID_SHOW = 1001
    ID_FILTER_ALL = 1002
    ID_PAUSE = 1003
    ID_SETTINGS = 1004
    ID_CLOSE = 1005
    SW_HIDE = 0

    class POINT(ctypes.Structure):
        _fields_ = [('x', wintypes.LONG), ('y', wintypes.LONG)]

    class WNDCLASSEXW(ctypes.Structure):
        _fields_ = [('cbSize', wintypes.UINT), ('style', wintypes.UINT), ('lpfnWndProc', ctypes.c_void_p), ('cbClsExtra', ctypes.c_int), ('cbWndExtra', ctypes.c_int), ('hInstance', wintypes.HINSTANCE), ('hIcon', wintypes.HICON), ('hCursor', ctypes.c_void_p), ('hbrBackground', wintypes.HBRUSH), ('lpszMenuName', wintypes.LPCWSTR), ('lpszClassName', wintypes.LPCWSTR), ('hIconSm', wintypes.HICON)]

    class NOTIFYICONDATAW(ctypes.Structure):
        _fields_ = [('cbSize', wintypes.DWORD), ('hWnd', wintypes.HWND), ('uID', wintypes.UINT), ('uFlags', wintypes.UINT), ('uCallbackMessage', wintypes.UINT), ('hIcon', wintypes.HICON), ('szTip', wintypes.WCHAR * 128), ('dwState', wintypes.DWORD), ('dwStateMask', wintypes.DWORD), ('szInfo', wintypes.WCHAR * 256), ('uVersion_or_Timeout', wintypes.UINT), ('szInfoTitle', wintypes.WCHAR * 64), ('dwInfoFlags', wintypes.DWORD), ('guidItem', ctypes.c_byte * 16), ('hBalloonIcon', wintypes.HICON)]
    WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

    def __init__(self, command_queue, filter_all_enabled=True, is_paused=False):
        self.command_queue = command_queue
        self.state_lock = threading.Lock()
        self.filter_all_enabled = bool(filter_all_enabled)
        self.is_paused = bool(is_paused)
        self.thread = None
        self.thread_id = None
        self.hwnd = None
        self.class_name = f'PyFirewallTray_{os.getpid()}_{id(self)}'
        self._wndproc = None
        self._hicon = None
        self._registered = False
        self._icon_added = False
        self._ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True, name='PyFirewallTray')
        self.thread.start()

    def _run(self):
        try:
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            self.thread_id = kernel32.GetCurrentThreadId()
            user32.RegisterClassExW.argtypes = [ctypes.POINTER(self.WNDCLASSEXW)]
            user32.RegisterClassExW.restype = wintypes.ATOM
            user32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID]
            user32.CreateWindowExW.restype = wintypes.HWND
            user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
            user32.DefWindowProcW.restype = ctypes.c_ssize_t
            user32.DestroyWindow.argtypes = [wintypes.HWND]
            user32.DestroyWindow.restype = wintypes.BOOL
            user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
            user32.ShowWindow.restype = wintypes.BOOL
            user32.LoadIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
            user32.LoadIconW.restype = wintypes.HICON
            user32.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT, ctypes.c_int, ctypes.c_int, wintypes.UINT]
            user32.LoadImageW.restype = wintypes.HICON
            user32.LoadCursorW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
            user32.LoadCursorW.restype = ctypes.c_void_p
            user32.DestroyIcon.argtypes = [wintypes.HICON]
            user32.DestroyIcon.restype = wintypes.BOOL
            user32.GetCursorPos.argtypes = [ctypes.POINTER(self.POINT)]
            user32.GetCursorPos.restype = wintypes.BOOL
            user32.CreatePopupMenu.argtypes = []
            user32.CreatePopupMenu.restype = wintypes.HMENU
            user32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR]
            user32.AppendMenuW.restype = wintypes.BOOL
            user32.DestroyMenu.argtypes = [wintypes.HMENU]
            user32.DestroyMenu.restype = wintypes.BOOL
            user32.SetForegroundWindow.argtypes = [wintypes.HWND]
            user32.SetForegroundWindow.restype = wintypes.BOOL
            user32.TrackPopupMenu.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.LPVOID]
            user32.TrackPopupMenu.restype = wintypes.UINT
            user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
            user32.PostMessageW.restype = wintypes.BOOL
            user32.PostThreadMessageW.argtypes = [wintypes.DWORD, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
            user32.PostThreadMessageW.restype = wintypes.BOOL
            shell32 = ctypes.windll.shell32
            shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(self.NOTIFYICONDATAW)]
            shell32.Shell_NotifyIconW.restype = wintypes.BOOL
            default_icon = ctypes.cast(ctypes.c_void_p(32512), wintypes.LPCWSTR)
            arrow_cursor = user32.LoadCursorW(None, default_icon)
            self._hicon = user32.LoadImageW(None, ICON_FILE, 1, 0, 0, 16 | 64)
            if not self._hicon:
                self._hicon = user32.LoadIconW(None, default_icon)
            if not self._hicon:
                raise OSError('Could not load a PyFirewall icon or the default Windows application icon')
            self._wndproc = self.WNDPROC(self._window_proc)
            wnd = self.WNDCLASSEXW()
            wnd.cbSize = ctypes.sizeof(self.WNDCLASSEXW)
            wnd.style = 0
            wnd.lpfnWndProc = ctypes.cast(self._wndproc, wintypes.LPVOID)
            wnd.cbClsExtra = 0
            wnd.cbWndExtra = 0
            wnd.hInstance = kernel32.GetModuleHandleW(None)
            wnd.hIcon = self._hicon
            wnd.hCursor = arrow_cursor
            wnd.hbrBackground = None
            wnd.lpszMenuName = None
            wnd.lpszClassName = self.class_name
            wnd.hIconSm = self._hicon
            atom = user32.RegisterClassExW(ctypes.byref(wnd))
            if not atom:
                raise OSError(f'RegisterClassExW failed with error {ctypes.get_last_error()}')
            self._registered = True
            self.hwnd = user32.CreateWindowExW(0, self.class_name, 'PyFirewall', 0, 0, 0, 0, 0, None, None, wnd.hInstance, None)
            if not self.hwnd:
                raise OSError(f'CreateWindowExW failed with error {ctypes.get_last_error()}')
            user32.ShowWindow(self.hwnd, self.SW_HIDE)
            nid = self.NOTIFYICONDATAW()
            nid.cbSize = ctypes.sizeof(self.NOTIFYICONDATAW)
            nid.hWnd = self.hwnd
            nid.uID = 1
            nid.uFlags = self.NIF_MESSAGE | self.NIF_ICON | self.NIF_TIP
            nid.uCallbackMessage = self.WM_TRAYICON
            nid.hIcon = self._hicon
            nid.szTip = 'PyFirewall'
            if not shell32.Shell_NotifyIconW(self.NIM_ADD, ctypes.byref(nid)):
                raise OSError(f'Shell_NotifyIconW(NIM_ADD) failed with error {ctypes.get_last_error()}')
            self._icon_added = True
            self._ready.set()
            msg = wintypes.MSG()
            while True:
                result = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if result == 0 or result == -1:
                    break
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        except Exception:
            self._ready.set()
        finally:
            try:
                if self._icon_added and self.hwnd:
                    nid = self.NOTIFYICONDATAW()
                    nid.cbSize = ctypes.sizeof(self.NOTIFYICONDATAW)
                    nid.hWnd = self.hwnd
                    nid.uID = 1
                    ctypes.windll.shell32.Shell_NotifyIconW(self.NIM_DELETE, ctypes.byref(nid))
                    self._icon_added = False
            except Exception:
                pass
            try:
                if self.hwnd:
                    ctypes.windll.user32.DestroyWindow(self.hwnd)
                    self.hwnd = None
            except Exception:
                pass
            try:
                if self._registered:
                    ctypes.windll.user32.UnregisterClassW(self.class_name, ctypes.windll.kernel32.GetModuleHandleW(None))
                    self._registered = False
            except Exception:
                pass
            try:
                if self._hicon:
                    ctypes.windll.user32.DestroyIcon(self._hicon)
                    self._hicon = None
            except Exception:
                pass

    def _window_proc(self, hwnd, msg, wparam, lparam):
        if msg == self.WM_TRAYICON:
            event = wintypes.UINT(lparam & 4294967295).value
            if event == self.WM_RBUTTONUP:
                self._show_context_menu(hwnd)
            elif event == self.WM_LBUTTONDBLCLK:
                self.command_queue.put('show')
            return 0
        if msg == self.WM_CLOSE:
            ctypes.windll.user32.DestroyWindow(hwnd)
            return 0
        if msg == self.WM_DESTROY:
            ctypes.windll.user32.PostQuitMessage(0)
            return 0
        return ctypes.windll.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def update_state(self, filter_all_enabled=None, is_paused=None):
        with self.state_lock:
            if filter_all_enabled is not None:
                self.filter_all_enabled = bool(filter_all_enabled)
            if is_paused is not None:
                self.is_paused = bool(is_paused)

    def _get_state(self):
        with self.state_lock:
            return (self.filter_all_enabled, self.is_paused)

    def _show_context_menu(self, hwnd):
        user32 = ctypes.windll.user32
        menu = user32.CreatePopupMenu()
        if not menu:
            return
        try:
            filter_all_enabled, is_paused = self._get_state()
            filter_command_flags = self.MF_STRING | (self.MF_GRAYED if is_paused else 0)
            filter_text = 'Disable Filter All Connections' if filter_all_enabled else 'Filter All Connections'
            pause_text = 'Resume Monitoring' if is_paused else 'Pause Monitoring'
            user32.AppendMenuW(menu, self.MF_STRING, self.ID_SHOW, 'Show PyFirewall')
            user32.AppendMenuW(menu, self.MF_STRING, self.ID_PAUSE, pause_text)
            user32.AppendMenuW(menu, filter_command_flags, self.ID_FILTER_ALL, filter_text)
            user32.AppendMenuW(menu, self.MF_STRING, self.ID_SETTINGS, 'Settings')
            user32.AppendMenuW(menu, self.MF_STRING, self.ID_CLOSE, 'Close')
            point = self.POINT()
            if not user32.GetCursorPos(ctypes.byref(point)):
                return
            user32.SetForegroundWindow(hwnd)
            command = user32.TrackPopupMenu(menu, self.TPM_LEFTALIGN | self.TPM_BOTTOMALIGN | self.TPM_RETURNCMD | self.TPM_NONOTIFY, point.x, point.y, 0, hwnd, None)
            user32.PostMessageW(hwnd, self.WM_NULL, 0, 0)
            if command == self.ID_SHOW:
                self.command_queue.put('show')
            elif command == self.ID_PAUSE:
                self.command_queue.put('toggle_pause')
            elif command == self.ID_FILTER_ALL:
                self.command_queue.put('toggle_filter_all')
            elif command == self.ID_SETTINGS:
                self.command_queue.put('settings')
            elif command == self.ID_CLOSE:
                self.command_queue.put('close')
        finally:
            user32.DestroyMenu(menu)

    def stop(self):
        hwnd = self.hwnd
        if hwnd:
            try:
                ctypes.windll.user32.PostMessageW(hwnd, self.WM_CLOSE, 0, 0)
            except Exception:
                pass
        elif self.thread and self.thread.is_alive() and self.thread_id:
            try:
                ctypes.windll.user32.PostThreadMessageW(self.thread_id, self.WM_CLOSE, 0, 0)
            except Exception:
                pass
