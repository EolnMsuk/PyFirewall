"""Entry-point checks without elevation, native tray creation or firewall writes."""

import importlib.util
from pathlib import Path
import queue
import socket
import threading
import unittest
from unittest.mock import MagicMock, Mock, patch

import app as app_module
import constants
import tray
import firewall_monitor as entry
import tkinter as tk


class StartupTests(unittest.TestCase):
    def test_single_click_and_double_click_queue_show_right_click_only_opens_menu(self):
        with patch.object(tray.threading, 'Thread'):
            icon = tray.PyFirewallSystemTray(queue.Queue())
        icon._show_context_menu = Mock()
        for event in (icon.WM_LBUTTONUP, icon.WM_LBUTTONDBLCLK, icon.WM_RBUTTONUP):
            icon._window_proc(123, icon.WM_TRAYICON, 0, event)
        self.assertEqual(list(icon.command_queue.queue), ['show', 'show'])
        icon._show_context_menu.assert_called_once_with(123)

    def test_tray_stop_during_startup_and_failed_registration_clean_up_once(self):
        for mode in ('stop_before_ready', 'stop_on_publish', 'failed_add', 'shared_icon', 'close'):
            with self.subTest(mode=mode), patch.object(tray.threading, 'Thread'), \
                 patch.object(tray, 'log_internal_error') as log:
                icon = tray.PyFirewallSystemTray(queue.Queue())
                native = MagicMock()
                user32 = native.user32
                native.kernel32.GetModuleHandleW.return_value = 0x100000001
                user32.LoadCursorW.return_value = 2
                user32.LoadImageW.return_value = 0 if mode == 'shared_icon' else 3
                user32.LoadIconW.return_value = 4
                user32.RegisterClassExW.return_value = 1
                user32.RegisterWindowMessageW.return_value = 12345
                def publish(*args):
                    if mode == 'stop_on_publish':
                        icon.stop()
                    return 0x200000001
                user32.CreateWindowExW.side_effect = publish
                def get_message(*args):
                    if mode == 'close':
                        icon._window_proc(icon.hwnd, icon.WM_CLOSE, 0, 0)
                        user32.DestroyWindow.assert_not_called()
                    return 0
                user32.GetMessageW.side_effect = get_message
                native.shell32.Shell_NotifyIconW.return_value = mode != 'failed_add'
                with patch.object(tray.ctypes, 'windll', native):
                    if mode == 'stop_before_ready':
                        icon.stop()
                    icon._run()
                    icon.stop()
                    icon.stop()
                self.assertTrue(icon._ready.is_set() and icon.wait(0))
                self.assertFalse(icon.available)
                self.assertIsNone(icon.hwnd)
                user32.DestroyWindow.assert_called_once_with(0x200000001)
                user32.UnregisterClassW.assert_called_once_with(icon.class_name, 0x100000001)
                if mode == 'shared_icon':
                    user32.DestroyIcon.assert_not_called()
                else:
                    user32.DestroyIcon.assert_called_once_with(3)
                if mode == 'failed_add':
                    self.assertEqual(icon.command_queue.get_nowait(), 'tray_unavailable')
                    log.assert_called()
                elif mode.startswith('stop_'):
                    native.shell32.Shell_NotifyIconW.assert_not_called()
                else:
                    self.assertEqual([c.args[0] for c in native.shell32.Shell_NotifyIconW.call_args_list], [0, 2])

    def test_taskbar_recreation_registers_again_and_reports_failure_to_tk(self):
        with patch.object(tray.threading, 'Thread'):
            icon = tray.PyFirewallSystemTray(queue.Queue())
        icon._taskbar_created, icon._hicon = 12345, 3
        native = MagicMock()
        native.shell32.Shell_NotifyIconW.side_effect = [True, False]
        with patch.object(tray.ctypes, 'windll', native), patch.object(tray, 'log_internal_error'):
            icon._window_proc(123, 12345, 0, 0)
            self.assertTrue(icon.available)
            icon._window_proc(123, 12345, 0, 0)
            self.assertFalse(icon.available)
            self.assertEqual(icon.command_queue.get_nowait(), 'tray_unavailable')
            icon.stop()
            icon._window_proc(123, 12345, 0, 0)
        self.assertEqual(native.shell32.Shell_NotifyIconW.call_count, 2)

    def test_restore_preserves_zoom_and_uses_main_wrapper_without_stale_activation(self):
        for state, maximized in [('normal', False), ('zoomed', True), ('iconic', True), ('withdrawn', True), ('withdrawn', False)]:
            with self.subTest(state=state, maximized=maximized):
                a = app_module.FirewallMonitorApp.__new__(app_module.FirewallMonitorApp)
                a.root = Mock()
                restored = 'zoomed' if maximized else 'normal'
                a.root.state.side_effect = [state, None, restored] if state in {'iconic', 'withdrawn'} else [state, restored]
                a.root.grab_current.return_value = None
                a.root.winfo_id.return_value = 0x100000001
                a.closed, a.tray_hidden, a.window_maximized = False, True, maximized
                a.auto_prompt_dialog = None
                native = MagicMock()
                native.user32.GetAncestor.return_value = 0x200000001
                native.user32.SetForegroundWindow.return_value = True
                with patch.object(app_module.ctypes, 'windll', native):
                    a.show_from_tray()
                    if state in {'iconic', 'withdrawn'}:
                        self.assertEqual(a.root.state.call_args.args, (restored,))
                    else:
                        a.root.deiconify.assert_not_called()
                    a.root.after_idle.call_args.args[0]()
                native.user32.GetAncestor.assert_called_once_with(0x100000001, 2)
                native.user32.SetForegroundWindow.assert_called_once_with(0x200000001)
                native.user32.SetForegroundWindow.reset_mock()
                a.tray_hidden = True
                with patch.object(app_module.ctypes, 'windll', native):
                    a.root.after_idle.call_args.args[0]()
                native.user32.SetForegroundWindow.assert_not_called()

    def test_title_bar_close_keeps_taskbar_during_pending_tray_and_exits_on_failure(self):
        a = app_module.FirewallMonitorApp.__new__(app_module.FirewallMonitorApp)
        a.closed = a.tray_hidden = False
        a.root = Mock()
        a._capture_layout, a.on_closing = Mock(), Mock()
        a.tray = Mock(available=False, _ready=threading.Event())
        a.minimize_to_tray()
        a.root.iconify.assert_called_once()
        a.root.withdraw.assert_not_called()
        a.on_closing.assert_not_called()
        a.tray._ready.set()
        a.minimize_to_tray()
        a.on_closing.assert_called_once()

    def test_activation_failure_keeps_window_accessible_and_respects_dialog_focus(self):
        a = app_module.FirewallMonitorApp.__new__(app_module.FirewallMonitorApp)
        a.root = Mock()
        a.root.state.return_value = 'normal'
        a.closed = a.tray_hidden = False
        a._visibility_generation = 1
        a.auto_prompt_dialog = Mock()
        a.auto_prompt_dialog.winfo_exists.return_value = True
        a.keep_notification_foreground = True
        modal = Mock()
        native = MagicMock()
        native.user32.SetForegroundWindow.return_value = False
        with patch.object(app_module.ctypes, 'windll', native):
            for grab, preference, target in [(modal, False, modal), (None, True, a.auto_prompt_dialog), (None, False, a.root)]:
                a.root.grab_current.return_value = grab
                a.keep_notification_foreground = preference
                target.winfo_id.return_value = 123
                a._foreground_main_window(1)
                native.user32.GetAncestor.assert_called_with(123, 2)
                target.lift.assert_called()
                target.focus_set.assert_not_called()
                target.attributes.assert_not_called()
                self.assertFalse(a.tray_hidden or a.foreground_activation_succeeded)

    def test_activation_listener_closes_socket_if_bind_fails(self):
        a = app_module.FirewallMonitorApp.__new__(app_module.FirewallMonitorApp)
        a.instance_activation_port = 40123
        listener = Mock()
        listener.bind.side_effect = OSError('address in use')
        with patch.object(app_module.socket, 'socket', return_value=listener), \
             patch.object(app_module, 'log_internal_error'):
            a._start_instance_activation_listener()
        listener.close.assert_called_once()

    def test_import_does_not_start_application_or_request_elevation(self):
        spec = importlib.util.spec_from_file_location('entry_import_test', entry.__file__)
        module = importlib.util.module_from_spec(spec)
        with patch.object(entry.ctypes, 'windll') as native, \
             patch.object(tk, 'Tk') as window, \
             patch.object(app_module, 'FirewallMonitorApp') as application:
            spec.loader.exec_module(module)
        self.assertEqual(native.mock_calls, [])
        window.assert_not_called()
        application.assert_not_called()
        self.assertIsNone(module._MUTEX_HANDLE)
        self.assertEqual(module.__version__, constants.__version__)

    def test_main_checks_guards_before_building_gui(self):
        events = []
        root = Mock()
        root.mainloop.side_effect = lambda: events.append('mainloop')
        with patch.object(entry, 'hide_console', side_effect=lambda: events.append('hide')), \
             patch.object(entry, 'elevate', side_effect=lambda: events.append('elevate')), \
             patch.object(entry, 'acquire_single_instance', side_effect=lambda: events.append('mutex') or True), \
             patch.object(tk, 'Tk', side_effect=lambda: events.append('window') or root), \
             patch.object(app_module, 'FirewallMonitorApp', side_effect=lambda *_args, **_kwargs: events.append('application')):
            entry.main()
        self.assertEqual(events, ['hide', 'elevate', 'mutex', 'window', 'application', 'mainloop'])
        root.iconbitmap.assert_called_once_with(default=constants.ICON_FILE)

    def test_duplicate_instance_does_not_create_gui(self):
        with patch.object(entry, 'hide_console'), patch.object(entry, 'elevate'), \
             patch.object(entry, 'acquire_single_instance', return_value=False), \
             patch.object(tk, 'Tk') as window, \
             patch.object(app_module, 'FirewallMonitorApp') as application:
            entry.main()
        window.assert_not_called()
        application.assert_not_called()

    def test_duplicate_instance_signals_the_running_copy_without_a_message_box(self):
        kernel32 = Mock()
        kernel32.CreateMutexW.return_value = 1
        kernel32.GetLastError.return_value = 183
        kernel32.WaitForSingleObject.return_value = 0x102
        native = MagicMock()
        native.kernel32 = kernel32
        with patch.object(entry.ctypes, 'windll', native), \
             patch.object(entry, 'activate_existing_instance', return_value=True) as activate:
            self.assertFalse(entry.acquire_single_instance())
        activate.assert_called_once_with()
        kernel32.CloseHandle.assert_called_once_with(1)
        self.assertFalse(hasattr(native.user32, 'MessageBoxW') and native.user32.MessageBoxW.called)

    def test_activation_request_retries_until_the_listener_is_ready(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        with patch.object(entry, 'instance_activation_port', return_value=40123), \
             patch.object(entry.socket, 'create_connection', side_effect=[OSError('not ready'), connection]) as connect, \
             patch.object(entry.time, 'monotonic', side_effect=[0, 0, 0.1]), \
             patch.object(entry.time, 'sleep') as sleep:
            self.assertTrue(entry.activate_existing_instance())
        self.assertEqual(connect.call_args_list[0].args, (('127.0.0.1', 40123),))
        connection.sendall.assert_called_once_with(b'SHOW')
        sleep.assert_called_once_with(0.1)

    def test_running_app_queues_show_request_from_loopback(self):
        application = app_module.FirewallMonitorApp.__new__(app_module.FirewallMonitorApp)
        application.tray_command_queue = queue.Queue()
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.return_value = b'SHOW'
        application._handle_instance_activation(connection)
        self.assertEqual(application.tray_command_queue.get_nowait(), 'show')

    def test_activation_accumulates_fragments_bounds_idle_clients_and_checks_shutdown(self):
        application = app_module.FirewallMonitorApp.__new__(app_module.FirewallMonitorApp)
        application.tray_command_queue = queue.Queue()
        application.closed = False
        application.instance_activation_stop = threading.Event()
        for fragments, expected in [([b'S', b'HO', b'W'], ['show']), ([socket.timeout()], [])]:
            connection = MagicMock()
            connection.__enter__.return_value = connection
            connection.recv.side_effect = fragments
            application._handle_instance_activation(connection)
            self.assertEqual(list(application.tray_command_queue.queue), expected)
            while not application.tray_command_queue.empty():
                application.tray_command_queue.get_nowait()
            self.assertLessEqual(connection.settimeout.call_args.args[0], 0.5)
            connection.__exit__.assert_called_once()
        connection.recv.side_effect = lambda n: application.instance_activation_stop.set() or b'SHOW'
        application._handle_instance_activation(connection)
        self.assertTrue(application.tray_command_queue.empty())
        application.instance_activation_stop.clear()
        connection.recv.reset_mock()
        connection.recv.side_effect = [b'S', b'H', b'OW']
        with patch.object(app_module.time, 'monotonic', side_effect=[0, 0.1, 0.4, 0.6]):
            application._handle_instance_activation(connection)
        self.assertEqual(connection.recv.call_count, 2)
        self.assertTrue(application.tray_command_queue.empty())

    def test_failed_mutex_stops_startup_and_primary_keeps_pointer_sized_handle(self):
        native = MagicMock()
        native.kernel32.GetLastError.return_value = 5
        with patch.object(entry.ctypes, 'windll', native), patch('helpers.log_internal_error') as log, \
             patch.object(entry, '_MUTEX_HANDLE', None):
            native.kernel32.CreateMutexW.return_value = 0
            with self.assertRaises(SystemExit):
                entry.acquire_single_instance()
            log.assert_called_once()
            native.kernel32.CreateMutexW.return_value = 0x100000001
            native.kernel32.GetLastError.return_value = 0
            self.assertTrue(entry.acquire_single_instance())
            self.assertEqual(entry._MUTEX_HANDLE, 0x100000001)
            self.assertIs(native.kernel32.CreateMutexW.restype, entry.wintypes.HANDLE)
            native.kernel32.CloseHandle.assert_not_called()
            self.assertEqual(native.kernel32.CreateMutexW.call_args.args,
                             (None, True, constants.NATIVE_OWNER_MUTEX))

    def test_owner_identity_is_path_independent_and_abandoned_owner_can_be_acquired(self):
        original = entry.instance_key()
        with patch.object(entry, '__file__', r'D:\second-copy\firewall_monitor.py'):
            self.assertEqual(entry.instance_key(), original)
        native = MagicMock()
        native.kernel32.CreateMutexW.return_value = 42
        native.kernel32.GetLastError.return_value = 183
        native.kernel32.WaitForSingleObject.return_value = 0x80
        with patch.object(entry.ctypes, 'windll', native), patch.object(entry, '_MUTEX_HANDLE', None), \
             patch.object(entry, 'activate_existing_instance') as activate:
            self.assertTrue(entry.acquire_single_instance())
            activate.assert_not_called()
            entry.release_single_instance()
            native.kernel32.ReleaseMutex.assert_called_once_with(42)
            native.kernel32.CloseHandle.assert_called_once_with(42)

    def test_elevation_exit_stops_startup(self):
        with patch.object(entry, 'hide_console'), \
             patch.object(entry, 'elevate', side_effect=SystemExit), \
             patch.object(entry, 'acquire_single_instance') as mutex, \
             patch.object(tk, 'Tk') as window:
            with self.assertRaises(SystemExit):
                entry.main()
        mutex.assert_not_called()
        window.assert_not_called()

    def test_resource_paths_remain_beside_entry_point(self):
        directory = Path(entry.__file__).resolve().parent
        self.assertEqual(Path(constants.SCRIPT_DIR), directory)
        for name in ('CONFIG_FILE', 'ICON_FILE', 'FIREWALL_PROFILE_BACKUP_FILE', 'INTERNAL_ERROR_LOG_FILE'):
            with self.subTest(resource=name):
                self.assertEqual(Path(getattr(constants, name)).parent, directory)


if __name__ == '__main__':
    unittest.main()
