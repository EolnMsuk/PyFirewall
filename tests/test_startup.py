"""Entry-point checks without elevation, native tray creation or firewall writes."""

import importlib.util
from pathlib import Path
import queue
import unittest
from unittest.mock import MagicMock, Mock, patch

import app as app_module
import constants
import firewall_monitor as entry
import tkinter as tk


class StartupTests(unittest.TestCase):
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
        native = MagicMock()
        native.kernel32 = kernel32
        with patch.object(entry.ctypes, 'windll', native), \
             patch.object(entry, 'activate_existing_instance', return_value=True) as activate:
            self.assertFalse(entry.acquire_single_instance())
        activate.assert_called_once_with()
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
