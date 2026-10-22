"""Update checks with fake HTTP responses and isolated Tk: no live firewall/network actions."""
import io
import json
import queue
import unittest
import urllib.error
from unittest.mock import Mock, patch
from support import patch_dependencies
from test_firewall_monitor import NS, app


class ReleaseCheckTests(unittest.TestCase):
    def check_response(self, payload):
        with patch.object(NS['urllib'].request, 'urlopen',
                          return_value=io.BytesIO(json.dumps(payload).encode())) as request:
            result = NS['check_latest_release']()
        sent = request.call_args.args[0]
        self.assertEqual(sent.full_url, 'https://api.github.com/repos/EolnMsuk/PyFirewall/releases/latest')
        self.assertEqual(sent.get_header('User-agent'), 'PyFirewall/2.4')
        self.assertEqual(request.call_args.kwargs['timeout'], 10)
        return result

    def test_numeric_comparison_and_leading_v(self):
        self.assertEqual(NS['__version__'], '2.4')
        for tag, newer in [('v2.5', True), ('2.10', True), ('v2.4.1', True),
                           ('v3.0', True), ('v2.4', False), ('2.4.0', False),
                           ('2.3.99', False), ('1.99', False)]:
            with self.subTest(tag=tag):
                self.assertEqual(self.check_response({'tag_name': tag}), (tag.lstrip('v'), newer))

    def test_invalid_and_nonstable_responses_are_unavailable(self):
        for payload in ({}, [], None, {'tag_name': None}, {'tag_name': 25},
                        {'tag_name': 'oops'}, {'tag_name': 'v2.5-rc1'},
                        {'tag_name': 'v3', 'prerelease': True}, {'tag_name': 'v3', 'draft': True}):
            with self.subTest(payload=payload):
                self.assertIsNone(self.check_response(payload))

    def test_offline_timeout_rate_limit_and_malformed_json(self):
        for error in (urllib.error.URLError('offline'), TimeoutError(),
                      urllib.error.HTTPError('https://api.github.com', 403, 'rate limit', {}, None),
                      urllib.error.HTTPError('https://api.github.com', 429, 'rate limit', {}, None)):
            with self.subTest(error=error), patch.object(NS['urllib'].request, 'urlopen', side_effect=error):
                self.assertIsNone(NS['check_latest_release']())
        with patch.object(NS['urllib'].request, 'urlopen', return_value=io.BytesIO(b'invalid json')):
            self.assertIsNone(NS['check_latest_release']())


class UpdateDispatchTests(unittest.TestCase):
    def setUp(self):
        self.a = app()
        self.a.root = Mock()
        self.a.ui_queue = queue.Queue()
        self.a._show_update_prompt = Mock()

    def test_check_is_background_and_concurrent_manual_click_reuses_worker(self):
        with patch.object(NS['threading'], 'Thread') as thread, \
             patch_dependencies(check_latest_release=Mock()) as namespace:
            self.a.check_for_updates(manual=False)
            self.a.check_for_updates()
            self.a.check_for_updates()
            thread.assert_called_once_with(target=self.a._update_check_worker, daemon=True,
                                           name='PyFirewall-UpdateCheck')
            thread.return_value.start.assert_called_once()
            namespace['check_latest_release'].assert_not_called()
        self.assertTrue(self.a.update_check_manual)
        self.assertTrue(self.a.update_check_running)

    def test_worker_only_queues_result_and_ui_thread_prompts(self):
        with patch_dependencies(check_latest_release=Mock(return_value=('2.5', True))):
            self.a._update_check_worker()
        self.a._show_update_prompt.assert_not_called()
        self.a.root.assert_not_called()
        self.a.drain_ui_queue()
        self.a._show_update_prompt.assert_called_once_with('2.5')

    def test_startup_checks_only_after_success_and_when_opted_in(self):
        for opted_in, success in ((False, True), (True, True), (True, False)):
            with self.subTest(opted_in=opted_in, success=success):
                a = app()
                a.root = Mock()
                a.ui_queue = queue.Queue()
                a.check_updates_on_startup = opted_in
                a.startup_complete = False
                a.refresh_rules = a.start_sniffing = a.update_status = Mock()
                a.status_firewall = a.status_state = Mock()
                def check(manual):
                    self.assertFalse(manual)
                    self.assertTrue(a.startup_complete)
                a.check_for_updates = Mock(side_effect=check)
                a.ui_queue.put(('startup_complete', success, 'test failure'))
                with patch.object(NS['threading'], 'Thread'), patch.object(NS['messagebox'], 'showerror'):
                    a.drain_ui_queue()
                self.assertEqual(a.check_for_updates.call_count, int(opted_in and success))

    def test_manual_results_and_quiet_startup_results(self):
        for manual in (False, True):
            for result in (None, ('2.4', False), ('2.5', True)):
                with self.subTest(manual=manual, result=result), patch.object(NS['messagebox'], 'showinfo') as info:
                    self.a.update_check_manual = manual
                    self.a.update_check_running = True
                    self.a._show_update_prompt.reset_mock()
                    self.a._finish_update_check(result)
                    self.assertFalse(self.a.update_check_running)
                    self.assertEqual(self.a._show_update_prompt.call_count, int(result == ('2.5', True)))
                    self.assertEqual(info.call_count, int(manual and result != ('2.5', True)))
                    if manual and result == ('2.4', False):
                        self.assertIn('2.4', info.call_args.args[1])

    def test_thread_start_failure_is_graceful(self):
        with patch.object(NS['threading'], 'Thread') as thread, patch.object(NS['messagebox'], 'showinfo') as info:
            thread.return_value.start.side_effect = RuntimeError('cannot start thread')
            self.a.check_for_updates()
        info.assert_called_once()
        self.assertFalse(self.a.update_check_running)

    def test_preference_save_failure_reports_error_without_real_dialog(self):
        self.a.check_updates_on_startup_var.get.return_value = True
        self.a.save_settings.return_value = False
        with patch.object(NS['messagebox'], 'showerror') as error:
            self.a.on_update_setting_changed()
        self.a.save_settings.assert_called_once()
        error.assert_called_once_with('Settings Not Saved',
                                      'Could not save the startup update preference. Please try again.',
                                      parent=self.a.root)

    def test_no_action_after_exit(self):
        self.a.closed = True
        with patch.object(NS['threading'], 'Thread') as thread, patch.object(NS['messagebox'], 'showinfo') as info:
            self.a.check_for_updates()
            self.a._finish_update_check(('2.5', True))
        thread.assert_not_called()
        info.assert_not_called()
        self.a._show_update_prompt.assert_not_called()


class UpdatePromptTests(unittest.TestCase):
    def setUp(self):
        self.root = NS['tk'].Tk()
        self.root.withdraw()
        self.a = app()
        self.a.root = self.root
        self.a.tray_hidden = False
        self.a._theme_dialog = Mock()
        self.a._center_dialog = Mock()

    def tearDown(self):
        self.root.destroy()

    def buttons(self):
        return {widget.cget('text'): widget for widget in self.a.update_dialog.winfo_children()
                if isinstance(widget, NS['ttk'].Button)}

    def test_only_explicit_open_action_opens_fixed_release_page(self):
        with patch.object(NS['os'], 'startfile') as startfile:
            self.a._show_update_prompt('2.5')
            startfile.assert_not_called()
            self.assertEqual(set(self.buttons()), {'Open Release Page', 'Cancel'})
            prompt = self.a.update_dialog.winfo_children()[0].cget('text')
            self.assertIn('2.5', prompt)
            self.assertIn('2.4', prompt)
            self.buttons()['Cancel'].invoke()
            startfile.assert_not_called()
            self.assertIsNone(self.a.update_dialog)
            self.a._show_update_prompt('2.5')
            self.buttons()['Open Release Page'].invoke()
            startfile.assert_called_once_with('https://github.com/EolnMsuk/PyFirewall/releases/latest')
            self.assertIsNone(self.a.update_dialog)

    def test_window_close_cancels_and_duplicate_check_does_not_start_worker(self):
        with patch.object(NS['os'], 'startfile') as startfile, patch.object(NS['threading'], 'Thread') as thread:
            self.a._show_update_prompt('2.5')
            self.a.check_for_updates()
            thread.assert_not_called()
            dialog = self.a.update_dialog
            dialog.tk.call(dialog.protocol('WM_DELETE_WINDOW'))
            startfile.assert_not_called()
            self.assertIsNone(self.a.update_dialog)

    def test_browser_failure_is_graceful(self):
        with patch.object(NS['os'], 'startfile', side_effect=OSError('no browser')), \
             patch.object(NS['messagebox'], 'showerror') as error:
            self.a._show_update_prompt('2.5')
            self.buttons()['Open Release Page'].invoke()
        error.assert_called_once()
        self.assertIn(NS['LATEST_RELEASE_PAGE'], error.call_args.args[1])


if __name__ == '__main__':
    unittest.main()
