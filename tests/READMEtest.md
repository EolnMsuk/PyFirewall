Run `python tests/run_ui_checks.py` for the UI/settings regression subset. This runner substitutes Scapy before importing the application, so it never loads Npcap or starts packet capture. Firewall and background services are mocked in these checks. The Keep Notification in Foreground option defaults to enabled.

| File | What it covers |
|---|---|
| test_rule_presentation.py | DNS-based global-rule drafts, inbound global status and removal, Managed Rules columns, and saved column/theme preferences. |
| test_requested_updates.py | Grouped targets and IP ranges, offline restoration and rollback, passive DNS hints, multi-selection copying, independent menu highlights, and light-theme colors. |
| [support.py](https://github.com/EolnMsuk/PyFirewall/blob/main/tests/support.py) | Shared application imports and dependency mocking used throughout the tests. |
| [run_ui_checks.py](https://github.com/EolnMsuk/PyFirewall/blob/main/tests/run_ui_checks.py) | Runs the UI/settings regression subset with Scapy, firewall, and background-service dependencies mocked. |
| [test_firewall_monitor.py](https://github.com/EolnMsuk/PyFirewall/blob/main/tests/test_firewall_monitor.py) | Core firewall transactions, rollback, profile recovery, Auto-Block races, packet-capture recovery, and rule actions. Also supplies shared test fixtures. |
| [test_native_port_rules.py](https://github.com/EolnMsuk/PyFirewall/blob/main/tests/test_native_port_rules.py) | Port-rule creation, removal, rollback, precedence, validation, and preservation of unrelated rules. |
| [test_combined_global_rules.py](https://github.com/EolnMsuk/PyFirewall/blob/main/tests/test_combined_global_rules.py) | Combined address/port matching, inbound-only policies, rollback, import/export and restart, dialog validation and cancellation, and contextual global/app removal. |
| [test_rule_editing.py](https://github.com/EolnMsuk/PyFirewall/blob/main/tests/test_rule_editing.py) | Protocol filters, atomic rule edits and rollback, rule priority, partial domain failures, double-click routing, result feedback, and real Tk dialog/menu styling. |
| [test_review_fixes.py](https://github.com/EolnMsuk/PyFirewall/blob/main/tests/test_review_fixes.py) | DNS failures and observed-IP fallback, saved domain rules, table scrolling/resizing, themes, and popup dismissal. |
| [test_feature_updates.py](https://github.com/EolnMsuk/PyFirewall/blob/main/tests/test_feature_updates.py) | Import compatibility, rule directions, column controls, settings persistence/reset, GUI layout, and PowerShell syntax. |
| [test_settings_and_traffic.py](https://github.com/EolnMsuk/PyFirewall/blob/main/tests/test_settings_and_traffic.py) | Traffic totals after pruning, overlapping address accounting, uninstall launch behavior, and settings/donation UI. |
| [test_startup.py](https://github.com/EolnMsuk/PyFirewall/blob/main/tests/test_startup.py) | Import side effects, elevation/startup ordering, duplicate-instance handling, and resource paths. |
| [test_ui_preferences.py](https://github.com/EolnMsuk/PyFirewall/blob/main/tests/test_ui_preferences.py) | Connection drafts, alert details, preference persistence, and saved window/table layout. |
| [test_installer_lifecycle.py](https://github.com/EolnMsuk/PyFirewall/blob/main/tests/test_installer_lifecycle.py) | Installer consent to close the app and preservation/creation of the startup task, using mocked Windows operations. |
| [test_uninstall_policy.py](https://github.com/EolnMsuk/PyFirewall/blob/main/tests/test_uninstall_policy.py) | Dependency ownership, missing install logs, declined removals, and cleanup ordering. |
| [test_update_checks.py](https://github.com/EolnMsuk/PyFirewall/blob/main/tests/test_update_checks.py) | Version comparisons, failed HTTP responses, background checks, preferences, and update prompts. |
