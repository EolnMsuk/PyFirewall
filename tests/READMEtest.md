| File | What it covers |
|---|---|
| [support.py](/C:/PyFirewall/tests/support.py) | Shared application imports and dependency mocking used throughout the tests. |
| [test_firewall_monitor.py](/C:/PyFirewall/tests/test_firewall_monitor.py) | Core firewall transactions, rollback, profile recovery, Auto-Block races, packet-capture recovery, and rule actions. Also supplies shared test fixtures. |
| [test_native_port_rules.py](/C:/PyFirewall/tests/test_native_port_rules.py) | Port-rule creation, removal, rollback, precedence, validation, and preservation of unrelated rules. |
| [test_review_fixes.py](/C:/PyFirewall/tests/test_review_fixes.py) | DNS failures and observed-IP fallback, saved domain rules, table scrolling/resizing, themes, and popup dismissal. |
| [test_feature_updates.py](/C:/PyFirewall/tests/test_feature_updates.py) | Import compatibility, rule directions, column controls, settings persistence/reset, GUI layout, and PowerShell syntax. |
| [test_settings_and_traffic.py](/C:/PyFirewall/tests/test_settings_and_traffic.py) | Traffic totals after pruning, overlapping address accounting, uninstall launch behavior, and settings/donation UI. |
| [test_startup.py](/C:/PyFirewall/tests/test_startup.py) | Import side effects, elevation/startup ordering, duplicate-instance handling, and resource paths. |
| [test_installer_lifecycle.py](/C:/PyFirewall/tests/test_installer_lifecycle.py) | Installer consent to close the app and preservation/creation of the startup task, using mocked Windows operations. |
| [test_uninstall_policy.py](/C:/PyFirewall/tests/test_uninstall_policy.py) | Dependency ownership, missing install logs, declined removals, and cleanup ordering. |
| [test_update_checks.py](/C:/PyFirewall/tests/test_update_checks.py) | Version comparisons, failed HTTP responses, background checks, preferences, and update prompts. |
