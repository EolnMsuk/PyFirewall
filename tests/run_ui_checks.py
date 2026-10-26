"""Run UI/settings regressions without importing Scapy or loading Npcap.

Run from the project directory: python tests/run_ui_checks.py
"""
import pathlib
import sys
import types
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
scapy = types.ModuleType('scapy')
scapy_all = types.ModuleType('scapy.all')
for name in ('DNS', 'IP', 'IPv6', 'TCP', 'UDP', 'conf', 'sniff'):
    setattr(scapy_all, name, Mock(side_effect=AssertionError('Capture is disabled in UI checks')))
scapy.all = scapy_all
sys.modules['scapy'] = scapy
sys.modules['scapy.all'] = scapy_all

if __name__ == '__main__':
    names = sys.argv[1:] or [
        'test_rule_presentation',
        'test_rule_editing',
        'test_feature_updates.ColumnAndDialogTests',
        'test_feature_updates.TkHeaderTests',
        'test_firewall_monitor.ContextGlobalRuleTests',
        'test_ui_preferences',
    ]
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(names))
    sys.exit(not result.wasSuccessful())
