"""Normal application imports and explicit dependency patches for isolated tests.

No source extraction is needed now that startup is behind main(). Tests create
partial application objects or explicitly mock background services for full GUIs.
"""

from contextlib import ExitStack, contextmanager
from unittest.mock import patch

import app as app_module
import auto_block
import constants
import firewall
import helpers
import monitoring
import settings
import tray
import updates
import views
import widgets

MODULES = (app_module, auto_block, constants, firewall, helpers, monitoring,
           settings, tray, updates, views, widgets)
App = app_module.FirewallMonitorApp

# Read-only lookup retained for the existing regression assertions. Replacements
# must patch the module where a name is used, via patch_dependencies below.
NS = {name: value for module in MODULES for name, value in vars(module).items()
      if not name.startswith('__') or name == '__version__'}


@contextmanager
def patch_dependencies(**replacements):
    """Patch imported dependencies in their owning/consuming modules, then restore."""
    with ExitStack() as stack:
        for name, value in replacements.items():
            consumers = [module for module in MODULES if hasattr(module, name)]
            if not consumers:
                raise KeyError(f'Unknown application dependency: {name}')
            for module in consumers:
                stack.enter_context(patch.object(module, name, value))
        yield dict(NS, **replacements)
