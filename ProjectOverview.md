# PyFirewall overview

PyFirewall is a Windows desktop application that shows which programs are using the network and lets you control their inbound and outbound traffic through Windows Defender Firewall. It runs with administrator privileges. Scapy captures packets through Npcap on the first usable non-loopback adapter. PyFirewall uses psutil to match TCP and UDP traffic to local processes. For each connection it can identify, the Live Monitor shows the program, remote host, ports, and upload and download totals.

## Required files

Keep these files together in the installation folder. Run the installer or uninstaller as administrator.

```text
PyFirewall/
├── Install-PyFirewall.cmd     # Checks for administrator privileges and starts setup.
├── requirements.ps1           # Sets up prerequisites, the desktop shortcut, and optional startup at login.
├── requirements.txt           # Lists the psutil and Scapy dependencies for pip.
├── firewall_monitor.py        # Launches one app instance with administrator privileges.
├── app.py                     # Builds the main window and coordinates startup and shutdown.
├── monitoring.py              # Matches packets to processes, resolves hostnames, and counts bytes.
├── firewall.py                # Applies and verifies firewall rules and restores profile settings.
├── auto_block.py              # Handles threshold alerts, temporary blocks, and decision prompts.
├── views.py                   # Shows connections, alerts, and rules. Handles CSV export and rule backups.
├── settings.py                # Builds the Settings tab and saves preferences and rules.
├── widgets.py                 # Provides themed controls, menus, tooltips, and table interactions.
├── tray.py                    # Handles the Windows tray icon and its menu commands.
├── updates.py                 # Checks GitHub for new releases and displays update prompts.
├── constants.py               # Defines shared defaults, limits, and resource paths.
├── helpers.py                 # Normalizes executable paths, addresses, and ports for rule matching.
├── diagnostics.py             # Records exceptions, cached UI state, heartbeat stalls, and fatal faults.
├── PyFirewall.ico             # Supplies the icon for the window, tray, and desktop shortcut.
└── Uninstall-PyFirewall.cmd   # Removes selected rules, settings, and components added by setup.
```