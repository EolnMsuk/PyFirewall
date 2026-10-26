# PyFirewall ⛨

**Python Personal Firewall & Network Monitor for Windows**

PyFirewall is a Windows desktop application for monitoring / filtering network connections by creating Windows Defender Firewall rules. **It monitors and configures both incoming and outgoing connections** using process and IP/domain specific rules. It uses Tkinter for the interface, Scapy for packet capture, psutil for process and network information, and supports application and global IP/domain rules.

---

<img width="1544" height="2857" alt="example" src="https://github.com/user-attachments/assets/a0aed78a-ed35-473f-9d50-fc45170f0036" />

---

## Features

* Live network connection monitoring
* Auto-Block Protection
* Per-application allow/block rules
* Global IP/domain & local/remote port specific rules
* IPv4 and IPv6 address, CIDR, and inclusive IP range support
* Connection-rate and upload-threshold alerts
* CSV export for connection data
* JSON export/import for managed firewall rules
* System-tray support and automatic start at Windows login
* Dark/light theme support
* Startup update checks and a manual **Check for Updates** button

## Requirements

* Windows 10 or Windows 11
* Administrator privileges
* [Python 3.8+](https://www.python.org/downloads/windows/) w/ Tkinter / psutil / scapy
* [Npcap](https://npcap.com/)

## Installation

### Method 1 (recommended)

1. Download and unpack the latest PyFirewall.zip from [here](https://github.com/EolnMsuk/PyFirewall/releases/latest).
2. Keep the project files in the same directory.
3. Right-click **`Install-PyFirewall.cmd`** and select **Run as administrator**.
4. Follow the prompts for any required components and startup options.
5. Complete the Npcap installer manually if it appears.
6. PyFirewall will launch after installation.

---

### Method 2 (advanced)

Manually find / download / install [Python 3.8+](https://www.python.org/downloads/windows/) with Tcl/Tk and pip, [Npcap](https://npcap.com/). Manually download the [PyFirewall.zip](https://github.com/EolnMsuk/PyFirewall/releases/latest), unpack it. Then run the following 2 commands (cmd/ps as admin) while in the unpacked directory:

```powershell
python -m pip install -r requirements.txt
```
```powershell
python firewall_monitor.py

```

## Usage

The main window can be closed but will remain in the system tray. Use **Close** from the tray menu to fully exit the application. The **Settings** tab controls alert thresholds, Auto-Block Protection, the connection/alert history limit, the UI theme, (auto) update checking, export / import rules, reset to defaults and uninstall option. When a threshold is exceeded, the connection is recorded in **Alerts**, triggering Auto-Block prompting, used for applications that pass the threshold (assuming they do not already have an application rule allowing or blocking it). Enabling **Filter All Connections** will set the threshold to 1, allowing you to live filter any new requests. Double-click a connection in **Live Monitor** or **Alerts** to edit its highest-priority applied rule. Double-click a rule in **Managed Rules** to edit that rule. Global rules accept comma-separated domains, IP addresses, CIDRs, and ranges such as `example.com, 192.168.1.1, 192.168.0.6-192.168.0.110`. Targets submitted together become one Managed Rules entry; existing independent rules stay separate. Right-click selected connections to use **Copy IP Domain** or **Copy Details** for every selected row. Managed Rules offers the same copy actions; application-only rules have no remote IP/domain to copy. **Windows Firewall** opens the Advanced Security console (`wf.msc`); select **Outbound Rules** in its left pane.

### Default Settings

| Setting | Default |
| --- | --- |
| Filter All Connections | Enabled |
| Connection threshold | 50 |
| Time window | 5 seconds |
| Upload threshold | 50 MB |
| Max Connections / Alerts | 250 |
| Alerts | Enabled |
| Auto-Block Protection | Enabled |
| Keep Notification in Foreground | Enabled |
| Dark theme | Enabled |
| Check for updates on startup | Enabled |

## Files

* `Install-PyFirewall.cmd` - administrator installer launcher
* `Uninstall-PyFirewall.cmd` - interactive uninstaller
* `firewall_monitor.py` - launch entry point, administrator elevation, and single-instance guard
* `app.py` - main window, shared state, startup, and UI event loop
* `widgets.py` - themes, button feedback, tooltips, custom menus, and table interactions
* `tray.py` - native Windows system-tray icon and menu
* `firewall.py` - firewall commands, rule transactions, verification, and profile recovery
* `settings.py` - settings persistence/UI, defaults, and support dialogs
* `monitoring.py` - packet capture, process attribution, DNS, and traffic accounting
* `auto_block.py` - temporary holds, cancellation, and Auto-Block decisions
* `views.py` - connection/rule/alert views, context actions, and import/export
* `updates.py` - release checking and update prompts
* `constants.py` - shared defaults, version, and resource paths
* `helpers.py` - normalization, formatting, and error diagnostics
* `requirements.txt` - Python dependencies
* `requirements.ps1` - automated prerequisite/setup script
* `PyFirewall.ico` - application and system-tray icon

PyFirewall stores its configuration in `firewall_config.json` beside the application.

## Troubleshooting

If double clicking the shortcut on the desktop does not open PyFirewall, right click the shortcut and select "Run as Administrator". For missing live traffic, verify that Npcap is installed and running and that PyFirewall is running with Administrator privileges. For unexpected errors, check `firewall_monitor_errors.log` beside the application for diagnostic details.

## Uninstallation

Run **`Uninstall-PyFirewall.cmd`** as administrator and answer each prompt with **Y** or **N**.

The uninstaller will prompt you to remove:

* PyFirewall-managed firewall rules
* Saved Windows Firewall profile settings
* The scheduled task
* Desktop shortcuts
* Python and packages
* Npcap

The installer records which Python components were installed by PyFirewall, preventing any 3rd party dependency issues.

## References

* [Python for Windows](https://www.python.org/downloads/windows/)
* [Npcap](https://npcap.com/)
* [Scapy Documentation](https://scapy.readthedocs.io/)

## Support Developer

[Venmo](https://venmo.com/u/rustonrails) | Bitcoin: `31uHLpioo1TbxAmo9kM7rrKcLz3wvcoZaL`
