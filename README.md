# PyFirewall

**Python Personal Firewall & Network Monitor for Windows**

PyFirewall is a Windows desktop application for monitoring network connections and managing Windows Defender Firewall rules. **This firewall is process and IP specific, meaning it monitors and blocks both incoming and outgoing connections.** It uses Tkinter for the interface, Scapy for packet capture, psutil for process/network information, and supports application and global IP/domain rules.

## Features

- Live network connection monitoring
- Active connection view
- Per-application allow/block rules
- Global IP/domain allow and block rules
- Connection-rate and upload-threshold alerts
- Optional Auto-Block Protection
- Configurable connection/alert history limit
- CSV export for connection data
- JSON export/import for managed firewall rules
- System-tray support and automatic start at Windows login
- Dark/light theme support

## Requirements

- Windows 10 or Windows 11
- Administrator privileges
- Python 3.8+ with Tkinter and pip
- Npcap
- Python packages listed in `requirements.txt`

## Installation

### Recommended

1. Keep the project files in the same directory.
2. Right-click **`Install-PyFirewall.cmd`** and select **Run as administrator**.
3. Complete the Npcap installer if it appears.
4. PyFirewall will launch automatically after installation.

The installer can install/configure Python, Python dependencies, Npcap, Windows Firewall requirements, a desktop shortcut, and a scheduled task for starting PyFirewall at login.

### Manual

Install Python 3.8+ with Tcl/Tk and pip, install Npcap, then run:

```powershell
python -m pip install -r requirements.txt
python firewall_monitor.py
```

## Usage

PyFirewall requests Administrator elevation when necessary.

The main window can be minimized to the system tray. Use **Close** from the tray menu to fully exit the application.

The **Settings** tab controls alert thresholds, Auto-Block Protection, the maximum number of retained Live Monitor/Alerts rows, and the UI theme.

Default settings include:

| Setting | Default |
|---|---:|
| Connection threshold | 50 |
| Time window | 5 seconds |
| Upload threshold | 50 MB |
| Max Connections / Alerts | 250 |
| Alerts | Enabled |
| Auto-Block Protection | Enabled |
| Dark theme | Enabled |

## Important Firewall Behavior

PyFirewall manages rules whose names begin with `PyFirewall_`.

On first firewall initialization, the application intentionally sets the Windows Firewall profile defaults to **Allow**, then restores/applies the PyFirewall-managed rules saved in `firewall_config.json`.

Review this behavior before using PyFirewall on a production system.

## Known Issues

- At first launch OR when all rules are removed, a Windows Security notification will prompt the user to enable Windows Defender Firewall even though its enabled. This is caused by the lack of any firewall rules currently assigned.

## Files

- `firewall_monitor.py` — main application
- `requirements.txt` — Python dependencies
- `requirements.ps1` — automated prerequisite/setup script
- `Install-PyFirewall.cmd` — administrator installer launcher
- `Uninstall-PyFirewall.cmd` — interactive uninstaller

PyFirewall stores its configuration in `firewall_config.json` beside the application when needed.

## Uninstallation

Run **`Uninstall-PyFirewall.cmd`** as administrator and answer each prompt with **Y** or **N**.

The uninstaller can remove PyFirewall-managed firewall rules, the scheduled task, desktop shortcut, Npcap, and the detected Python 3.14.7 installation/dependencies. Python and Npcap are presented as separate choices.

Review each prompt carefully because Python or Npcap may also be used by other software.

## Troubleshooting

For missing live traffic, verify that Npcap is installed/running and that PyFirewall is running with Administrator privileges.

## References

- [Python for Windows](https://www.python.org/downloads/windows/)
- [Npcap](https://npcap.com/)
- [Scapy Documentation](https://scapy.readthedocs.io/)

## Donations

- [Venmo](https://venmo.com/u/rustonrails/)
