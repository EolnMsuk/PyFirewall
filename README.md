# PyFirewall ⛨

**Python Personal Firewall & Network Monitor for Windows**

PyFirewall is a Windows desktop application for monitoring network connections and managing Windows Defender Firewall rules. **It monitors and blocks both incoming and outgoing connections** using process- and IP-specific rules. It uses Tkinter for the interface, Scapy for packet capture, psutil for process and network information, and supports application and global IP/domain rules.

---

<img width="1200" height="1893" alt="example" src="https://github.com/user-attachments/assets/ecb3ffdd-dda0-4e74-ae04-95613a0f2245" />

---

## Features

- Live network connection monitoring
- Active connection view
- Auto-Block Protection
- Filter All Connections
- Per-application allow/block rules
- Global IP/domain allow and block rules
- IPv4 and IPv6 address and CIDR support
- Connection-rate and upload-threshold alerts
- Configurable connection and alert history limit
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
3. Follow the prompts for any required components and startup options.
4. Complete the Npcap installer manually if it appears.
5. PyFirewall will launch after installation.

The installer offers to install and/or configure Python, Python packages, Npcap, Windows Firewall requirements, a desktop shortcut, and a scheduled task for starting PyFirewall at login.

### Manual

Install Python 3.8+ with Tcl/Tk and pip, install Npcap, then run:

```powershell
python -m pip install -r requirements.txt
python firewall_monitor.py
```

## Usage

The main window can be closed but will remain in the system tray. Use **Close** from the tray menu to fully exit the application. The **Settings** tab controls alert thresholds, Auto-Block Protection, the connection/alert history limit, and the UI theme. When a threshold is exceeded, the connection is recorded in **Alerts**. Auto-Block prompting is used for applications that do not already have an application rule.

### Default Settings

| Setting | Default |
|---|---:|
| Filter All Connections | Enabled |
| Connection threshold | 50 |
| Time window | 5 seconds |
| Upload threshold | 50 MB |
| Max Connections / Alerts | 250 |
| Alerts | Enabled |
| Auto-Block Protection | Enabled |
| Dark theme | Enabled |

## Important Firewall Behavior

On first firewall initialization, PyFirewall saves the existing Windows Firewall profile settings. The saved firewall profile settings will be restored during uninstallation.

## Known Issues

- At first launch or when all managed firewall rules are removed, Windows will display a notification to enable Windows Defender Firewall.

## Files

- `firewall_monitor.py` — main application
- `requirements.txt` — Python dependencies
- `requirements.ps1` — automated prerequisite/setup script
- `Install-PyFirewall.cmd` — administrator installer launcher
- `Uninstall-PyFirewall.cmd` — interactive uninstaller
- `PyFirewall.ico` — application and system-tray icon

PyFirewall stores its configuration in `firewall_config.json` beside the application when needed.

## Uninstallation

Run **`Uninstall-PyFirewall.cmd`** as administrator and answer each prompt with **Y** or **N**.

The uninstaller will prompt you to remove:

- PyFirewall-managed firewall rules
- Saved Windows Firewall profile settings
- The scheduled task
- Desktop shortcuts
- PyFirewall-installed Python and packages
- Npcap

The installer records which Python components were installed by PyFirewall so shared or pre-existing installations can be kept. Review each prompt carefully because Python or Npcap may also be used by other software.

## Troubleshooting

For missing live traffic, verify that Npcap is installed and running and that PyFirewall is running with Administrator privileges. For repeated Auto-Block prompts, verify that the application does not already have an Allow or Block rule.

## References

- [Python for Windows](https://www.python.org/downloads/windows/)
- [Npcap](https://npcap.com/)
- [Scapy Documentation](https://scapy.readthedocs.io/)

## Donations

- [Venmo](https://venmo.com/u/rustonrails/)
- [Bitcoin](https://www.blockchain.com/explorer/addresses/btc/31uHLpioo1TbxAmo9kM7rrKcLz3wvcoZaL)
