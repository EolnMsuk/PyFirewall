# PyFirewall ⛨

**Python Personal Firewall & Network Monitor for Windows**

PyFirewall is a Windows desktop application for monitoring network connections and managing Windows Defender Firewall rules. **It monitors and blocks both incoming and outgoing connections** using process and IP/domain specific rules. It uses Tkinter for the interface, Scapy for packet capture, psutil for process and network information, and supports application and global IP/domain rules.

---

<img width="1554" height="2591" alt="example" src="https://github.com/user-attachments/assets/d96e82fb-4829-4a1a-9c48-93529336c776" />

---

## Features

- Live network connection monitoring
- Auto-Block Protection
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

### Method 1 (recommended)

1. Download and unpack the latest PyFirewall.zip from [here](https://github.com/EolnMsuk/PyFirewall/releases).
2. Keep the project files in the same directory.
3. Right-click **`Install-PyFirewall.cmd`** and select **Run as administrator**.
4. Follow the prompts for any required components and startup options.
5. Complete the Npcap installer manually if it appears.
6. PyFirewall will launch after installation.

---

### Method 2 (advanced)

Manually download the PyFirewall.zip, unpack it. Manually find / download / install Python 3.8+ with Tcl/Tk and pip, Npcap, then run the following 2 commands while in the unpacked directory:

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

On each launch, PyFirewall saves the existing Windows Firewall profile settings, enables the profiles, and sets their default inbound and outbound actions to Allow while its managed rules are active. On a normal exit, it restores the saved profile settings. If a session is interrupted, the retained backup is restored before the next session is initialized. Restoration failures are reported and the backup is retained for recovery. The uninstaller can also restore a retained backup.

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

For missing live traffic, verify that Npcap is installed and running and that PyFirewall is running with Administrator privileges. For repeated Auto-Block prompts, verify that the application does not already have an Allow or Block rule. For unexpected errors, check `firewall_monitor_errors.log` beside the application for diagnostic details.

## References

- [Python for Windows](https://www.python.org/downloads/windows/)
- [Npcap](https://npcap.com/)
- [Scapy Documentation](https://scapy.readthedocs.io/)

## Support Developer

[Venmo](https://venmo.com/u/rustonrails) | Bitcoin: `31uHLpioo1TbxAmo9kM7rrKcLz3wvcoZaL`
