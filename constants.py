"""Shared defaults and installation-relative resource paths."""

import os

__version__ = "2.6"
LATEST_RELEASE_API = 'https://api.github.com/repos/EolnMsuk/PyFirewall/releases/latest'
LATEST_RELEASE_PAGE = 'https://github.com/EolnMsuk/PyFirewall/releases/latest'
DEFAULT_CHECK_UPDATES_ON_STARTUP = True
DEFAULT_RATE_THRESHOLD = 50
DEFAULT_RATE_WINDOW = 5.0
DEFAULT_UPLOAD_THRESHOLD_MB = 50
DEFAULT_LOG_ALERTS_ONLY = True
DEFAULT_DARK_MODE = True
DEFAULT_MAX_CONNECTIONS_ALERTS = 250
CREATE_NO_WINDOW = 134217728
WATCH_PORTS = {23: 'Telnet', 445: 'SMB', 3389: 'RDP', 4444: 'Common remote-control port', 5555: 'Android Debug Bridge', 5900: 'VNC', 6667: 'IRC'}
GLOBAL_BLOCK_PREFIX = 'PyFirewall_GlobalIP_'
GLOBAL_ALLOW_PREFIX = 'PyFirewall_GlobalIPAllow_'
GLOBAL_PORT_PREFIX = 'PyFirewall_GlobalPort_'
GLOBAL_PURPLE = '#ad79cf'
GLOBAL_TEAL = '#35b6ac'
GLOBAL_YELLOW = '#b5a126'
CRYPTO_WALLETS = (
    ('BTC (Bitcoin Network)', '31uHLpioo1TbxAmo9kM7rrKcLz3wvcoZaL'),
    ('LTC (Litecoin Network)', 'MNWMWwueZBoQSd7Ms9meQ1cMfeY16BA7E1'),
    ('ETH (Ethereum Network)', '0x6060BEA4305BC4259bcF1db5eDbe756b7b74a895'),
    ('USDT (Ethereum Network)', '0x17f0c9d7229E9A1Ad1cAccbfEe7979CF39F2301F'),
    ('RNDR / ERC-20 (Ethereum Network)', '0x9cc3fCc3b41a31cDC07E33930F1d622c3ed690E9'),
    ('USDC (Ethereum Network)', '0xD69Dc2a18e64E071d096435dD6f9DdD52B10785c'),
    ('SOL (Solana Network)', 'H2ydj95396KRErC4nMtK5B2BAjobPTyUh7LpYBFSmFnP'),
    ('BNB (BNB Smart Chain Network)', '0x314148b89744663ad9F1Fb8EA6862a62abf2fC93'),
)
AUTO_HOLD_PREFIX = 'PyFirewall_AutoHold_'
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, 'firewall_config.json')
ICON_FILE = os.path.join(SCRIPT_DIR, 'PyFirewall.ico')
FIREWALL_PROFILE_BACKUP_FILE = os.path.join(SCRIPT_DIR, 'firewall_profile_backup.json')
DNS_MAX_WORKERS = 8
DNS_MAX_PENDING = 256
DNS_CACHE_MAX_ENTRIES = 2048
DNS_CACHE_TTL = 900.0
FIREWALL_COMMAND_TIMEOUT = 30.0
TRAFFIC_MAX_IP_ENTRIES = 8192
TRAFFIC_MAX_PROC_IP_ENTRIES = 16384
TRAFFIC_PRUNE_INTERVAL = 30.0
INTERNAL_ERROR_LOG_FILE = os.path.join(SCRIPT_DIR, 'firewall_monitor_errors.log')
