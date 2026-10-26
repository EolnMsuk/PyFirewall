"""Address/path normalization, display formatting and error diagnostics."""

import ipaddress
import os
import re
import threading
import time
import traceback

from constants import INTERNAL_ERROR_LOG_FILE

INTERNAL_ERROR_LOG_LOCK = threading.Lock()


def error_details(exc):
    details = [str(exc)]
    for field in ('stderr', 'stdout'):
        output = getattr(exc, field, None)
        if isinstance(output, bytes):
            output = output.decode('utf-8', errors='replace')
        if output and str(output).strip():
            details.append(f'{field}: {str(output).strip()}')
    return '\n'.join(details)


def log_internal_error(context, exc):
    try:
        with INTERNAL_ERROR_LOG_LOCK:
            with open(INTERNAL_ERROR_LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {context}: {type(exc).__name__}: {error_details(exc)}\n")
                traceback.print_exception(type(exc), exc, exc.__traceback__, file=f)
                f.write('\n')
    except Exception:
        pass


def normalize_path(path):
    if not path:
        return ''
    try:
        return os.path.normcase(os.path.normpath(str(path).replace('/', '\\')))
    except Exception:
        return str(path).lower()


def display_path(path):
    return os.path.normpath(str(path).replace('/', '\\')) if path else ''


def normalize_target(target):
    value = str(target or '').strip()
    if ',' in value:
        return ', '.join(dict.fromkeys(normalize_target(part) for part in value.split(',')))
    value = value.strip('[]').casefold().rstrip('.')
    try:
        start, end = ip_range(value)
        return f'{start}-{end}'
    except ValueError:
        pass
    try:
        return str(ipaddress.ip_network(value, strict=False)) if '/' in value else str(ipaddress.ip_address(value))
    except ValueError:
        return value


def ip_range(value):
    """Parse an inclusive native firewall range without expanding its addresses."""
    parts = str(value).split('-')
    if len(parts) != 2:
        raise ValueError('Expected an IP range.')
    start, end = (ipaddress.ip_address(part.strip().strip('[]')) for part in parts)
    if start.version != end.version or int(start) > int(end):
        raise ValueError('IP ranges must use one address family and ascending endpoints.')
    return start, end


def address_networks(value):
    try:
        return tuple(ipaddress.summarize_address_range(*ip_range(value)))
    except ValueError:
        return (ipaddress.ip_network(value, strict=False),)


def normalize_address(value):
    """Validate firewall address filters; hostnames are never accepted here."""
    value = normalize_target(value)
    address_networks(value)
    return value


def global_targets(value):
    targets = list(dict.fromkeys(normalize_target(part) for part in str(value).split(',')))
    if not all(is_global_target(part) for part in targets):
        raise ValueError('Enter valid domains, IP addresses, CIDRs or ascending IP ranges.')
    return targets


def is_ip(target):
    try:
        address_networks(normalize_target(str(target).split(' (', 1)[0]))
        return True
    except ValueError:
        return False


def is_global_target(target):
    """Validate addresses/hostnames without ever sending application paths to DNS."""
    value = normalize_target(target)
    if value in {'', '\u2014', '-'}:
        return False
    try:
        address_networks(value)
        return True
    except ValueError:
        pass
    if '-' in value and (':' in value or re.match(r'^\d+(?:\.\d+){3}\s*-', value)):
        # Do not mistake malformed/reversed numeric ranges for DNS hostnames.
        return False
    try:
        hostname = value.encode('idna').decode('ascii')
    except UnicodeError:
        return False
    return bool(hostname and len(hostname) <= 253 and
                all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                    for part in hostname.split('.')))


def mb(value):
    return f'{value / (1024 * 1024):.2f} MB'


def direction_name(value):
    value = str(value or '').casefold()
    if value in {'in', 'inbound', 'incoming'}:
        return 'Inbound'
    if value in {'out', 'outbound', 'outgoing'}:
        return 'Outbound'
    return 'Both'


def direction_set(value):
    value = direction_name(value)
    return {'in'} if value == 'Inbound' else {'out'} if value == 'Outbound' else {'in', 'out'}
