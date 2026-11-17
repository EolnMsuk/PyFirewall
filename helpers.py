"""Address/path normalization, display formatting and error diagnostics."""

import ipaddress
import json
import os
import re
import threading
import time
import traceback

from constants import INTERNAL_ERROR_LOG_FILE

INTERNAL_ERROR_LOG_LOCK = threading.Lock()
ERROR_STATE_PROVIDER = None
DIAGNOSTIC_LOG_LIMIT = 1024 * 1024


def error_details(exc):
    details = [str(exc)]
    for field in ('stderr', 'stdout'):
        output = getattr(exc, field, None)
        if isinstance(output, bytes):
            output = output.decode('utf-8', errors='replace')
        if output and str(output).strip():
            details.append(f'{field}: {str(output).strip()}')
    return '\n'.join(details)


def rotate_diagnostic_log(path):
    """One previous generation; never use on a file held open by faulthandler."""
    if os.path.exists(path) and os.path.getsize(path) >= DIAGNOSTIC_LOG_LIMIT:
        os.replace(path, path + '.1')


def log_internal_error(context, exc, traceback_obj=None, *, outcome=None):
    acquired = False
    try:
        # An error handler must not itself strand Tk behind another logger.
        acquired = INTERNAL_ERROR_LOG_LOCK.acquire(timeout=0.05)
        if not acquired:
            return False
        rotate_diagnostic_log(INTERNAL_ERROR_LOG_FILE)
        state = ERROR_STATE_PROVIDER() if ERROR_STATE_PROVIDER is not None else ''
        if outcome is not None:
            state += '\nRule outcome: ' + json.dumps(outcome, ensure_ascii=True)[:16384]
        trace = ''.join(traceback.format_exception(type(exc), exc,
                        traceback_obj if traceback_obj is not None else exc.__traceback__, limit=40))
        with open(INTERNAL_ERROR_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write((f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {context}: {type(exc).__name__}: {error_details(exc)}\n"
                     + state + '\n' + trace)[:65536] + '\n\n')
        return True
    except Exception:
        return False
    finally:
        if acquired:
            INTERNAL_ERROR_LOG_LOCK.release()


def log_rule_lookup(outcome):
    """One bounded data record per attempt, in the existing rotated local log."""
    acquired = False
    try:
        acquired = INTERNAL_ERROR_LOG_LOCK.acquire(timeout=0.05)
        if not acquired:
            return False
        rotate_diagnostic_log(INTERNAL_ERROR_LOG_FILE)
        payload = dict(outcome)
        failures = list(payload.get('lookup_failures', ()))
        payload['lookup_failures'] = failures[:32]
        omitted = len(failures) - len(payload['lookup_failures'])
        while True:
            if omitted:
                payload['omitted_targets'] = omitted
            encoded = json.dumps(payload, ensure_ascii=True)
            if len(encoded) <= 8192 or not payload['lookup_failures']:
                break
            payload['lookup_failures'].pop()
            omitted += 1
        with open(INTERNAL_ERROR_LOG_FILE, 'a', encoding='utf-8') as output:
            output.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] global_rule_lookup: "
                         + encoded + '\n')
        return True
    except Exception:
        return False
    finally:
        if acquired:
            INTERNAL_ERROR_LOG_LOCK.release()


def normalize_path(path):
    if not path:
        return ''
    try:
        return os.path.normcase(os.path.normpath(str(path).replace('/', '\\')))
    except Exception:
        return str(path).lower()


def display_path(path):
    return os.path.normpath(str(path).replace('/', '\\')) if path else ''


def rule_executables(rule, validate=True):
    """Read the current executable selection without parsing display-name CSVs."""
    if 'exe' in rule:
        raise ValueError('Global rules require an exes array.')
    values = rule.get('exes', [])
    if not isinstance(values, list):
        raise ValueError('Global rule executables must be an array of paths.')
    paths, seen = [], set()
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError('Select an absolute executable (.exe) path, or leave it blank for all processes.')
        path = display_path(value.strip())
        # A rooted path without a drive is not a fully qualified Windows path.
        drive, tail = os.path.splitdrive(path)
        if validate and (not drive or not tail.startswith('\\') or not path.lower().endswith('.exe')):
            raise ValueError('Select an absolute executable (.exe) path, or leave it blank for all processes.')
        key = normalize_path(path)
        if key not in seen:
            seen.add(key)
            paths.append(path)
    return paths


def executable_fields(paths):
    """Use one representation for every executable selection."""
    return {'exes': list(paths)}


def executable_identity(rule):
    return tuple(sorted(normalize_path(path) for path in rule_executables(rule)))


def normalize_target(target):
    value = str(target or '').strip()
    if ',' in value:
        return ', '.join(dict.fromkeys(normalize_target(part) for part in value.split(',')))
    value = value.casefold().rstrip('.')
    if value.startswith('[') and value.endswith(']') and value.count('[') == 1:
        value = value[1:-1]
    elif value.startswith('[') and ']/' in value:
        value = value.replace(']/', '/', 1)[1:]
    try:
        start, end = ip_range(value)
        return f'{start}-{end}'
    except ValueError:
        pass
    try:
        network, = address_networks(value)
        return str(network) if '/' in value else str(network.network_address)
    except ValueError:
        return value


def _ip_component(value):
    """Reject DNS/display text and oversized literals before the numeric parser."""
    value = value.strip()
    if value.startswith('[') and value.endswith(']'):
        value = value[1:-1]
    if (not value or len(value) > 45 or not re.fullmatch(r'[0-9a-fA-F:.]+', value)
            or not (':' in value or '.' in value)):
        raise ValueError('Expected a numeric IP address (at most 45 characters).')
    if ':' not in value and not re.fullmatch(r'[0-9]{1,3}(?:\.[0-9]{1,3}){3}', value):
        raise ValueError('Expected a numeric IPv4 address.')
    return value


def ip_range(value):
    """Parse an inclusive native firewall range without expanding its addresses."""
    if not isinstance(value, str):
        raise ValueError('Expected an IP range.')
    parts = value.split('-')
    if len(parts) != 2:
        raise ValueError('Expected an IP range.')
    start, end = (ipaddress.ip_address(_ip_component(part)) for part in parts)
    if start.version != end.version or int(start) > int(end):
        raise ValueError('IP ranges must use one address family and ascending endpoints.')
    return start, end


def address_networks(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError('Expected a numeric address filter.')
    value = value.strip()
    if '-' in value:
        return tuple(ipaddress.summarize_address_range(*ip_range(value)))
    parts = value.split('/')
    if len(parts) > 2:
        raise ValueError('Invalid IP prefix.')
    address = _ip_component(parts[0])
    if len(parts) == 2:
        prefix = parts[1]
        if not (re.fullmatch(r'[0-9]{1,3}', prefix) or
                ':' not in address and re.fullmatch(r'[0-9.]{7,15}', prefix)):
            raise ValueError('Invalid IP prefix.')
        address += '/' + prefix
    return (ipaddress.ip_network(address, strict=False),)


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
    if ':' in value or '/' in value or re.fullmatch(r'[0-9.]+', value) or ('-' in value and re.match(r'^\d+(?:\.\d+){3}\s*-', value)):
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


def normalize_ports(value):
    """Parse editor text or a current port array into one normalized selection."""
    if value is None or isinstance(value, str) and not value.strip():
        return []
    parts = value if isinstance(value, list) else [part.strip() for part in str(value).split(',')]
    parts = [str(part) for part in parts]
    if any(not part.isdecimal() or not 1 <= int(part) <= 65535 for part in parts):
        raise ValueError('Port numbers must be integers from 1 to 65535, separated by commas.')
    ports = sorted({int(part) for part in parts})
    return ports


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
