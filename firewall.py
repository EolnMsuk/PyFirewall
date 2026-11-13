"""Windows Firewall commands, managed rules, verification and recovery."""

import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import queue
import threading
import copy
from tkinter import messagebox

from constants import (
    AUTO_HOLD_PREFIX,
    CREATE_NO_WINDOW,
    FIREWALL_COMMAND_TIMEOUT,
    FIREWALL_PROFILE_BACKUP_FILE,
    GLOBAL_PORT_PREFIX,
)
from helpers import (
    address_networks,
    global_targets,
    ip_range,
    normalize_address,
    direction_name,
    direction_set,
    display_path,
    executable_fields,
    executable_identity,
    error_details,
    is_global_target,
    is_ip,
    log_internal_error,
    normalize_path,
    normalize_ports,
    normalize_target,
    rule_executables,
)

class FirewallMixin:
    """Methods composed into FirewallMonitorApp; state is owned by that application."""

    @staticmethod
    def _direction_from_flags(data):
        return 'Both' if data['in'] and data['out'] else 'Inbound' if data['in'] else 'Outbound'

    # Command execution and verified transactions

    def _start_native_worker(self):
        self.native_jobs = queue.Queue(maxsize=128)
        self.native_job_keys = set()
        self.native_shutdown_requested = False
        self.native_worker = threading.Thread(target=self._native_worker, daemon=True,
                                               name='PyFirewall-Native')
        self.native_worker.start()

    def _native_ui_call(self):
        return (hasattr(self, 'native_jobs') and
                threading.get_ident() == self.ui_thread_id)

    def _queue_native_job(self, label, operation, key=None):
        """Bound discardable requests; cleanup and shutdown use retained state."""
        with self.lock:
            if self.closed or getattr(self, 'native_shutdown_requested', False):
                return False
            if key is not None and key in self.native_job_keys:
                return True
            try:
                self.native_jobs.put_nowait((label, operation, key))
            except queue.Full:
                self.queue_alert('High', 'Native work queue', '', '',
                                 f'{label} was not queued: the worker is busy. Please retry.')
                return False
            if key is not None:
                self.native_job_keys.add(key)
        return True

    def _native_worker(self):
        while True:
            if self.native_shutdown_requested:
                self._shutdown_worker()
                return
            # Retired holds are durable cleanup obligations, not queue events.
            if getattr(self, 'auto_hold_cleanup', {}):
                self._release_auto_holds_for_generation(None)
            try:
                label, operation, key = self.native_jobs.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                if not self.native_shutdown_requested:
                    with self.firewall_lock:
                        with self.lock:
                            self.native_operation_label = label
                        operation()
            except Exception as exc:
                log_internal_error('native_worker', exc)
                self.queue_alert('High', label, '', '', str(exc))
                self._native_message('showerror', label, str(exc))
            finally:
                with self.lock:
                    self.native_operation_label = None
                    self.native_job_keys.discard(key)
                self.native_jobs.task_done()

    def _native_message(self, method, title, text, **options):
        if threading.get_ident() != getattr(self, 'ui_thread_id', threading.main_thread().ident):
            self.ui_queue.put(('message', method, title, text))
        else:
            getattr(messagebox, method)(title, text, **options)

    def _run(self, args, check=True, timeout=None):
        return subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=check,
            creationflags=CREATE_NO_WINDOW,
            timeout=FIREWALL_COMMAND_TIMEOUT if timeout is None else timeout,
        )

    def run_ps(self, command, check=True, timeout=None):
        args = ('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass')
        options = {} if timeout is None else {'timeout': timeout}
        # Large imports exceed Windows' command-line limit. A BOM also preserves
        # Unicode paths when Windows PowerShell 5.1 reads the temporary script.
        if len(command.encode('utf-16-le')) > 16000:
            with tempfile.TemporaryDirectory(prefix='pyfirewall-') as directory:
                path = os.path.join(directory, 'rules.ps1')
                with open(path, 'w', encoding='utf-8-sig') as script:
                    script.write(command)
                return self._run((*args, '-File', path), check, **options)
        return self._run((*args, '-Command', command), check, **options)

    def run_netsh(self, args, check=True):
        return self._run(('netsh', 'advfirewall', 'firewall', *args), check)

    def delete_rule_names(self, names, strict=True):
        names = sorted(set(n for n in names if n))
        if not names:
            return False
        command = "$ErrorActionPreference='Stop'\n$names=@(" + ','.join(self._ps_quote(n) for n in names) + ")\n"
        command += '''
$existing = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.DisplayName -in $names })
if ($existing.Count) { $existing | Remove-NetFirewallRule -ErrorAction Stop }
$remaining = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.DisplayName -in $names })
if ($remaining.Count) { throw ('Firewall rules could not be removed: ' + ($remaining.DisplayName -join ', ')) }
if ($existing.Count) { 'removed' } else { 'absent' }
'''
        try:
            output = self.run_ps(command).stdout.strip()
            if output not in {'removed', 'absent'}:
                raise RuntimeError('Invalid firewall deletion result.')
            return output == 'removed'
        except Exception:
            return self._delete_rule_names_individually(names, strict)

    def _delete_rule_names_individually(self, names, strict=True):
        names = set(n for n in names if n)
        if not names:
            return False
        existing = {r['name'] for r in self.get_firewall_rules()}
        for name in names & existing:
            try:
                self.run_netsh(['delete', 'rule', f'name={name}'])
            except (subprocess.SubprocessError, OSError):
                pass
        remaining = names & {r['name'] for r in self.get_firewall_rules()}
        if remaining:
            raise RuntimeError('Firewall rules could not be removed: ' + ', '.join(sorted(remaining)))
        return bool(names & existing)

    def _replace_rule_records(self, previous, desired_names, apply, apply_first=False, preserve_holds=False, commit=None):
        names = {r['name'] for r in previous} | set(desired_names)
        try:
            if preserve_holds:
                self.delete_rule_names(r['name'] for r in previous if not r.get('is_hold'))
                apply()
                self.delete_rule_names(r['name'] for r in previous if r.get('is_hold'))
            elif apply_first:
                apply()
                self.delete_rule_names(r['name'] for r in previous)
            else:
                self.delete_rule_names(r['name'] for r in previous)
                apply()
            if commit is not None:
                commit()
        except Exception as error:
            cleanup_error = None
            try:
                self.delete_rule_names(names)
            except Exception as exc:
                cleanup_error = exc
            try:
                remaining = {r['name'] for r in self.get_firewall_rules()}
                self._restore_app_rule_records([r for r in previous if r['name'] not in remaining])
                if cleanup_error:
                    raise cleanup_error
            except Exception as rollback_error:
                try:
                    self.sync_rule_cache()
                    self._save_settings_with_feedback()
                except Exception as reconcile_error:
                    log_internal_error('rule_reconciliation', reconcile_error)
                raise RuntimeError(f'Rule update failed: {error}; rollback failed: {rollback_error}') from rollback_error
            raise

    # Rule discovery, identities and port policies

    def get_firewall_rules(self):
        command = '''
$rules = Get-NetFirewallRule -ErrorAction Stop |
  Where-Object {$_.DisplayName -like "PyFirewall_*"} |
  ForEach-Object {
    $r = $_
    $a = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction Stop |
      Select-Object -First 1
    $p = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction Stop | Select-Object -First 1
    $address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction Stop
    [PSCustomObject]@{
      DisplayName=[string]$r.DisplayName
      Action=[string]$r.Action
      Direction=[string]$r.Direction
      Enabled=[string]$r.Enabled
      Profile=[string]$r.Profile
      Addresses=@($address.RemoteAddress)
      LocalAddresses=@($address.LocalAddress)
      Program=if($null -ne $a){[string]$a.Program}else{""}
      Protocol=if($p){[string]$p.Protocol}else{""}
      LocalPorts=@(if($p){$p.LocalPort})
      RemotePorts=@(if($p){$p.RemotePort})
    }
  }
if($null -eq $rules){"[]"}else{@($rules)|ConvertTo-Json -Compress}
'''
        output = self.run_ps(command).stdout.strip()
        if not output:
            return []
        try:
            raw = json.loads(output)
        except (json.JSONDecodeError, TypeError) as exc:
            raise RuntimeError(f'Windows Firewall returned invalid rule data: {exc}') from exc
        if isinstance(raw, dict):
            raw = [raw]
        if not isinstance(raw, list):
            raise RuntimeError('Windows Firewall returned an unexpected rule-data format.')
        records = []
        for item in raw:
            if not isinstance(item, dict):
                raise RuntimeError('Windows Firewall returned an invalid rule record.')
            if not str(item.get('DisplayName', '') or '').strip():
                raise RuntimeError('Windows Firewall returned a rule without a display name.')
            if 'Action' not in item or 'Direction' not in item:
                raise RuntimeError('Windows Firewall returned incomplete rule metadata.')
            name = str(item.get('DisplayName', '') or '')
            global_rule = name.startswith(GLOBAL_PORT_PREFIX + '4_1_')
            records.append({'name': name, 'action': str(item.get('Action', '') or ''), 'direction': str(item.get('Direction', '') or ''), 'path': '' if global_rule else display_path(item.get('Program', '')), 'normalized_path': '' if global_rule else normalize_path(item.get('Program', '')), 'is_global': global_rule, 'is_hold': name.startswith(AUTO_HOLD_PREFIX), 'addresses': item.get('Addresses', [])})
            records[-1].update(enabled=str(item.get('Enabled', '')).casefold() == 'true',
                               profile=item.get('Profile', 'Any'), local_addresses=item.get('LocalAddresses', ['Any']),
                               program=display_path(item.get('Program', '')),
                               protocol=item.get('Protocol', ''), local_ports=item.get('LocalPorts', []),
                               remote_ports=item.get('RemotePorts', []))
            if name.startswith(GLOBAL_PORT_PREFIX + '4_1_'):
                records[-1].update(is_port=True, protocol=item.get('Protocol', ''),
                                   path=display_path(item.get('Program', '')) if item.get('Program') not in ('Any', '', None) else '',
                                   local_ports=item.get('LocalPorts', []), remote_ports=item.get('RemotePorts', []))
        return records

    def app_rule_base(self, proc_name, exe_path, kind='Block'):
        base = re.sub('[^A-Za-z0-9_.-]+', '_', os.path.splitext(os.path.basename(exe_path))[0] or proc_name or 'Process')[:60]
        digest = hashlib.sha1(normalize_path(exe_path).encode('utf-8', 'ignore')).hexdigest()[:8]
        return f'PyFirewall_{kind}_{base}_{digest}'

    @staticmethod
    def _policy_key(rule):
        identity = {key: rule[key] for key in ('action', 'direction', 'protocol', 'ports')}
        identity['exes'] = executable_identity(rule)
        identity['targets'] = sorted(item['target'] for item in rule['targets'])
        return 'global:' + hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:32]

    @staticmethod
    def _parse_port_rules(entries):
        """Validate the whole 4.1 selection; old and mixed policies are errors."""
        if not isinstance(entries, list):
            raise ValueError('Global rules must be a JSON array.')
        result = {}
        fields = {'action', 'direction', 'protocol', 'exes', 'targets', 'ports'}
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != fields:
                raise ValueError('Global rules require the clean PyFirewall 4.1 format. Older or mixed rules cannot be imported.')
            if not isinstance(entry['action'], str) or entry['action'] not in {'Allow', 'Block'}:
                raise ValueError('A global rule requires Allow or Block.')
            if not isinstance(entry['direction'], str) or entry['direction'] not in {'Both', 'Inbound', 'Outbound'}:
                raise ValueError('A global rule requires Both, Inbound or Outbound.')
            if not isinstance(entry['protocol'], str) or entry['protocol'] not in {'TCP/UDP', 'TCP', 'UDP', 'Any'}:
                raise ValueError('Invalid global rule protocol.')
            if not isinstance(entry['ports'], list) or any(type(port) is not int or not 1 <= port <= 65535 for port in entry['ports']):
                raise ValueError('Global remote ports must be an array of integers from 1 through 65535.')
            if entry['protocol'] == 'Any' and entry['ports']:
                raise ValueError('Remote ports require TCP or UDP.')
            rule = {key: entry[key] for key in ('action', 'direction', 'protocol')}
            rule['exes'] = sorted(rule_executables(entry), key=normalize_path)
            rule['ports'] = sorted(set(entry['ports']))
            if not isinstance(entry['targets'], list):
                raise ValueError('Global targets must be an array.')
            targets = {}
            for item in entry['targets']:
                if not isinstance(item, dict) or set(item) != {'target', 'addresses'} or not isinstance(item['target'], str):
                    raise ValueError('Each target requires a target and its own addresses array.')
                target = normalize_target(item['target'])
                if ',' in target or not is_global_target(target):
                    raise ValueError('Invalid global target.')
                if not isinstance(item['addresses'], list) or not all(isinstance(value, str) for value in item['addresses']):
                    raise ValueError('Target addresses must be an array of numeric address filters.')
                addresses = {normalize_address(value) for value in item['addresses']}
                if is_ip(target):
                    # A numeric target never borrows another target's coverage.
                    if addresses and addresses != {normalize_address(target)}:
                        raise ValueError('Numeric target addresses must match their target.')
                    addresses = {normalize_address(target)}
                targets.setdefault(target, set()).update(addresses)
            numeric = FirewallMixin._coverage(target for target in targets if is_ip(target))
            domains = {target: addresses for target, addresses in targets.items() if not is_ip(target)}
            if {str(network) for network in numeric} == {'0.0.0.0/0', '::/0'}:
                targets = {}
            else:
                targets = dict(domains)
                for network in numeric:
                    target = str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)
                    targets[target] = {target}
            rule['targets'] = [{'target': target, 'addresses': sorted(addresses)} for target, addresses in sorted(targets.items())]
            key = FirewallMixin._policy_key(rule)
            if key in result:
                saved = {item['target']: item['addresses'] for item in result[key]['targets']}
                for item in rule['targets']:
                    item['addresses'] = sorted(set(item['addresses']) | set(saved[item['target']]))
            result[key] = rule
        return result

    @staticmethod
    def _rule_addresses(rule):
        return sorted({address for target in rule['targets'] for address in target['addresses']}) if rule['targets'] else ['Any']

    @staticmethod
    def _port_firewall_rules(ports, all_directions=False):
        """Keep native fan-out and the compatible 4_1 native-name format."""
        rules = []
        for key, rule in ports.items():
            digest = hashlib.sha256(key.encode()).hexdigest()[:32]
            protocols = (('TCP', 6), ('UDP', 17)) if rule['protocol'] == 'TCP/UDP' else ((rule['protocol'], {'TCP': 6, 'UDP': 17, 'Any': 256}[rule['protocol']]),)
            directions = ('Inbound', 'Outbound') if all_directions else tuple(side for side in ('Inbound', 'Outbound') if direction_set(side) <= direction_set(rule['direction']))
            for path in rule_executables(rule) or ['']:
                program = hashlib.sha256(normalize_path(path).encode()).hexdigest()[:16]
                for protocol, number in protocols:
                    for direction in directions:
                        rules.append({'name': f'{GLOBAL_PORT_PREFIX}4_1_{digest}_{program}_{number}_{direction}',
                                      'action': rule['action'], 'direction': direction, 'path': path, 'is_port': True,
                                      'protocol': protocol, 'addresses': FirewallMixin._rule_addresses(rule),
                                      'local_ports': ['Any'], 'remote_ports': [str(port) for port in rule['ports']] or ['Any']})
        return rules

    @staticmethod
    def _coverage(values):
        networks = [network for value in values for network in address_networks(value)]
        return tuple(network for version in (4, 6) for network in ipaddress.collapse_addresses(n for n in networks if n.version == version))

    @classmethod
    def _address_subset(cls, first, second):
        if not second['targets']:
            return True
        if not first['targets']:
            numeric = cls._coverage(item['target'] for item in second['targets'] if is_ip(item['target']))
            return {str(network) for network in numeric} == {'0.0.0.0/0', '::/0'}
        # Domains retain their identities: today's DNS answer is not a promise
        # that two domains will keep the same coverage tomorrow.
        first_domains = {item['target'] for item in first['targets'] if not is_ip(item['target'])}
        second_domains = {item['target'] for item in second['targets'] if not is_ip(item['target'])}
        if not first_domains <= second_domains:
            return False
        first_numeric = cls._coverage(item['target'] for item in first['targets'] if is_ip(item['target']))
        second_numeric = cls._coverage(item['target'] for item in second['targets'] if is_ip(item['target']))
        if any(not any(net.version == other.version and net.subnet_of(other) for other in second_numeric) for net in first_numeric):
            return False
        coverage = cls._coverage(cls._rule_addresses(second))
        return all(any(net.version == other.version and net.subnet_of(other) for other in coverage) for net in cls._coverage(cls._rule_addresses(first)))

    @classmethod
    def _exact_policy_union(cls, first, second):
        if any(first[key] != second[key] for key in ('action', 'direction', 'protocol')) or executable_identity(first) != executable_identity(second):
            return None
        ports_a, ports_b = set(first['ports']), set(second['ports'])
        if ports_a != ports_b:
            return None
        merged = copy.deepcopy(first)
        merged['exes'] = list(second['exes'])
        merged['ports'] = sorted(ports_a)
        targets = {}
        if first['targets'] and second['targets']:
            for target in first['targets'] + second['targets']:
                targets.setdefault(target['target'], set()).update(target['addresses'])
        merged['targets'] = [{'target': target, 'addresses': sorted(addresses)} for target, addresses in sorted(targets.items())]
        return next(iter(cls._parse_port_rules([merged]).values()))

    @classmethod
    def _subtract_addresses(cls, values, removed):
        """Subtract bounded CIDR coverage, including /0, without enumerating hosts."""
        remaining = list(cls._coverage(values))
        for cut in cls._coverage(removed):
            pieces = []
            for network in remaining:
                if network.version != cut.version or not network.overlaps(cut):
                    pieces.append(network)
                elif network.subnet_of(cut):
                    continue
                else:
                    pieces.extend(network.address_exclude(cut))
            remaining = pieces
        return [str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
                for net in cls._coverage(map(str, remaining))]

    @classmethod
    def _connection_target_remainder(cls, source, selections):
        """Remove named identities and observed points; None means exhausted, never Any.

        Named matches leave independent overlapping domains alone. An IP-only
        match through a domain freezes that domain's remaining saved addresses
        as numeric targets, since re-resolving its name could restore the point.
        """
        domains = {item['target'] for item in source['targets'] if not is_ip(item['target'])}
        points, named, anonymous = set(), set(), set()
        coverage = cls._coverage(cls._rule_addresses(source)) if source['targets'] else ()
        for selection in selections:
            point = str(ipaddress.ip_address(selection['remote']))
            address = ipaddress.ip_address(point)
            if source['targets'] and not any(address.version == net.version and address in net for net in coverage):
                raise ValueError('This connection no longer matches the saved global rule.')
            points.add(point)
            name = normalize_target(selection.get('domain', ''))
            if name in domains:
                named.add(name)
            else:
                anonymous.add(point)
        if not points:
            raise ValueError('No connection target was selected.')
        numeric, domain_residuals, retained = [], [], []
        for item in source['targets']:
            if is_ip(item['target']):
                numeric.append(item['target'])
            elif item['target'] not in named:
                rest = cls._subtract_addresses(item['addresses'], anonymous)
                if cls._coverage(rest) == cls._coverage(item['addresses']):
                    retained.append(copy.deepcopy(item))
                else:
                    domain_residuals.extend(rest)
        if not source['targets']:
            numeric = ['0.0.0.0/0', '::/0']
        # Independent named coverage stays independent of numeric point cuts.
        numeric = cls._subtract_addresses(numeric, points) + domain_residuals
        retained.extend({'target': value, 'addresses': [value]}
                        for value in cls._subtract_addresses(numeric, ()))
        if not retained:
            return None
        return next(iter(cls._parse_port_rules([dict(source, targets=retained)]).values()))

    def matching_global_port_rules(self, row):
        protocol = {'6': 'TCP', '17': 'UDP'}.get(str(row.get('protocol')), str(row.get('protocol', '')).upper())
        with self.lock:
            return {key: dict(rule) for key, rule in getattr(self, 'global_ports', {}).items()
                    if (not rule['ports'] or str(row.get('dport')) in {str(port) for port in rule['ports']})
                    and (not rule_executables(rule) or normalize_path(row.get('exe', '')) in executable_identity(rule))
                    and (rule['protocol'] == 'Any' or rule['protocol'] == protocol or rule['protocol'] == 'TCP/UDP' and protocol in {'TCP', 'UDP'})
                    and (row.get('direction') is None or direction_set(row['direction']) <= direction_set(rule['direction']))
                    and (not rule['targets'] or self._global_match({item['target']: dict(item, direction=rule['direction']) for item in rule['targets']}, row.get('dst_ip', ''), row.get('domain', ''), row.get('direction')))}

    def global_port_action(self, row):
        actions = [rule['action'] for key, rule in self.matching_global_port_rules(row).items()
                   if self._policy_verified('port', key)]
        return 'Block' if 'Block' in actions else 'Allow' if 'Allow' in actions else None

    def apply_global_port_rules(self, entries):
        return self._apply_rule_batch((), port_updates=entries)

    @staticmethod
    def _ps_quote(value):
        return "'" + str(value).replace("'", "''") + "'"

    # Application rule creation and native command fallbacks

    def _app_rule_commands(self, name, exe_path, side, action='block'):
        direction = 'Inbound' if side == 'in' else 'Outbound'
        action_name = 'Block' if str(action).casefold() == 'block' else 'Allow'
        ps_command = (
            f"New-NetFirewallRule -Name {self._ps_quote(name)} -DisplayName {self._ps_quote(name)} "
            f"-Direction {direction} -Program {self._ps_quote(exe_path)} "
            f"-Action {action_name} -Enabled True -Profile Any -ErrorAction Stop | Out-Null"
        )
        verify = (
            f"$r=Get-NetFirewallRule -Name {self._ps_quote(name)} -ErrorAction Stop; "
            f"$a=Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction Stop | Select-Object -First 1; "
            f"if(-not $a){{throw 'Application filter is missing.'}}; "
            f"if([string]$r.Enabled -ne 'True'){{throw 'Firewall rule is disabled.'}}; "
            f"if([string]$r.Direction -ne {self._ps_quote(direction)}){{throw ('Wrong direction: ' + [string]$r.Direction)}}; "
            f"if([string]$r.Action -ne {self._ps_quote(action_name)}){{throw ('Wrong action: ' + [string]$r.Action)}}; "
            f"if(-not [string]::Equals([string]$a.Program,{self._ps_quote(exe_path)},[System.StringComparison]::OrdinalIgnoreCase)){{throw ('Wrong program: ' + [string]$a.Program)}}"
        )
        return ps_command, verify

    def _add_app_firewall_rule(self, name, exe_path, side, action='block'):
        """Create one application rule, including the native netsh fallback."""
        action_name = 'Block' if str(action).casefold() == 'block' else 'Allow'
        created = False
        used_netsh = False
        ps_command, verify = self._app_rule_commands(name, exe_path, side, action)

        try:
            self.run_ps(ps_command)
            created = True
        except Exception as first_error:
            first_detail = getattr(first_error, 'stderr', '') or ''
            try:
                self.run_netsh([
                    'add', 'rule',
                    f'name={name}',
                    f'dir={side}',
                    f'action={action_name.casefold()}',
                    f'program={exe_path}',
                    'enable=yes',
                    'profile=any',
                ])
                created = True
                used_netsh = True
            except Exception as second_error:
                second_detail = getattr(second_error, 'stderr', '') or ''
                try:
                    self.delete_rule_names((name,))
                except Exception:
                    pass
                raise RuntimeError(
                    f"Could not create application firewall rule '{name}' for '{exe_path}'. "
                    f"PowerShell: {str(first_detail).strip() or str(first_error)}; "
                    f"netsh: {str(second_detail).strip() or str(second_error)}"
                ) from second_error

        try:
            self.run_ps(verify)
            return
        except Exception as exc:
            if used_netsh:
                try:
                    self.run_netsh(['show', 'rule', f'name={name}', 'verbose'])
                    return
                except Exception:
                    pass
            detail = getattr(exc, 'stderr', '') or ''
            if created:
                try:
                    self.delete_rule_names((name,))
                except Exception:
                    pass
            raise RuntimeError(
                f"Windows Firewall created rule '{name}', but verification failed for '{exe_path}': "
                f"{str(detail).strip() or str(exc)}"
            ) from exc

    def add_app_rules(self, proc_name, exe_path, direction, kind='Block'):
        base = self.app_rule_base(proc_name, exe_path, kind)
        names, commands, checks = [], [], []
        for side in direction_set(direction):
            name = f"{base}_{'In' if side == 'in' else 'Out'}"
            create, verify = self._app_rule_commands(name, exe_path, side)
            names.append(name)
            commands.append(create)
            checks.append(verify)
        try:
            self.run_ps("$ErrorActionPreference='Stop'\n" + '\n'.join(commands + checks))
            return base
        except Exception as error:
            try:
                self.delete_rule_names(names)
            except Exception as cleanup_error:
                raise RuntimeError(f'Application rule batch failed: {error_details(error)}; cleanup failed: {cleanup_error}') from cleanup_error
            return self._add_app_rules_individually(proc_name, exe_path, direction, kind)

    def _add_app_rules_individually(self, proc_name, exe_path, direction, kind='Block'):
        base = self.app_rule_base(proc_name, exe_path, kind)
        created_names = []
        try:
            for side in direction_set(direction):
                name = f"{base}_{('In' if side == 'in' else 'Out')}"
                self._add_app_firewall_rule(name, exe_path, side, 'block')
                created_names.append(name)
            return base
        except Exception:
            if created_names:
                try:
                    self.delete_rule_names(created_names)
                except Exception:
                    pass
            raise

    def _restore_app_rule_records(self, records):
        created = []
        try:
            for record in records:
                path = display_path(record.get('path', ''))
                name = str(record.get('name', '') or '').strip()
                if not name:
                    continue
                if record.get('is_port'):
                    self._create_rule_batch([record])
                    created.append(name)
                    continue
                if record.get('is_global'):
                    raise ValueError('Only current global filters can be restored.')
                if not path:
                    raise ValueError(f'Missing program for rule {name}')
                action = 'Allow' if str(record.get('action', '')).casefold() == 'allow' else 'Block'
                suffixes = {'in': 'In', 'out': 'Out'}
                for side in direction_set(record.get('direction', 'Both')):
                    rule_name = name if name.endswith(f"_{suffixes[side]}") else f"{name}_{suffixes[side]}"
                    self._add_app_firewall_rule(rule_name, path, side, action)
                    created.append(rule_name)
                    if record.get('enabled', True) is False:
                        self.run_ps('$r=Get-NetFirewallRule -DisplayName ' + self._ps_quote(rule_name)
                                    + " -ErrorAction Stop; $r | Set-NetFirewallRule -Enabled False -ErrorAction Stop; "
                                    + 'if (@(Get-NetFirewallRule -DisplayName ' + self._ps_quote(rule_name)
                                    + " -ErrorAction Stop | Where-Object { [string]$_.Enabled -ne 'False' }).Count) { throw 'Disabled rule restoration failed' }")
        except Exception:
            if created:
                try:
                    self.delete_rule_names(created)
                except Exception:
                    pass
            raise

    # Global IP and domain rules

    def resolve_global_target(self, target, observed_addresses=()):
        target = normalize_target(target)
        if ',' in target:
            return tuple(sorted({address for part in global_targets(target)
                                 for address in self.resolve_global_target(part)}))
        if not is_global_target(target):
            raise ValueError(f'Not a global IP/Domain target: {target}')
        try:
            start, end = ip_range(target)
            return (f'{start}-{end}',)
        except ValueError:
            pass
        try:
            if '/' in target:
                return (str(ipaddress.ip_network(target, strict=False)),)
            return (str(ipaddress.ip_address(target)),)
        except ValueError:
            pass
        # Only validated connection addresses may serve as a DNS fallback. Never
        # guess an IP from a PTR-style hostname or pass a hostname to the firewall.
        addresses = {normalize_address(value) for value in observed_addresses}
        try:
            addresses.update(str(ipaddress.ip_address(result[4][0]))
                             for result in socket.getaddrinfo(target, None, type=socket.SOCK_STREAM))
            if not addresses:
                raise ValueError('DNS returned no addresses.')
        except (OSError, ValueError, UnicodeError) as exc:
            if not addresses:
                raise ValueError(f"Could not resolve global target '{target}': {error_details(exc)}") from exc
        return tuple(sorted(addresses))

    def add_global_rule_sync(self, target, allow, direction='both'):
        target = normalize_target(target)
        with self.firewall_lock:
            self._commit_rule_batch([(target, allow, direction, True)])
        addresses = tuple(sorted({address for rule in self.global_ports.values() for item in rule['targets'] if item['target'] == target for address in item['addresses']}))
        return target, addresses

    # Firewall profile backup and restoration

    def _read_firewall_profile_state(self):
        command = "Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,@{n='Enabled';e={[string]$_.Enabled}},@{n='DefaultInboundAction';e={[string]$_.DefaultInboundAction}},@{n='DefaultOutboundAction';e={[string]$_.DefaultOutboundAction}} | ConvertTo-Json -Compress"
        output = self.run_ps(command).stdout.strip() or '[]'
        raw = json.loads(output)
        if isinstance(raw, dict):
            raw = [raw]
        profiles = []
        for item in raw if isinstance(raw, list) else []:
            name = str(item.get('Name', '') or '')
            if not name:
                continue
            profiles.append({
                'name': name,
                'enabled': self._profile_enabled(item.get('Enabled', False)),
                'default_inbound_action': self._profile_action(item.get('DefaultInboundAction')), 
                'default_outbound_action': self._profile_action(item.get('DefaultOutboundAction')), 
            })
        if not profiles:
            raise ValueError('No Windows Firewall profiles were returned.')
        return profiles

    def _backup_firewall_profile_state(self):
        if os.path.exists(FIREWALL_PROFILE_BACKUP_FILE):
            return
        profiles = self._read_firewall_profile_state()
        backup = {'version': 1, 'created_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'profiles': profiles}
        temp = FIREWALL_PROFILE_BACKUP_FILE + '.tmp'
        with open(temp, 'w', encoding='utf-8') as f:
            json.dump(backup, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, FIREWALL_PROFILE_BACKUP_FILE)

    def initialize_or_restore_firewall(self):
        try:
            with self.firewall_lock:
                with self.lock:
                    if self.closed:
                        return False, 'Application is closing.'
                if os.path.exists(FIREWALL_PROFILE_BACKUP_FILE):
                    self._restore_firewall_profile_state_locked()
                self._require_valid_policy_settings()
                self._backup_firewall_profile_state()
                with self.lock:
                    self.firewall_profile_modified = True
                try:
                    self.run_ps('Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {Set-NetFirewallProfile -Name $_.Name -Enabled True -DefaultInboundAction Allow -DefaultOutboundAction Allow -ErrorAction Stop}')
                    self.restore_saved_rules_locked()
                    self.remove_auto_holds_locked()
                except Exception as setup_error:
                    log_internal_error('firewall_setup', setup_error)
                    try:
                        self._restore_firewall_profile_state_locked()
                    except Exception as restore_error:
                        raise RuntimeError(f'Firewall setup failed: {error_details(setup_error)}\n'
                                           f'Profile restoration also failed: {error_details(restore_error)}') from restore_error
                    raise
                with self.lock:
                    self.firewall_initialized = True
                    self.firewall_ready = True
            return True, ''
        except Exception as exc:
            log_internal_error('initialize_or_restore_firewall', exc)
            return False, error_details(exc)

    @staticmethod
    def _profile_action(value):
        actions = {'0': 'NotConfigured', '2': 'Allow', '4': 'Block',
                   'notconfigured': 'NotConfigured', 'allow': 'Allow', 'block': 'Block'}
        result = actions.get(str(value).strip().casefold())
        if result is None:
            raise ValueError(f'Invalid firewall profile action: {value!r}')
        return result

    @staticmethod
    def _profile_enabled(value):
        if value is True or str(value).casefold() in {'true', '1'}:
            return True
        if value is False or str(value).casefold() in {'false', '0'}:
            return False
        raise ValueError(f'Invalid firewall enabled state: {value!r}')

    def _restore_firewall_profile_state_locked(self):
        if not os.path.exists(FIREWALL_PROFILE_BACKUP_FILE):
            return False
        with open(FIREWALL_PROFILE_BACKUP_FILE, 'r', encoding='utf-8') as f:
            backup = json.load(f)
        profiles = backup.get('profiles') if isinstance(backup, dict) else None
        if not isinstance(profiles, list) or not profiles:
            raise ValueError('Firewall profile backup is missing or invalid.')
        validated = []
        for profile in profiles:
            if not isinstance(profile, dict) or profile.get('name') not in {'Domain', 'Private', 'Public'}:
                raise ValueError('Invalid firewall profile in backup.')
            validated.append((profile['name'], self._profile_enabled(profile.get('enabled')),
                              self._profile_action(profile.get('default_inbound_action')),
                              self._profile_action(profile.get('default_outbound_action'))))
        if {p[0] for p in validated} != {'Domain', 'Private', 'Public'} or len(validated) != 3:
            raise ValueError('Backup must contain each firewall profile exactly once.')
        for name, enabled, inbound, outbound in validated:
            self.run_ps(f"Set-NetFirewallProfile -Name {self._ps_quote(name)} "
                        f"-Enabled {'True' if enabled else 'False'} "
                        f"-DefaultInboundAction {inbound} -DefaultOutboundAction {outbound} -ErrorAction Stop")
        os.remove(FIREWALL_PROFILE_BACKUP_FILE)
        with self.lock:
            self.firewall_profile_modified = False
            self.firewall_initialized = False
            self.firewall_ready = False
        return True

    def restore_saved_rules_locked(self):
        with self.lock:
            allowed = list(self.allowed_apps)
            pending = list(self.pending_rules)
            ports = list(getattr(self, 'global_ports', {}).values())
        records = self.get_firewall_rules()
        requests = [(path, True, 'both', False) for path in allowed]
        for rule in pending:
            path = display_path(rule['path'])
            norm = normalize_path(path)
            wanted = direction_set(rule['direction'])
            actual = set()
            for record in records:
                if (record['normalized_path'] == norm and not record['is_hold'] and record['action'].casefold() == 'block'
                        and self._native_record_matches(record, dict(record, path=path, action='Block',
                            protocol='Any', addresses=['Any'], local_ports=['Any'], remote_ports=['Any']))):
                    d = record['direction'].casefold()
                    if 'in' in d:
                        actual.add('in')
                    if 'out' in d:
                        actual.add('out')
            if actual != wanted:
                requests.append((path, False, rule['direction'], False))
        if requests or ports:
            options = {'port_updates': ports} if ports else {}
            self._commit_rule_batch(requests, records=records, **options)
        with self.lock:
            self.pending_rules.clear()

    def remove_auto_holds_locked(self, normalized_path=None):
        records = self.get_firewall_rules()
        holds = [r for r in records if r['is_hold'] and (not normalized_path or r['normalized_path'] == normalized_path)]
        self._replace_rule_records(holds, (), lambda: None)

    # Cached rule lookup and duplicate detection

    def get_rule_status(self, exe_path):
        norm = normalize_path(exe_path)
        with self.lock:
            data = getattr(self, 'verified_blocked_paths', self.blocked_paths).get(norm, {})
            if data.get('in') and data.get('out'):
                return 'blocked_both'
            if data.get('in'):
                return 'blocked_in'
            if data.get('out'):
                return 'blocked_out'
            if norm in self.allowed_apps:
                return 'allowed'
            return ''

    def get_rule_status_display(self, exe_path):
        status = self.get_rule_status(exe_path)
        return {'allowed': 'Allowed', 'blocked_both': 'Blocked', 'blocked_in': 'Blocked (in)', 'blocked_out': 'Blocked'}.get(status, '—')

    def _global_match(self, collection, remote_ip, domain, direction=None):
        try:
            remote = ipaddress.ip_address(str(remote_ip).split('%', 1)[0])
        except ValueError:
            return False
        for target, data in collection.items():
            if direction is not None and not direction_set(direction) <= direction_set(data.get('direction', 'Both')):
                continue
            for address in (*target.split(','), *data.get('addresses', ())):
                try:
                    if any(remote in network for network in address_networks(address.strip())):
                        return True
                except ValueError:
                    continue
        return False

    def _unrestricted_global_action(self, remote_ip, domain, direction, action):
        with self.lock:
            return any(rule['action'] == action and not rule['ports'] and not rule['exes'] and rule['protocol'] == 'Any'
                       and self._policy_verified('port', key)
                       and (direction is None or direction_set(direction) <= direction_set(rule['direction']))
                       and (not rule['targets'] or self._global_match({item['target']: dict(item, direction=rule['direction']) for item in rule['targets']}, remote_ip, domain, direction))
                       for key, rule in self.global_ports.items())

    def is_globally_blocked(self, remote_ip, domain='', direction=None):
        return self._unrestricted_global_action(remote_ip, domain, direction, 'Block')

    def is_globally_allowed(self, remote_ip, domain='', direction=None):
        return self._unrestricted_global_action(remote_ip, domain, direction, 'Allow')

    def connection_has_rule(self, exe_path, remote_ip, domain, direction, local_port=None, remote_port=None, protocol='TCP'):
        if self.global_port_action({'lport': local_port, 'dport': remote_port, 'protocol': protocol,
                                    'dst_ip': remote_ip, 'domain': domain, 'direction': direction, 'exe': exe_path}):
            return True
        if self.is_globally_blocked(remote_ip, domain, direction) or self.is_globally_allowed(remote_ip, domain, direction):
            return True
        status = self.get_rule_status(exe_path)
        normalized_direction = direction_name(direction)
        if status in {'allowed', 'blocked_both'}:
            return True
        if status == 'blocked_in':
            return normalized_direction == 'Inbound'
        if status == 'blocked_out':
            return normalized_direction == 'Outbound'
        return False

    def application_has_rule(self, exe_path):
        return bool(self.get_rule_status(exe_path))

    def rules_changed(self):
        if threading.get_ident() != getattr(self, 'ui_thread_id', threading.main_thread().ident):
            self.ui_queue.put(('rules_changed',))
        else:
            self.refresh_rules(force=True)

    def _require_valid_policy_settings(self):
        if getattr(self, 'settings_load_error', None):
            raise RuntimeError(self.settings_load_error + '\nSaved policy is preserved; rule changes are disabled for this run.')

    def _invalidate_rule_snapshot_locked(self):
        """Caller holds firewall_lock then lock after a native commit."""
        self.rules_generation = getattr(self, 'rules_generation', 0) + 1
        if getattr(self, 'rules_refresh_worker_running', False):
            self.rules_refresh_pending = True

    def _record_app_commit_locked(self, norm, decision_guard=None):
        if not hasattr(self, 'app_policy_versions'):
            self.app_policy_versions = {}
        self.app_policy_versions[norm] = self.app_policy_versions.get(norm, 0) + 1
        if hasattr(self, 'verified_blocked_paths'):
            self.verified_blocked_paths.pop(norm, None)
            if norm in self.blocked_paths:
                self.verified_blocked_paths[norm] = dict(self.blocked_paths[norm])
        if hasattr(self, 'rule_enforcement'):
            self.rule_enforcement[('app', norm)] = 'Verified'
        if hasattr(self, 'observed_app_paths'):
            self.observed_app_paths.discard(norm)
            if norm in self.blocked_paths:
                self.observed_app_paths.add(norm)
        if decision_guard is not None and hasattr(decision_guard, 'committed'):
            decision_guard.committed(self.app_policy_versions[norm])

    def _rule_is_duplicate(self, target, allow=False, direction='both', global_target=False):
        """Use the managed-rule cache; never launch a firewall command to check."""
        with self.lock:
            if global_target:
                return False  # Unified policies verify native filters in the batch transaction.
            norm = normalize_path(target)
            if allow:
                return (norm in self.allowed_apps and norm not in self.blocked_paths
                        and norm not in getattr(self, 'observed_app_paths', set())
                        and norm not in getattr(self, 'verified_blocked_paths', {}))
            data = self.blocked_paths.get(norm, {})
            actual = {side for side in ('in', 'out') if data.get(side)}
            return (self._policy_verified('app', norm) and norm not in self.allowed_apps
                    and actual == direction_set(direction))

    def _warn_duplicate_rule(self, target, quiet=False):
        text = f'The requested rule already exists and was skipped:\n{target}'
        self.queue_alert('Info', 'Duplicate rule', '', '', text)

    def _persist_rule_changes(self):
        if self.save_settings() is False:
            detail = getattr(self, 'settings_save_error', None) or 'Could not write the saved configuration.'
            self.settings_save_error = detail
            raise RuntimeError(f'Firewall changes were applied, but could not be saved for the next launch.\n{detail}')

    def _duplicate_rule_result(self, target, quiet=False):
        self._warn_duplicate_rule(target, quiet)
        if getattr(self, 'settings_save_error', None):
            try:
                self._persist_rule_changes()
            except Exception as exc:
                self.queue_alert('High', target, '', '', str(exc))
                if not quiet:
                    self._native_message('showerror', 'Save Failed', str(exc), parent=self.root)
                return False
        return True

    # Bulk rule creation and commit

    def _create_rule_batch(self, rules):
        """Create and verify every planned rule in one PowerShell process."""
        if not rules:
            return
        payload = self._ps_quote(json.dumps(rules, ensure_ascii=True))
        command = "$ErrorActionPreference='Stop'\n$rules=ConvertFrom-Json " + payload + '\n'
        command += '''
function Get-AddressKey([string]$address) {
    if ($address.Contains('-')) {
        $ends = $address.Split('-')
        return ([System.Net.IPAddress]::Parse($ends[0]).ToString() + '-' + [System.Net.IPAddress]::Parse($ends[1]).ToString())
    }
    $parts = $address.Split('/')
    $ip = [System.Net.IPAddress]::Parse($parts[0])
    $bits = $ip.GetAddressBytes().Length * 8
    $prefix = $bits
    if ($parts.Length -gt 1) {
        if ($parts[1].Contains('.')) {
            $prefix = 0
            foreach ($byte in ([System.Net.IPAddress]::Parse($parts[1])).GetAddressBytes()) {
                $prefix += ([Convert]::ToString($byte, 2).Replace('0', '')).Length
            }
        } else { $prefix = [int]$parts[1] }
    }
    $ip.ToString() + '/' + $prefix
}
foreach ($rule in $rules) {
    $enabled = if ($rule.enabled -eq $false) { 'False' } else { 'True' }
    $profile = if ($rule.profile -and [string]$rule.profile -ne '0') { [string]$rule.profile } else { 'Any' }
    $params = @{
        Name=[string]$rule.name; DisplayName=[string]$rule.name
        Direction=[string]$rule.direction; Action=[string]$rule.action
        Enabled=$enabled; Profile=$profile; ErrorAction='Stop'
    }
    if ($rule.is_port) {
        if ($rule.path) { $params.Program=[string]$rule.path }
        $params.Protocol=[string]$rule.protocol
        if ($rule.protocol -ne 'Any') {
            $params.LocalPort=[string[]]$rule.local_ports
            $params.RemotePort=[string[]]$rule.remote_ports
        }
        if ($rule.addresses) { $params.RemoteAddress=[string[]]$rule.addresses }
        if ($rule.local_addresses) { $params.LocalAddress=[string[]]$rule.local_addresses }
    }
    elseif ($rule.path) { $params.Program=[string]$rule.path }
    else { throw ('A current application or global filter is required: ' + $rule.name) }
    New-NetFirewallRule @params | Out-Null
}
foreach ($rule in $rules) {
    $enabled = if ($rule.enabled -eq $false) { 'False' } else { 'True' }
    $profile = if ($rule.profile -and [string]$rule.profile -ne '0') { [string]$rule.profile } else { 'Any' }
    $r = Get-NetFirewallRule -Name $rule.name -ErrorAction Stop
    if (@($r).Count -ne 1 -or [string]$r.Enabled -ne $enabled -or
        [string]$r.Action -ne $rule.action -or [string]$r.Direction -ne $rule.direction -or
        [string]$r.Profile -ne $profile) {
        throw ('Firewall rule verification failed: ' + $rule.name)
    }
    if ($rule.is_port) {
        $p = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction Stop | Select-Object -First 1
        $protocol = [string]$p.Protocol
        $expected = [string]$rule.protocol
        if ($protocol -eq '6') { $protocol = 'TCP' }
        if ($protocol -eq '17') { $protocol = 'UDP' }
        if ($protocol -eq '256') { $protocol = 'Any' }
        if ($expected -eq '6') { $expected = 'TCP' }
        if ($expected -eq '17') { $expected = 'UDP' }
        if ($protocol -ne $expected -or
            (Compare-Object @($rule.local_ports) @($p.LocalPort)) -or
            (Compare-Object @($rule.remote_ports) @($p.RemotePort))) {
            throw ('Wrong port filter: ' + $rule.name)
        }
        $program = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction Stop | Select-Object -First 1
        $address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction Stop | Select-Object -First 1
        $expectedAddresses = @('Any')
        if ($rule.addresses) { $expectedAddresses = @($rule.addresses) }
        $expectedKeys = @($expectedAddresses | ForEach-Object { if ($_ -eq 'Any') { 'Any' } else { Get-AddressKey $_ } } | Sort-Object -Unique)
        $actualKeys = @($address.RemoteAddress | ForEach-Object { if ($_ -eq 'Any') { 'Any' } else { Get-AddressKey $_ } } | Sort-Object -Unique)
        $expectedLocalAddresses = @('Any')
        if ($rule.local_addresses) { $expectedLocalAddresses = @($rule.local_addresses) }
        $expectedLocalKeys = @($expectedLocalAddresses | ForEach-Object { if ($_ -eq 'Any') { 'Any' } else { Get-AddressKey $_ } } | Sort-Object -Unique)
        $actualLocalKeys = @($address.LocalAddress | ForEach-Object { if ($_ -eq 'Any') { 'Any' } else { Get-AddressKey $_ } } | Sort-Object -Unique)
        $expectedProgram = 'Any'
        if ($rule.path) { $expectedProgram = [string]$rule.path }
        if (-not [string]::Equals([string]$program.Program, $expectedProgram, [System.StringComparison]::OrdinalIgnoreCase) -or
            (Compare-Object $expectedKeys $actualKeys) -or
            (Compare-Object $expectedLocalKeys $actualLocalKeys)) {
            throw ('Wrong application or address filter for port rule: ' + $rule.name)
        }
    } elseif ($rule.path) {
        $filter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction Stop |
            Select-Object -First 1
        if (-not $filter -or -not [string]::Equals([string]$filter.Program,
            [string]$rule.path, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw ('Wrong program for firewall rule: ' + $rule.name)
        }
    } else { throw ('A current application or global filter is required: ' + $rule.name) }
}
'''
        self.run_ps(command, timeout=max(FIREWALL_COMMAND_TIMEOUT, len(rules) * 2.0))

    @staticmethod
    def _merge_policy_traffic(items):
        totals = {'download': 0, 'upload': 0, '_contributions': {}}
        for stats in items:
            contributions = stats.get('_contributions', {})
            for bucket, values in contributions.items():
                target = totals['_contributions'].setdefault(bucket, {'download': 0, 'upload': 0})
                for side in ('download', 'upload'):
                    target[side] = max(target[side], values.get(side, 0))
            # Current capture always supplies buckets. Keep synthetic/manual
            # counters as distinct contributions when no capture ledger exists.
            if not contributions:
                for side in ('download', 'upload'):
                    totals[side] += stats.get(side, 0)
        for values in totals['_contributions'].values():
            for side in ('download', 'upload'):
                totals[side] += values.get(side, 0)
        return totals

    @classmethod
    def _saved_global_target_addresses(cls, rule, policies, source=None):
        """Select per-target fallback from a policy snapshot; no DNS or native work."""
        saved_rule = policies.get(source if source is not None else cls._policy_key(rule), {})
        targets = {item['target'] for item in rule['targets']}
        saved_targets = {item['target']: list(item['addresses']) for item in saved_rule.get('targets', [])
                         if item['target'] in targets}
        # Edits use only their source. Fresh targets without effective addresses
        # may use compatible peers, even when their remote ports differ.
        if source is None:
            missing_addresses = {item['target'] for item in rule['targets'] if not item['addresses']}
            for saved in policies.values():
                if (all(saved[field] == rule[field] for field in ('action', 'direction', 'protocol'))
                        and executable_identity(saved) == executable_identity(rule)):
                    for item in saved['targets']:
                        if item['target'] in missing_addresses:
                            saved_targets[item['target']] = sorted(set(saved_targets.get(item['target'], ())) | set(item['addresses']))
        return saved_targets

    def _commit_rule_batch(self, requests, records=None, port_updates=None, observed_addresses=None, replace_rule=None, decision_guard=None, target_edits=None):
        """Caller holds firewall_lock across read, exact merge and verified commit."""
        self._require_valid_policy_settings()
        submitted = self._parse_port_rules(port_updates or [])
        apps, planned = {}, []
        for target, allow, direction, global_target in requests:
            if global_target:
                parts = global_targets(target)
                rule = {'action': 'Allow' if allow else 'Block', 'direction': direction_name(direction),
                        'protocol': 'Any', 'exes': [], 'ports': [],
                        'targets': [{'target': part, 'addresses': list((observed_addresses or {}).get(part, ()))} for part in parts]}
                submitted.update(self._parse_port_rules([rule]))
            else:
                norm = normalize_path(target)
                wanted = direction_set(direction)
                apps[norm] = (target, allow, wanted)
                if not allow:
                    base = self.app_rule_base(None, target)
                    for side in sorted(wanted):
                        planned.append({'name': base + ('_In' if side == 'in' else '_Out'),
                                        'direction': 'Inbound' if side == 'in' else 'Outbound', 'action': 'Block', 'path': target})
        with self.lock:
            original = copy.deepcopy(getattr(self, 'global_ports', {}))
        if replace_rule and replace_rule[0] != 'port':
            raise ValueError('Only current-format global policies can be edited.')
        source = replace_rule[1] if replace_rule else None
        if source is not None and source not in original:
            raise ValueError('This global rule changed or was removed. Refresh Managed Rules before editing it.')
        edits = {}
        for edit in target_edits or ():
            key = edit['source']
            if key == source or key not in original or original[key] != edit['snapshot']:
                raise ValueError('This global rule changed or was removed. Reopen the connection editor before retrying.')
            group = edits.setdefault(key, {'selections': [], 'replacements': []})
            group['selections'].extend(edit['selections'])
            if edit.get('replacement') is not None:
                group['replacements'].extend(self._parse_port_rules([edit['replacement']]).values())
        retired = set(edits) | ({source} if source in original else set())
        candidates = {key: rule for key, rule in original.items() if key not in retired}
        affected = set(retired)
        provenance = {key: {key} for key in candidates}
        history = {key: {key} for key in candidates}
        stages = []
        for key, edit in sorted(edits.items()):
            remainder = self._connection_target_remainder(original[key], edit['selections'])
            if remainder is not None:
                stages.append((remainder, {key}, {key}, False, key))
            for index, replacement in enumerate(edit['replacements']):
                # Historical bytes belong to the remainder once; a separated
                # replacement starts at zero. With no remainder retain them once.
                owners = {key} if remainder is None and index == 0 else set()
                stages.append((replacement, {key}, owners, True, key))
        for replacement in submitted.values():
            members = {source} if source in original else set()
            stages.append((replacement, members, set(members), True, source))
        final_keys = set()
        for replacement, members, owners, resolve, fallback_source in stages:
            rule = copy.deepcopy(replacement)
            # Fallback addresses belong to a specific target. Editing a target
            # out never borrows its former addresses for another domain.
            if resolve:
                saved_targets = self._saved_global_target_addresses(rule, original, fallback_source)
                for item in rule['targets']:
                    observed = set(item['addresses']) | set(saved_targets.get(item['target'], ()))
                    item['addresses'] = list(self.resolve_global_target(item['target'], observed))
            changed = True
            while changed:
                changed = False
                for key in sorted(candidates):
                    merged = self._exact_policy_union(rule, candidates[key])
                    if merged is None:
                        continue
                    rule = merged
                    members.update(provenance.pop(key))
                    owners.update(history.pop(key))
                    candidates.pop(key)
                    final_keys.discard(key)
                    changed = True
                    break
            key = self._policy_key(rule)
            candidates[key] = rule
            provenance[key] = members
            history[key] = owners
            affected.update(members)
            final_keys.add(key)
        if records is None:
            records = self.get_firewall_rules()
        updates = {}
        for key in sorted(final_keys):
            rule = candidates[key]
            expected = self._port_firewall_rules({key: rule})
            # A verified duplicate is idempotent, but native drift still repairs.
            if key in original and rule == original[key] and provenance[key] <= {key} and source is None and self._enforcement_for(expected, records) == 'Verified':
                affected.discard(key)
                continue
            updates[key] = rule
            planned.extend(expected)
        names = {rule['name'] for rule in self._port_firewall_rules({key: original[key] for key in affected if key in original}, all_directions=True)}
        names.update(rule['name'] for rule in self._port_firewall_rules(updates, all_directions=True))
        previous = [record for record in records if (not record.get('is_global') and not record.get('is_hold') and record.get('normalized_path') in apps) or record['name'] in names]
        def create():
            if decision_guard is not None and not decision_guard():
                raise RuntimeError('Auto-Block decision was cancelled.')
            self._create_rule_batch(planned)
            if planned and self._enforcement_for(planned, self.get_firewall_rules()) != 'Verified':
                raise RuntimeError('Windows Firewall did not retain the complete requested filters.')
        def commit():
            with self.lock:
                if decision_guard is not None and not decision_guard():
                    raise RuntimeError('Auto-Block decision was cancelled.')
                traffic = getattr(self, 'global_port_traffic', {})
                migrated = {key: self._merge_policy_traffic([traffic[old] for old in sorted(history[key]) if old in traffic]) for key in updates}
                for key in affected:
                    self.global_ports.pop(key, None)
                    traffic.pop(key, None)
                    getattr(self, 'rule_enforcement', {}).pop(('port', key), None)
                self.global_ports.update(updates)
                traffic.update(migrated)
                self.global_port_traffic = traffic
                if updates or affected:
                    self.global_policy_epoch = getattr(self, 'global_policy_epoch', 0) + 1
                if hasattr(self, 'rule_enforcement'):
                    for key in final_keys:
                        self.rule_enforcement['port', key] = 'Verified'
                if decision_guard is not None and hasattr(decision_guard, 'committed_port'):
                    for key in sorted(final_keys):
                        decision_guard.committed_port(key, self.global_ports[key])
                for norm, (path, allow, wanted) in apps.items():
                    if allow:
                        self.allowed_apps.add(norm)
                        self.blocked_paths.pop(norm, None)
                    else:
                        self.allowed_apps.discard(norm)
                        self.blocked_paths[norm] = {'path': path, 'in': 'in' in wanted, 'out': 'out' in wanted}
                    self._record_app_commit_locked(norm)
                self.connection_rates = {key: value for key, value in self.connection_rates.items() if key[0] not in apps}
                self.upload_alerted = {key for key in self.upload_alerted if key[0] not in apps or not apps[key[0]][1]}
                self._invalidate_rule_snapshot_locked()
        if apps or planned or previous or affected or decision_guard is not None:
            self._replace_rule_records(previous, [rule['name'] for rule in planned], create, commit=commit)
        return apps, any(request[3] for request in requests)

    def _apply_auto_connection_rule(self, endpoint, exe, allow, decision_guard):
        """Commit an exact captured endpoint; the prompt owns saving and hold cleanup."""
        paths = rule_executables({'exes': [endpoint.get('exe')]})
        if len(paths) != 1 or normalize_path(paths[0]) != normalize_path(exe):
            raise ValueError('The captured connection needs its full executable path. Use an application decision or retry after a complete connection is captured.')
        try:
            remote = str(ipaddress.ip_address(str(endpoint.get('dst_ip', '')).strip()))
            if '%' in remote:
                raise ValueError('Scoped address')
        except ValueError as exc:
            raise ValueError('The captured connection needs one exact remote IPv4 or IPv6 address.') from exc
        raw_port = endpoint.get('dport')
        if isinstance(raw_port, bool) or not str(raw_port).isdigit() or not 1 <= int(raw_port) <= 65535:
            raise ValueError('The captured connection needs a remote port from 1 through 65535.')
        protocol = str(endpoint.get('protocol', '')).upper()
        if protocol not in {'TCP', 'UDP'}:
            raise ValueError('The captured connection needs a TCP or UDP protocol.')
        rule = {'exes': paths, 'targets': [{'target': remote, 'addresses': [remote]}],
                'ports': [int(raw_port)], 'protocol': protocol,
                'action': 'Allow' if allow else 'Block', 'direction': 'Both'}
        self._commit_rule_batch((), port_updates=[rule], decision_guard=decision_guard)
        return True

    def _apply_rule_batch(self, requests, quiet=False, port_updates=None, observed_addresses=None, replace_rule=None, report=False, target_edits=None):
        """Apply a whole selection/import with one snapshot, save and refresh."""
        if self._native_ui_call():
            snapshot = copy.deepcopy((list(requests), quiet, port_updates, observed_addresses, replace_rule, report, target_edits))
            queued = self._queue_native_job('Rule update', lambda: self._apply_rule_batch(*snapshot))
            return None if queued else False
        try:
            ports = self._parse_port_rules(port_updates or [])
        except ValueError as exc:
            self.queue_alert('High', 'Global port rule', '', '', str(exc))
            if not quiet:
                self._native_message('showerror', 'Global Port Rule', str(exc), parent=self.root)
            return False
        selected = {}
        skipped_global, skipped_app = [], []
        for target, allow, direction, global_target in requests:
            if target and global_target and not is_global_target(target):
                skipped_global.append(str(target))
                continue
            if target and not global_target and not os.path.isabs(str(target)):
                skipped_app.append(str(target))
                continue
            target = normalize_target(target) if global_target else display_path(target)
            if not target:
                continue
            if global_target:
                try:
                    target = str(ipaddress.ip_network(target, strict=False)) if '/' in target else str(ipaddress.ip_address(target))
                except ValueError:
                    pass
            key = (target if global_target else normalize_path(target), global_target)
            # Preserve the old sequential import's final state for conflicting entries.
            selected[key] = (target, allow, direction, global_target)
        self._warn_inapplicable_rules(skipped_global, True, quiet)
        self._warn_inapplicable_rules(skipped_app, False, quiet)
        if not selected and not ports and not target_edits:
            if report and not quiet:
                self._show_rule_result('Rule Update', 'No applicable rules were selected. No rules were changed.')
            return True
        try:
            with self.firewall_lock:
                # A failed disk save does not undo the verified native commit.
                # Retry the exact operation only as persistence, never subtract twice.
                receipt = getattr(self, '_unsaved_target_edit', None)
                request_identity = (list(selected.values()), ports, replace_rule, observed_addresses)
                if (target_edits and receipt and receipt[0] == target_edits and receipt[1] == self.global_ports
                        and receipt[2] == request_identity):
                    self._persist_rule_changes()
                    self._unsaved_target_edit = None
                    return True
                pending, duplicates = [], []
                with self.lock:
                    # The generic transaction leaves holds alone. Retire only
                    # the manual selection's captured owner at this boundary.
                    owners = dict(getattr(self, 'auto_hold_cleanup', {}))
                    owners.update(getattr(self, 'auto_hold_owners', {}))
                    prompt_generation = self.auto_prompt_generation
                cleanup_failed = False
                global_changed = False
                port_pending = list(ports.values())
                for request in selected.values():
                    if request[3] or replace_rule or not self._rule_is_duplicate(*request):
                        pending.append(request)
                    else:
                        duplicates.append(request[0])
                if pending or port_pending or target_edits:
                    options = {'port_updates': port_pending} if port_pending else {}
                    if observed_addresses:
                        options['observed_addresses'] = observed_addresses
                    if replace_rule:
                        options['replace_rule'] = replace_rule
                    if target_edits:
                        options['target_edits'] = target_edits
                    apps, global_changed = self._commit_rule_batch(pending, **options)
                    if global_changed:
                        self._invalidate_auto_prompts(close_dialog=True)
                if not global_changed:
                    for path, _, _, global_target in selected.values():
                        if global_target:
                            continue
                        norm = normalize_path(path)
                        owner = owners.get(norm)
                        if owner is not None and not self._release_auto_hold_locked(norm, owner, resolve_prompt=True):
                            cleanup_failed = True
                            continue
                        self._cancel_app_prompt(norm, owner if owner is not None else prompt_generation)
            if pending or port_pending or target_edits:
                if target_edits:
                    self._unsaved_target_edit = copy.deepcopy((target_edits, self.global_ports, request_identity))
                self.rules_changed()
                self._persist_rule_changes()
                if target_edits:
                    self._unsaved_target_edit = None
            elif duplicates and getattr(self, 'settings_save_error', None):
                self._persist_rule_changes()
            if cleanup_failed:
                raise RuntimeError('The application rule was applied, but its temporary block could not be released. Retry the same rule action to finish cleanup.')
        except Exception as exc:
            details = error_details(exc)
            log_internal_error('rule_batch', exc)
            self.queue_alert('High', 'Bulk rules', '', '', f'Firewall rule update failed: {details}')
            if not quiet:
                self._native_message('showerror', 'Rule Update Failed', details)
            return False
        return True

    def _warn_inapplicable_rules(self, skipped, global_target, quiet=False):
        if not skipped:
            return
        text = (f'{len(skipped)} selected app rule(s) or invalid target(s) were not impacted '
                'because they are not global IP/Domain rules.' if global_target else
                f'{len(skipped)} selected global IP/Domain rule(s) or invalid target(s) were not '
                'impacted because they are not application rules.')
        text += '\nApplicable selected rules will still be processed.'
        if quiet:
            self.queue_alert('Info', 'Skipped rules', '', '', text)
        else:
            self._native_message('showwarning', 'Some Rules Were Skipped', text)

    # Single-rule actions and removal

    def block_executable(self, exe_path, proc_name=None, direction='both', refresh=True, quiet=False, update_ui=True, decision_guard=None):
        if self._native_ui_call():
            self._queue_native_job('Block application', lambda: self.block_executable(
                exe_path, proc_name, direction, refresh, quiet, update_ui, decision_guard))
            return None
        path = display_path(exe_path)
        norm = normalize_path(path)
        if not norm:
            return False
        proc_name = proc_name or os.path.splitext(os.path.basename(path))[0] or 'Process'
        if self._rule_is_duplicate(path, direction=direction):
            return self._duplicate_rule_result(path, quiet)
        try:
            with self.firewall_lock:
                self._require_valid_policy_settings()
                if self._rule_is_duplicate(path, direction=direction):
                    return self._duplicate_rule_result(path, quiet)
                records = self.get_firewall_rules()
                previous = [r for r in records if r['normalized_path'] == norm and not r.get('is_global')]
                base = self.app_rule_base(proc_name, path, 'Block')
                replacing_hold = bool(previous) and all(r.get('is_hold') for r in previous)
                def create():
                    if decision_guard is not None and not decision_guard():
                        raise RuntimeError('Auto-Block decision was cancelled.')
                    self.add_app_rules(proc_name, path, direction, kind='Block')
                def commit():
                    with self.lock:
                        if decision_guard is not None and not decision_guard():
                            raise RuntimeError('Auto-Block decision was cancelled.')
                        wanted = direction_set(direction)
                        self.allowed_apps.discard(norm)
                        self.blocked_paths[norm] = {'in': 'in' in wanted, 'out': 'out' in wanted, 'path': path}
                        self.connection_rates = {k: v for k, v in self.connection_rates.items() if k[0] != norm}
                        self._invalidate_rule_snapshot_locked()
                        self._record_app_commit_locked(norm, decision_guard)
                self._replace_rule_records(previous, (base + '_In', base + '_Out'),
                                           create, apply_first=replacing_hold, commit=commit)
            if update_ui:
                self._cancel_app_prompt(norm)
            if refresh and update_ui:
                self.rules_changed()
            self._persist_rule_changes()
            return True
        except Exception as exc:
            self.queue_alert('High', path, '', '', f'Firewall rule update failed: {exc}')
            if not quiet:
                self._native_message('showerror', 'Block Failed', f'{proc_name}\n\n{exc}')
            return False

    def allow_executable(self, exe_path, refresh=True, quiet=False, update_ui=True, decision_guard=None):
        if self._native_ui_call():
            self._queue_native_job('Allow application', lambda: self.allow_executable(
                exe_path, refresh, quiet, update_ui, decision_guard))
            return None
        path = display_path(exe_path)
        norm = normalize_path(path)
        if not norm:
            return False
        if self._rule_is_duplicate(path, allow=True):
            return self._duplicate_rule_result(path, quiet)
        try:
            with self.firewall_lock:
                self._require_valid_policy_settings()
                if self._rule_is_duplicate(path, allow=True):
                    return self._duplicate_rule_result(path, quiet)
                records = self.get_firewall_rules()
                previous = [r for r in records if r['normalized_path'] == norm and not r.get('is_global')]
                def commit():
                    with self.lock:
                        if decision_guard is not None and not decision_guard():
                            raise RuntimeError('Auto-Block decision was cancelled.')
                        self.allowed_apps.add(norm)
                        self.blocked_paths.pop(norm, None)
                        self.connection_rates = {k: v for k, v in self.connection_rates.items() if k[0] != norm}
                        self.upload_alerted = {k for k in self.upload_alerted if k[0] != norm}
                        self._invalidate_rule_snapshot_locked()
                        self._record_app_commit_locked(norm, decision_guard)
                self._replace_rule_records(previous, (), lambda: None, commit=commit)
            if update_ui:
                self._cancel_app_prompt(norm)
            if refresh and update_ui:
                self.rules_changed()
            self._persist_rule_changes()
            return True
        except Exception as exc:
            self.queue_alert('High', path, '', '', f'Firewall rule update failed: {exc}')
            if not quiet:
                self._native_message('showerror', 'Allow Failed', f'{path}\n\n{exc}')
            return False

    def add_global_rule(self, target, allow, refresh=True, quiet=False, direction='both'):
        return self._apply_rule_batch([(target, allow, direction, True)], quiet=quiet)

    def remove_rule(self, status, path, refresh=True):
        return self._remove_rule_batch(((status, path),), refresh=refresh)

    def _managed_rule_category(self, status, path):
        return 'port' if str(path) in self.global_ports or str(status).casefold() in {'global port block', 'global port allow', 'allowed (global)', 'blocked (global)'} else 'app'

    def _remove_rule_batch(self, requests, refresh=True):
        if self._native_ui_call():
            snapshot = tuple(requests)
            self._queue_native_job('Remove rules', lambda: self._remove_rule_batch(snapshot, refresh))
            return None
        apps, ports = set(), set()
        for status, path in requests:
            if self._managed_rule_category(status, path) == 'port':
                ports.add(str(path))
            elif normalize_path(path):
                apps.add(normalize_path(path))
        if not apps and not ports:
            return False
        try:
            with self.firewall_lock:
                self._require_valid_policy_settings()
                records = self.get_firewall_rules()
                with self.lock:
                    selected = {key: rule for key, rule in self.global_ports.items() if key in ports}
                names = {rule['name'] for rule in self._port_firewall_rules(selected, all_directions=True)}
                previous = [record for record in records if (not record.get('is_global') and not record.get('is_hold') and record.get('normalized_path') in apps) or record['name'] in names]
                self._replace_rule_records(previous, (), lambda: None)
                with self.lock:
                    for key in ports:
                        self.global_ports.pop(key, None)
                        self.global_port_traffic.pop(key, None)
                        getattr(self, 'rule_enforcement', {}).pop(('port', key), None)
                    if ports:
                        self.global_policy_epoch = getattr(self, 'global_policy_epoch', 0) + 1
                    for norm in apps:
                        self.allowed_apps.discard(norm)
                        self.blocked_paths.pop(norm, None)
                        self._record_app_commit_locked(norm)
                    self._invalidate_rule_snapshot_locked()
                for norm in apps:
                    self._cancel_app_prompt(norm)
            if refresh:
                self.rules_changed()
            self._persist_rule_changes()
            return True
        except Exception as exc:
            self._native_message('showerror', 'Remove Rule Failed', str(exc))
            return False

    # Cache reconciliation

    def _policy_verified(self, kind, key):
        states = getattr(self, 'rule_enforcement', None)
        return states is None or states.get((kind, key)) == 'Verified'

    @staticmethod
    def _native_record_matches(record, expected):
        def values(raw, addresses=False):
            raw = [raw] if isinstance(raw, (str, int)) else raw or ['Any']
            parts = [str(part).strip() for value in raw for part in str(value).split(',')]
            if addresses:
                try:
                    networks = [network for part in parts for network in address_networks(part)]
                    return tuple(sorted(str(n) for version in (4, 6) for n in ipaddress.collapse_addresses(
                        n for n in networks if n.version == version)))
                except ValueError:
                    pass
            return tuple(sorted(p.casefold() for p in parts))
        def protocol(value):
            return {'6': 'tcp', '17': 'udp', '256': 'any', '': 'any'}.get(str(value).casefold(), str(value).casefold())
        program = record.get('program', record.get('path', ''))
        program = '' if str(program).casefold() in {'any', ''} else normalize_path(program)
        return (record.get('enabled', True) is True
                and str(record.get('action', '')).casefold() == expected['action'].casefold()
                and direction_name(record.get('direction')) == direction_name(expected['direction'])
                and program == (normalize_path(expected.get('path')) or '')
                and protocol(record.get('protocol', 'Any')) == protocol(expected.get('protocol', 'Any'))
                and values(record.get('addresses'), True) == values(expected.get('addresses'), True)
                and str(record.get('profile', 'Any')).casefold() in {'any', '0'}
                and values(record.get('local_addresses'), True) == values(['Any'], True)
                and values(record.get('local_ports')) == values(expected.get('local_ports'))
                and values(record.get('remote_ports')) == values(expected.get('remote_ports')))

    def _enforcement_for(self, expected, records):
        by_name = {}
        for record in records:
            by_name.setdefault(record['name'], []).append(record)
        matches = [by_name.get(rule['name'], []) for rule in expected]
        if not any(matches):
            return 'Missing'
        if any(len(group) != 1 for group in matches):
            return 'Partial'
        if any(not group[0].get('enabled', True) for group in matches):
            return 'Disabled'
        return 'Verified' if all(self._native_record_matches(group[0], rule)
                                 for group, rule in zip(matches, expected)) else 'Changed'

    def _reconcile_native_rules_locked(self, records):
        """Keep intended policy; publish only a fully checked native observation.

        Caller owns firewall_lock. No native I/O runs while holding the model lock.
        Drift is repaired by the normal verified edit transactions, never refresh.
        """
        with self.lock:
            blocked = copy.deepcopy(self.blocked_paths)
            allowed = set(self.allowed_apps)
            ports = copy.deepcopy(self.global_ports)
            blocks, allows = {}, {}
            states = {}
            for norm, data in blocked.items():
                base = self.app_rule_base(None, data.get('path', norm))
                expected = [{'name': base + ('_In' if side == 'in' else '_Out'),
                             'path': data.get('path', norm), 'action': 'Block',
                             'direction': 'Inbound' if side == 'in' else 'Outbound'}
                            for side in ('in', 'out') if data.get(side)]
                states['app', norm] = data['_enforcement'] = self._enforcement_for(expected, records)
            for key, rule in ports.items():
                states['port', key] = rule['_enforcement'] = self._enforcement_for(
                    self._port_firewall_rules({key: rule}), records)
            self.verified_blocked_paths = self._blocked_from_records(records)
            self.observed_app_paths = {r.get('normalized_path') for r in records
                                       if not r.get('is_global') and not r.get('is_hold')}
            # Observed native blocks take precedence over a stored Allow exclusion.
            observed = {}
            for record in records:
                if record.get('is_global') or record.get('is_hold') or str(record.get('action')).casefold() != 'block':
                    continue
                norm = record.get('normalized_path')
                if not norm:
                    continue
                data = observed.setdefault(norm, {'path': record['path'], 'in': False, 'out': False, 'records': []})
                data['records'].append(record)
                for side in direction_set(record.get('direction')):
                    data[side] = True
            for norm, data in observed.items():
                if norm not in blocked:
                    members = data.pop('records')
                    if not any(r.get('enabled', True) for r in members):
                        state = 'Disabled'
                    elif not all(r.get('enabled', True) for r in members):
                        state = 'Partial'
                    else:
                        state = 'Observed' if norm in self.verified_blocked_paths else 'Changed'
                    blocked[norm] = dict(data, _enforcement=state, _native_only=True)
            self.rule_enforcement = states
            return blocked, allowed, blocks, allows, ports

    def _invalidate_native_observation(self):
        with self.lock:
            self.rule_enforcement = {key: 'Unknown' for key in getattr(self, 'rule_enforcement', {})}
            self.verified_blocked_paths = {}

    @staticmethod
    def _blocked_from_records(records):
        blocked = {}
        for record in records:
            if record['is_global'] or record['is_hold'] or record['action'].casefold() != 'block' or not record.get('enabled', True):
                continue
            norm = record['normalized_path']
            if not norm:
                continue
            if not FirewallMixin._native_record_matches(record, dict(
                    record, action='Block', addresses=['Any'], protocol='Any',
                    local_ports=['Any'], remote_ports=['Any'])):
                continue
            data = blocked.setdefault(norm, {'in': False, 'out': False, 'path': record['path']})
            direction = record['direction'].casefold()
            data['in'] |= 'in' in direction
            data['out'] |= 'out' in direction
        return blocked

    def sync_rule_cache(self):
        with self.firewall_lock:
            records = self.get_firewall_rules()
            return self._reconcile_native_rules_locked(records)
