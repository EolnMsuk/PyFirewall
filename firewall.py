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
from tkinter import messagebox

from constants import (
    AUTO_HOLD_PREFIX,
    CREATE_NO_WINDOW,
    FIREWALL_COMMAND_TIMEOUT,
    FIREWALL_PROFILE_BACKUP_FILE,
    GLOBAL_ALLOW_PREFIX,
    GLOBAL_BLOCK_PREFIX,
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
    error_details,
    is_global_target,
    is_ip,
    log_internal_error,
    normalize_path,
    normalize_target,
)

class FirewallMixin:
    """Methods composed into FirewallMonitorApp; state is owned by that application."""

    @staticmethod
    def _direction_from_flags(data):
        return 'Both' if data['in'] and data['out'] else 'Inbound' if data['in'] else 'Outbound'

    # Command execution and verified transactions

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

    def _replace_rule_records(self, previous, desired_names, apply, apply_first=False, preserve_holds=False):
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
                    self.save_settings()
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
    $p = if ($r.DisplayName -like 'PyFirewall_GlobalPort_*') {
      Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction Stop | Select-Object -First 1
    } else { $null }
    [PSCustomObject]@{
      DisplayName=[string]$r.DisplayName
      Action=[string]$r.Action
      Direction=[string]$r.Direction
      Addresses=@((Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction Stop).RemoteAddress)
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
            global_rule = name.startswith((GLOBAL_BLOCK_PREFIX, GLOBAL_ALLOW_PREFIX, GLOBAL_PORT_PREFIX))
            records.append({'name': name, 'action': str(item.get('Action', '') or ''), 'direction': str(item.get('Direction', '') or ''), 'path': '' if global_rule else display_path(item.get('Program', '')), 'normalized_path': '' if global_rule else normalize_path(item.get('Program', '')), 'is_global': global_rule, 'is_hold': name.startswith(AUTO_HOLD_PREFIX), 'addresses': item.get('Addresses', [])})
            if name.startswith(GLOBAL_PORT_PREFIX):
                records[-1].update(is_port=True, protocol=item.get('Protocol', ''),
                                   local_ports=item.get('LocalPorts', []), remote_ports=item.get('RemotePorts', []))
        return records

    def app_rule_base(self, proc_name, exe_path, kind='Block'):
        base = re.sub('[^A-Za-z0-9_.-]+', '_', os.path.splitext(os.path.basename(exe_path))[0] or proc_name or 'Process')[:60]
        digest = hashlib.sha1(normalize_path(exe_path).encode('utf-8', 'ignore')).hexdigest()[:8]
        return f'PyFirewall_{kind}_{base}_{digest}'

    def global_rule_base(self, target, allow, include_domain=False):
        digest = hashlib.sha1(normalize_target(target).encode('utf-8')).hexdigest()[:12]
        label = (normalize_target(target).encode('idna').decode('ascii') + '_'
                 if include_domain and not is_ip(target) else '')
        return f'{(GLOBAL_ALLOW_PREFIX if allow else GLOBAL_BLOCK_PREFIX)}{label}{digest}'

    def _global_rule_names(self, target, allow):
        # Recognize installations that used only a hash as the rule identifier.
        return {base + '_' + side for base in (self.global_rule_base(target, allow),
                                              self.global_rule_base(target, allow, include_domain=True))
                for side in ('In', 'Out')}

    @staticmethod
    def _parse_port_rules(entries):
        if not isinstance(entries, list):
            raise ValueError('Global port rules must be a JSON array.')
        result = {}
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError('Invalid global port rule.')
            scope = str(entry.get('scope', '')).lower()
            action = str(entry.get('action', '')).title()
            raw = entry.get('port', '')
            target = normalize_target(entry.get('target', ''))
            if scope not in {'local', 'remote'} or action not in {'Allow', 'Block'}:
                raise ValueError('A global port rule requires Local/Remote and Allow/Block.')
            protocol = str(entry.get('protocol', 'TCP/UDP')).upper()
            if protocol not in {'TCP/UDP', 'TCP', 'UDP'}:
                raise ValueError('Protocol must be TCP/UDP, TCP or UDP.')
            if raw is None and target:
                port = None
            elif isinstance(raw, bool) or not str(raw).isdecimal() or not 1 <= int(raw) <= 65535:
                raise ValueError('Port numbers must be integers from 1 to 65535.')
            else:
                port = int(raw)
            rule = {'scope': scope, 'port': port, 'action': action}
            if protocol != 'TCP/UDP':
                rule['protocol'] = protocol
            raw_direction = str(entry.get('direction', 'Both')).casefold()
            if raw_direction not in {'both', 'in', 'inbound', 'incoming'}:
                raise ValueError('Global port rules must apply to Both or Inbound directions.')
            if direction_name(raw_direction) == 'Inbound':
                rule['direction'] = 'Inbound'
            key = f'{scope}:{port}'
            if protocol != 'TCP/UDP':
                key += f':{protocol}'
            if target:
                target = ', '.join(global_targets(target))
                try:
                    target = str(ipaddress.ip_network(target, strict=False)) if '/' in target else str(ipaddress.ip_address(target))
                except ValueError:
                    pass
                rule['target'] = target
                addresses = entry.get('addresses', [])
                if not isinstance(addresses, (list, tuple)):
                    raise ValueError('Global rule addresses must be an array.')
                if addresses:
                    rule['addresses'] = sorted({normalize_address(address) for address in addresses})
                if ',' in target and 'target_addresses' in entry:
                    saved_targets = entry['target_addresses']
                    if not isinstance(saved_targets, dict):
                        raise ValueError('Target addresses must be an object.')
                    rule['target_addresses'] = {}
                    for part in global_targets(target):
                        values = saved_targets.get(part, [])
                        if not isinstance(values, (list, tuple)):
                            raise ValueError('Target addresses must be arrays.')
                        rule['target_addresses'][part] = sorted({normalize_address(value) for value in values})
                key += f':{target}'
            result[key] = rule
        return result

    @staticmethod
    def _port_firewall_rules(ports, all_directions=False):
        """One logical rule expands to TCP/UDP rules for its selected directions."""
        rules = []
        for r in ports.values():
            suffix = ('_' + hashlib.sha1(r['target'].encode('utf-8')).hexdigest()[:12]
                      if r.get('target') else '')
            # Distinct logical policies may overlap without sharing native names.
            if r.get('protocol', 'TCP/UDP') != 'TCP/UDP':
                suffix += '_' + r['protocol']
            directions = ('Inbound', 'Outbound') if all_directions else (
                ('Inbound',) if r.get('direction') == 'Inbound' else ('Inbound', 'Outbound'))
            rules.extend([{'name': f"{GLOBAL_PORT_PREFIX}{r['scope']}_{r['port']}{suffix}_{number}_{direction}",
                 'action': r['action'], 'direction': direction, 'path': '', 'is_port': True,
                 'protocol': protocol, 'addresses': list(r.get('addresses') or ['Any']),
                 'local_ports': [str(r['port'])] if r['scope'] == 'local' and r['port'] else ['Any'],
                 'remote_ports': [str(r['port'])] if r['scope'] == 'remote' and r['port'] else ['Any']}
                for protocol, number in (('TCP', 6), ('UDP', 17))
                if r.get('protocol', 'TCP/UDP') in {'TCP/UDP', protocol} for direction in directions])
        return rules

    def matching_global_port_rules(self, row):
        if str(row.get('protocol', '')).upper() not in {'TCP', 'UDP', '6', '17'}:
            return {}
        with self.lock:
            return {key: dict(rule) for key, rule in getattr(self, 'global_ports', {}).items()
                    if (rule['port'] is None or str(row.get('lport' if rule['scope'] == 'local' else 'dport')) == str(rule['port']))
                    and rule.get('protocol', 'TCP/UDP') in {'TCP/UDP', {'6': 'TCP', '17': 'UDP'}.get(str(row.get('protocol')), str(row.get('protocol', '')).upper())}
                    and (row.get('direction') is None or
                         direction_set(row['direction']) <= direction_set(rule.get('direction', 'Both')))
                    and (not rule.get('target') or self._global_match(
                        {rule['target']: rule}, row.get('dst_ip', ''), row.get('domain', ''), row.get('direction')))}

    def global_port_action(self, row):
        actions = [rule['action'] for rule in self.matching_global_port_rules(row).values()]
        return 'Block' if 'Block' in actions else 'Allow' if 'Allow' in actions else None

    def apply_global_port_rules(self, entries):
        return self._apply_rule_batch((), port_updates=entries)

    @staticmethod
    def _ps_quote(value):
        return "'" + str(value).replace("'", "''") + "'"

    # Application rule creation and compatibility fallbacks

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
        """Compatibility path for one application rule, including netsh fallback."""
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
                    addresses = record.get('addresses', [])
                    if isinstance(addresses, str):
                        addresses = [addresses]
                    side = 'in' if direction_name(record['direction']) == 'Inbound' else 'out'
                    self.run_netsh(['add', 'rule', f'name={name}', f'dir={side}',
                                    'action=' + record['action'].lower(),
                                    'remoteip=' + ','.join(addresses), 'enable=yes'])
                    created.append(name)
                    continue
                if not path:
                    raise ValueError(f'Missing program for rule {name}')
                action = 'Allow' if str(record.get('action', '')).casefold() == 'allow' else 'Block'
                suffixes = {'in': 'In', 'out': 'Out'}
                for side in direction_set(record.get('direction', 'Both')):
                    rule_name = name if name.endswith(f"_{suffixes[side]}") else f"{name}_{suffixes[side]}"
                    self._add_app_firewall_rule(rule_name, path, side, action)
                    created.append(rule_name)
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
        try:
            target = str(ipaddress.ip_network(target, strict=False)) if '/' in target else str(ipaddress.ip_address(target))
        except ValueError:
            pass
        addresses = self.resolve_global_target(target)
        if not addresses:
            raise ValueError('Enter a valid IP address or a domain that resolves to at least one IP address.')
        base = self.global_rule_base(target, allow)
        names = self._global_rule_names(target, allow) | self._global_rule_names(target, not allow)
        previous = [r for r in self.get_firewall_rules() if r['name'] in names]
        def create():
            for side in sorted(direction_set(direction)):
                name = f'{base}_{side.title()}'
                self.run_netsh(['add', 'rule', f'name={name}', f'dir={side}',
                                'action=' + ('allow' if allow else 'block'),
                                'remoteip=' + ','.join(addresses), 'enable=yes'])
            records = {r['name']: r for r in self.get_firewall_rules()}
            for side, expected_direction in (('In', 'Inbound'), ('Out', 'Outbound')):
                if side.casefold() not in direction_set(direction):
                    continue
                record = records.get(f'{base}_{side}')
                if not record or record['action'].casefold() != ('allow' if allow else 'block') or direction_name(record['direction']) != expected_direction:
                    raise RuntimeError(f'Global firewall rule verification failed: {base}_{side}')
        self._replace_rule_records(previous, names, create)
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
        return True

    def restore_saved_rules_locked(self):
        with self.lock:
            allowed = list(self.allowed_apps)
            pending = list(self.pending_rules)
            global_blocks = {target: data.get('direction', 'Both') for target, data in self.global_blocks.items()}
            global_allows = {target: data.get('direction', 'Both') for target, data in self.global_allows.items()}
            ports = list(getattr(self, 'global_ports', {}).values())
        records = self.get_firewall_rules()
        requests = [(path, True, 'both', False) for path in allowed]
        for rule in pending:
            path = display_path(rule['path'])
            norm = normalize_path(path)
            wanted = direction_set(rule['direction'])
            actual = set()
            for record in records:
                if record['normalized_path'] == norm and not record['is_hold'] and record['action'].casefold() == 'block':
                    d = record['direction'].casefold()
                    if 'in' in d:
                        actual.add('in')
                    if 'out' in d:
                        actual.add('out')
            if actual != wanted:
                requests.append((path, False, rule['direction'], False))
        requests.extend((target, False, direction, True) for target, direction in global_blocks.items())
        requests.extend((target, True, direction, True) for target, direction in global_allows.items())
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
            if norm in self.allowed_apps:
                return 'allowed'
            data = self.blocked_paths.get(norm, {})
            if data.get('in') and data.get('out'):
                return 'blocked_both'
            if data.get('in'):
                return 'blocked_in'
            if data.get('out'):
                return 'blocked_out'
            return ''

    def get_rule_status_display(self, exe_path):
        status = self.get_rule_status(exe_path)
        return {'allowed': 'Allowed', 'blocked_both': 'Blocked', 'blocked_in': 'Blocked (In)', 'blocked_out': 'Blocked'}.get(status, '—')

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

    def is_globally_blocked(self, remote_ip, domain='', direction=None):
        with self.lock:
            return self._global_match(self.global_blocks, remote_ip, domain, direction)

    def is_globally_allowed(self, remote_ip, domain='', direction=None):
        with self.lock:
            return self._global_match(self.global_allows, remote_ip, domain, direction)

    def connection_has_rule(self, exe_path, remote_ip, domain, direction, local_port=None, remote_port=None, protocol='TCP'):
        if self.global_port_action({'lport': local_port, 'dport': remote_port, 'protocol': protocol,
                                    'dst_ip': remote_ip, 'domain': domain, 'direction': direction}):
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
        self.refresh_rules(force=True)

    def _rule_is_duplicate(self, target, allow=False, direction='both', global_target=False):
        """Use the managed-rule cache; never launch a firewall command to check."""
        with self.lock:
            if global_target:
                target = normalize_target(target)
                collection = self.global_allows if allow else self.global_blocks
                return target in collection and direction_set(collection[target].get('direction', 'Both')) == direction_set(direction)
            norm = normalize_path(target)
            if allow:
                return norm in self.allowed_apps and norm not in self.blocked_paths
            data = self.blocked_paths.get(norm, {})
            actual = {side for side in ('in', 'out') if data.get(side)}
            return norm not in self.allowed_apps and actual == direction_set(direction)

    def _warn_duplicate_rule(self, target, quiet=False):
        text = f'The requested rule already exists and was skipped:\n{target}'
        self.queue_alert('Info', 'Duplicate rule', '', '', text)

    def _persist_rule_changes(self):
        if self.save_settings() is False:
            detail = getattr(self, 'settings_save_error', None) or 'Could not write the saved configuration.'
            raise RuntimeError(f'Firewall changes were applied, but could not be saved for the next launch.\n{detail}')

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
    $params = @{
        Name=[string]$rule.name; DisplayName=[string]$rule.name
        Direction=[string]$rule.direction; Action=[string]$rule.action
        Enabled='True'; Profile='Any'; ErrorAction='Stop'
    }
    if ($rule.is_port) {
        $params.Protocol=[string]$rule.protocol
        $params.LocalPort=[string[]]$rule.local_ports
        $params.RemotePort=[string[]]$rule.remote_ports
        if ($rule.addresses) { $params.RemoteAddress=[string[]]$rule.addresses }
    }
    elseif ($rule.path) { $params.Program=[string]$rule.path }
    else { $params.RemoteAddress=[string[]]$rule.addresses }
    New-NetFirewallRule @params | Out-Null
}
foreach ($rule in $rules) {
    $r = Get-NetFirewallRule -Name $rule.name -ErrorAction Stop
    if (@($r).Count -ne 1 -or [string]$r.Enabled -ne 'True' -or
        [string]$r.Action -ne $rule.action -or [string]$r.Direction -ne $rule.direction) {
        throw ('Firewall rule verification failed: ' + $rule.name)
    }
    if ($rule.is_port) {
        $p = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction Stop | Select-Object -First 1
        $protocol = [string]$p.Protocol
        $expected = [string]$rule.protocol
        if ($protocol -eq '6') { $protocol = 'TCP' }
        if ($protocol -eq '17') { $protocol = 'UDP' }
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
        if ([string]$program.Program -ne 'Any' -or
            (Compare-Object $expectedKeys $actualKeys) -or
            (Compare-Object @('Any') @($address.LocalAddress))) {
            throw ('Wrong application or address filter for port rule: ' + $rule.name)
        }
    } elseif ($rule.path) {
        $filter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction Stop |
            Select-Object -First 1
        if (-not $filter -or -not [string]::Equals([string]$filter.Program,
            [string]$rule.path, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw ('Wrong program for firewall rule: ' + $rule.name)
        }
    } else {
        $actual = @((Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction Stop).RemoteAddress)
        $expectedKeys = @($rule.addresses | ForEach-Object { Get-AddressKey $_ } | Sort-Object -Unique)
        $actualKeys = @($actual | ForEach-Object { Get-AddressKey $_ } | Sort-Object -Unique)
        if (-not $actualKeys.Count -or (Compare-Object $expectedKeys $actualKeys)) {
            throw ('Wrong addresses for firewall rule: ' + $rule.name)
        }
    }
}
'''
        self.run_ps(command, timeout=max(FIREWALL_COMMAND_TIMEOUT, len(rules) * 2.0))

    def _commit_rule_batch(self, requests, records=None, port_updates=None, observed_addresses=None, replace_rule=None):
        """Caller holds firewall_lock; publish caches only after the transaction."""
        ports = self._parse_port_rules(port_updates or [])
        for key, rule in ports.items():
            if rule.get('target'):
                with self.lock:
                    saved = getattr(self, 'global_ports', {}).get(key, {}).get('addresses', ())
                observed = set(saved) | set(rule.get('addresses', ()))
                if ',' in rule['target']:
                    # Keep fallback addresses associated with their own target;
                    # editing out one domain must also remove its old addresses.
                    saved_targets = rule.get('target_addresses', {})
                    resolved = {part: list(self.resolve_global_target(part, saved_targets.get(part, ())))
                                for part in global_targets(rule['target'])}
                    rule['target_addresses'] = resolved
                    rule['addresses'] = sorted({address for values in resolved.values() for address in values})
                else:
                    rule['addresses'] = list(self.resolve_global_target(rule['target'], observed))
        planned, apps, globals_, global_names = [], {}, {}, set()
        for target, allow, direction, global_target in requests:
            if global_target:
                try:
                    target = str(ipaddress.ip_network(target, strict=False)) if '/' in target else str(ipaddress.ip_address(target))
                except ValueError:
                    pass
                observed = set((observed_addresses or {}).get(target, ()))
                # Retain observed endpoints on subsequent updates and after a
                # restart, including PTR names that have no forward DNS record.
                if not is_ip(target):
                    with self.lock:
                        for collection in (self.global_blocks, self.global_allows):
                            for address in collection.get(target, {}).get('addresses', ()):
                                try:
                                    observed.add(str(ipaddress.ip_address(address)))
                                except ValueError:
                                    continue
                if observed:
                    addresses = self.resolve_global_target(target, observed)
                else:
                    addresses = self.resolve_global_target(target)
                if not addresses:
                    raise ValueError(f'No addresses found for {target}.')
                globals_[target] = (allow, addresses, direction_name(direction))
                base = self.global_rule_base(target, allow, include_domain=True)
                global_names.update(self._global_rule_names(target, allow))
                global_names.update(self._global_rule_names(target, not allow))
                for suffix, side in (('In', 'Inbound'), ('Out', 'Outbound')):
                    if suffix.casefold() not in direction_set(direction):
                        continue
                    planned.append({'name': base + '_' + suffix, 'direction': side,
                                    'action': 'Allow' if allow else 'Block', 'path': '',
                                    'addresses': list(addresses)})
            else:
                norm = normalize_path(target)
                wanted = direction_set(direction)
                apps[norm] = (target, allow, wanted)
                # Application allows are exclusions from monitoring; as in the
                # single-rule path they remove blocks without creating allow rules.
                if not allow:
                    base = self.app_rule_base(None, target)
                    for side in sorted(wanted):
                        planned.append({'name': base + ('_In' if side == 'in' else '_Out'),
                                        'direction': 'Inbound' if side == 'in' else 'Outbound',
                                        'action': 'Block', 'path': target})
        port_rules = self._port_firewall_rules(ports)
        planned.extend(port_rules)
        # Direction changes must also delete the old outbound rules.
        global_names.update(rule['name'] for rule in self._port_firewall_rules(ports, all_directions=True))
        if replace_rule:
            kind, key = replace_rule
            if kind == 'port':
                with self.lock:
                    old = getattr(self, 'global_ports', {}).get(key)
                if old:
                    global_names.update(r['name'] for r in self._port_firewall_rules({key: old}, all_directions=True))
            else:
                global_names.update(self._global_rule_names(key, kind == 'allow'))
        if records is None:
            records = self.get_firewall_rules()
        previous = [r for r in records if r.get('normalized_path') in apps or r['name'] in global_names
                    or (globals_ and r.get('is_hold'))]
        # Keep temporary blocks in place until all replacement rules verify.
        self._replace_rule_records(previous, [r['name'] for r in planned],
                                   lambda: self._create_rule_batch(planned), preserve_holds=True)
        with self.lock:
            if replace_rule:
                kind, key = replace_rule
                store = self.global_ports if kind == 'port' else self.global_allows if kind == 'allow' else self.global_blocks
                store.pop(key, None)
            if ports:
                self.global_ports.update(ports)
            for norm, (path, allow, wanted) in apps.items():
                if allow:
                    self.allowed_apps.add(norm)
                    self.blocked_paths.pop(norm, None)
                else:
                    self.allowed_apps.discard(norm)
                    self.blocked_paths[norm] = {'path': path, 'in': 'in' in wanted, 'out': 'out' in wanted}
            self.connection_rates = {k: v for k, v in self.connection_rates.items() if k[0] not in apps}
            self.upload_alerted = {k for k in self.upload_alerted if k[0] not in apps or not apps[k[0]][1]}
            for target, (allow, addresses, direction) in globals_.items():
                destination = self.global_allows if allow else self.global_blocks
                other = self.global_blocks if allow else self.global_allows
                destination[target] = {'addresses': addresses, 'direction': direction_name(direction)}
                other.pop(target, None)
        return apps, bool(globals_)

    def _apply_rule_batch(self, requests, quiet=False, port_updates=None, observed_addresses=None, replace_rule=None, report=False):
        """Apply a whole selection/import with one snapshot, save and refresh."""
        try:
            ports = self._parse_port_rules(port_updates or [])
        except ValueError as exc:
            self.queue_alert('High', 'Global port rule', '', '', str(exc))
            if not quiet:
                messagebox.showerror('Global Port Rule', str(exc), parent=self.root)
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
        if not selected and not ports:
            if report and not quiet:
                self._show_rule_result('Rule Update', 'No applicable rules were selected. No rules were changed.')
            return True
        try:
            with self.firewall_lock:
                pending, duplicates = [], []
                port_pending = []
                with self.lock:
                    for key, rule in ports.items():
                        existing = getattr(self, 'global_ports', {}).get(key, {})
                        same_policy = {k: v for k, v in existing.items() if k != 'addresses'} == {
                            k: v for k, v in rule.items() if k != 'addresses'}
                        if not replace_rule and same_policy and set(rule.get('addresses', ())) <= set(existing.get('addresses', ())):
                            duplicates.append(key)
                        else:
                            port_pending.append(rule)
                for request in selected.values():
                    target, allow, _, global_target = request
                    collection = self.global_allows if allow else self.global_blocks
                    observed = (observed_addresses or {}).get(target, ()) if global_target else ()
                    covered = set(observed) <= set(collection.get(target, {}).get('addresses', ()))
                    if not replace_rule and self._rule_is_duplicate(*request) and covered:
                        duplicates.append(request[0])
                    else:
                        pending.append(request)
                if pending or port_pending:
                    options = {'port_updates': port_pending} if port_pending else {}
                    if observed_addresses:
                        options['observed_addresses'] = observed_addresses
                    if replace_rule:
                        options['replace_rule'] = replace_rule
                    apps, global_changed = self._commit_rule_batch(pending, **options)
                    if global_changed:
                        self._invalidate_auto_prompts(close_dialog=True)
                    else:
                        for norm in apps:
                            self._cancel_app_prompt(norm)
            if pending or port_pending:
                self.rules_changed()
                self._persist_rule_changes()
            elif duplicates and getattr(self, 'settings_save_error', None):
                self._persist_rule_changes()
        except Exception as exc:
            details = error_details(exc)
            log_internal_error('rule_batch', exc)
            self.queue_alert('High', 'Bulk rules', '', '', f'Firewall rule update failed: {details}')
            if not quiet:
                messagebox.showerror('Rule Update Failed', details)
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
            messagebox.showwarning('Some Rules Were Skipped', text)

    # Single-rule actions and removal

    def block_executable(self, exe_path, proc_name=None, direction='both', refresh=True, quiet=False, update_ui=True):
        path = display_path(exe_path)
        norm = normalize_path(path)
        if not norm:
            return False
        proc_name = proc_name or os.path.splitext(os.path.basename(path))[0] or 'Process'
        if self._rule_is_duplicate(path, direction=direction):
            self._warn_duplicate_rule(path, quiet)
            return True
        try:
            with self.firewall_lock:
                if self._rule_is_duplicate(path, direction=direction):
                    self._warn_duplicate_rule(path, quiet)
                    return True  # The requested state is already satisfied.
                records = self.get_firewall_rules()
                previous = [r for r in records if r['normalized_path'] == norm]
                base = self.app_rule_base(proc_name, path, 'Block')
                replacing_hold = bool(previous) and all(r.get('is_hold') for r in previous)
                self._replace_rule_records(previous, (base + '_In', base + '_Out'),
                                           lambda: self.add_app_rules(proc_name, path, direction, kind='Block'),
                                           apply_first=replacing_hold)
                with self.lock:
                    wanted = direction_set(direction)
                    self.allowed_apps.discard(norm)
                    self.blocked_paths[norm] = {'in': 'in' in wanted, 'out': 'out' in wanted, 'path': path}
                    self.connection_rates = {k: v for k, v in self.connection_rates.items() if k[0] != norm}
            if update_ui:
                self._cancel_app_prompt(norm)
            if refresh and update_ui:
                self.rules_changed()
            self._persist_rule_changes()
            return True
        except Exception as exc:
            self.queue_alert('High', path, '', '', f'Firewall rule update failed: {exc}')
            if not quiet:
                messagebox.showerror('Block Failed', f'{proc_name}\n\n{exc}')
            return False

    def allow_executable(self, exe_path, refresh=True, quiet=False, update_ui=True):
        path = display_path(exe_path)
        norm = normalize_path(path)
        if not norm:
            return False
        if self._rule_is_duplicate(path, allow=True):
            self._warn_duplicate_rule(path, quiet)
            return True
        try:
            with self.firewall_lock:
                if self._rule_is_duplicate(path, allow=True):
                    self._warn_duplicate_rule(path, quiet)
                    return True
                records = self.get_firewall_rules()
                previous = [r for r in records if r['normalized_path'] == norm]
                self._replace_rule_records(previous, (), lambda: None)
                with self.lock:
                    self.allowed_apps.add(norm)
                    self.blocked_paths.pop(norm, None)
                    self.connection_rates = {k: v for k, v in self.connection_rates.items() if k[0] != norm}
                    self.upload_alerted = {k for k in self.upload_alerted if k[0] != norm}
            if update_ui:
                self._cancel_app_prompt(norm)
            if refresh and update_ui:
                self.rules_changed()
            self._persist_rule_changes()
            return True
        except Exception as exc:
            self.queue_alert('High', path, '', '', f'Firewall rule update failed: {exc}')
            if not quiet:
                messagebox.showerror('Allow Failed', f'{path}\n\n{exc}')
            return False

    def add_global_rule(self, target, allow, refresh=True, quiet=False, direction='both'):
        target = normalize_target(target)
        if not target:
            return False
        if self._rule_is_duplicate(target, allow, direction, global_target=True):
            self._warn_duplicate_rule(target, quiet)
            return True
        try:
            with self.firewall_lock:
                if self._rule_is_duplicate(target, allow, direction, global_target=True):
                    self._warn_duplicate_rule(target, quiet)
                    return True
                target, addresses = self.add_global_rule_sync(target, allow, direction)
                with self.lock:
                    destination = self.global_allows if allow else self.global_blocks
                    other = self.global_blocks if allow else self.global_allows
                    destination[target] = {'addresses': addresses, 'direction': direction_name(direction)}
                    other.pop(target, None)
            try:
                self.release_auto_holds()
            except Exception as exc:
                self.queue_alert('High', 'Temporary blocks', '', target, f'Global rule applied, but pending blocks could not be released: {exc}')
            if refresh:
                self.rules_changed()
            self._persist_rule_changes()
            return True
        except Exception as exc:
            details = error_details(exc)
            log_internal_error(f'global_rule {"allow" if allow else "block"} {target}', exc)
            self.queue_alert('High', 'Global rule', '', target, f'Firewall rule update failed: {details}')
            if not quiet:
                messagebox.showerror('Global Rule Failed', f"{('Allow' if allow else 'Block')} {target}\n\n{details}")
            return False

    def remove_rule(self, status, path, refresh=True):
        return self._remove_rule_batch(((status, path),), refresh=refresh)

    def _managed_rule_category(self, status, path):
        status = str(status).casefold()
        if status == 'blocked (in) (global)':
            with self.lock:
                return 'port' if str(path) in getattr(self, 'global_ports', {}) else 'global'
        if status in {'global port block', 'global port allow', 'allowed (global)', 'blocked (global)'}:
            return 'port'
        if status in {'global block', 'global allow'}:
            return 'global'
        return 'app'

    def _remove_rule_batch(self, requests, refresh=True):
        apps, globals_, ports = set(), set(), set()
        for status, path in requests:
            status = str(status).casefold()
            category = self._managed_rule_category(status, path)
            if category == 'port':
                ports.add(str(path))
            elif category == 'global':
                target = normalize_target(str(path).split(' (', 1)[0])
                if target:
                    globals_.add((target, status == 'global allow'))
            else:
                norm = normalize_path(path)
                if norm:
                    apps.add(norm)
        if not apps and not globals_ and not ports:
            return False
        try:
            with self.firewall_lock:
                records = self.get_firewall_rules()
                names = {name for target, allow in globals_
                         for name in self._global_rule_names(target, allow)}
                with self.lock:
                    selected_ports = {key: rule for key, rule in getattr(self, 'global_ports', {}).items() if key in ports}
                names.update(rule['name'] for rule in self._port_firewall_rules(selected_ports, all_directions=True))
                previous = [r for r in records if r.get('normalized_path') in apps or r['name'] in names]
                self._replace_rule_records(previous, (), lambda: None)
                with self.lock:
                    for key in ports:
                        self.global_ports.pop(key, None)
                    for target, allow in globals_:
                        (self.global_allows if allow else self.global_blocks).pop(target, None)
                    for norm in apps:
                        self.allowed_apps.discard(norm)
                        self.blocked_paths.pop(norm, None)
                for norm in apps:
                    self._cancel_app_prompt(norm)
            if refresh:
                self.rules_changed()
            self._persist_rule_changes()
            return True
        except Exception as exc:
            messagebox.showerror('Remove Rule Failed', str(exc))
            return False

    # Cache reconciliation

    @staticmethod
    def _blocked_from_records(records):
        blocked = {}
        for record in records:
            if record['is_global'] or record['is_hold'] or record['action'].casefold() != 'block':
                continue
            norm = record['normalized_path']
            if not norm:
                continue
            data = blocked.setdefault(norm, {'in': False, 'out': False, 'path': record['path']})
            direction = record['direction'].casefold()
            data['in'] |= 'in' in direction
            data['out'] |= 'out' in direction
        return blocked

    def sync_rule_cache(self):
        with self.firewall_lock:
            records = self.get_firewall_rules()
            blocked = self._blocked_from_records(records)
            with self.lock:
                self.allowed_apps.difference_update(blocked)
                self.blocked_paths = blocked
                names = {r['name'] for r in records}
                for allow, collection in ((False, self.global_blocks), (True, self.global_allows)):
                    for target in list(collection):
                        matching = self._global_rule_names(target, allow) & names
                        if not matching:
                            collection.pop(target, None)
                        else:
                            sides = {name.rsplit('_', 1)[-1] for name in matching}
                            collection[target]['direction'] = ('Both' if len(sides) == 2 else
                                                               'Inbound' if 'In' in sides else 'Outbound')
