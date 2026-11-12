"""Packet capture, process attribution, DNS caching and traffic accounting."""

import ipaddress
import psutil
import queue
import socket
import threading
import time
from collections import deque

from scapy.all import DNS, IP, IPv6, TCP, UDP, conf, sniff

from constants import (
    DNS_CACHE_MAX_ENTRIES,
    DNS_CACHE_TTL,
    DNS_MAX_PENDING,
    DNS_MAX_WORKERS,
    TRAFFIC_MAX_IP_ENTRIES,
    TRAFFIC_MAX_PROC_IP_ENTRIES,
    TRAFFIC_PRUNE_INTERVAL,
    WATCH_PORTS,
    RATE_MAX_KEYS,
)
from helpers import address_networks, is_global_target, is_ip, log_internal_error, mb, normalize_path, normalize_target

class MonitoringMixin:
    """Methods composed into FirewallMonitorApp; state is owned by that application."""

    # Process and socket attribution

    def refresh_process_cache(self):
        now = time.monotonic()
        if now - self.cache_time < 2:
            return
        socket_cache, listener_cache = {}, {}
        try:
            local_addresses = {normalize_target(a.address.split('%', 1)[0])
                               for addresses in psutil.net_if_addrs().values()
                               for a in addresses if a.family in (socket.AF_INET, socket.AF_INET6)}
            local_addresses.update({'127.0.0.1', '::1'})
            for conn in psutil.net_connections(kind='inet'):
                if not conn.laddr or not conn.pid:
                    continue
                family_key = int(conn.family)
                proto = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                local_ip = normalize_target(conn.laddr.ip.split('%', 1)[0])
                local_port = conn.laddr.port
                if conn.raddr:
                    remote_ip = normalize_target(conn.raddr.ip.split('%', 1)[0])
                    key = (family_key, proto, local_ip, local_port, remote_ip, conn.raddr.port)
                    socket_cache.setdefault(key, set()).add(conn.pid)
                elif proto == 'UDP' or conn.status == psutil.CONN_LISTEN:
                    listener_cache.setdefault((family_key, proto, local_ip, local_port), set()).add(conn.pid)
            self.local_addresses = local_addresses
            self.socket_process_cache = socket_cache
            self.listener_process_cache = listener_cache
            self.cache_time = now
        except (psutil.Error, OSError) as exc:
            self.socket_process_cache = {}
            self.listener_process_cache = {}
            log_internal_error('refresh_process_cache', exc)

    def get_process_info(self, local_ip, local_port, remote_ip, remote_port, proto, family_key):
        self.refresh_process_cache()
        local_ip_n = normalize_target(local_ip.split('%', 1)[0])
        remote_ip_n = normalize_target(remote_ip.split('%', 1)[0])
        if local_ip_n not in self.local_addresses:
            return None, None, None
        candidates = self.socket_process_cache.get((family_key, proto, local_ip_n, int(local_port), remote_ip_n, int(remote_port)))
        if candidates is None:
            candidates = set(self.listener_process_cache.get((family_key, proto, local_ip_n, int(local_port)), ()))
            wildcard = '0.0.0.0' if family_key == int(socket.AF_INET) else '::'
            candidates.update(self.listener_process_cache.get((family_key, proto, wildcard, int(local_port)), ()))
        if len(candidates) != 1:
            return None, None, None
        pid = next(iter(candidates))
        try:
            proc = psutil.Process(pid)
            return proc.name(), proc.exe(), pid
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None, None, None

    # Bounded DNS workers and cache

    def observe_dns_response(self, packet):
        """Learn display hints from captured DNS; never use hints to enforce rules."""
        if DNS not in packet:
            return
        dns = packet[DNS]
        if not dns.qr or dns.rcode or dns.tc or not dns.qd:
            return

        def name(value):
            if isinstance(value, bytes):
                value = value.decode('ascii')
            value = normalize_target(value)
            return value if is_global_target(value) and not is_ip(value) else ''

        try:
            query = name(dns.qd[0].qname)
            if not query or int(dns.qd[0].qtype) not in (1, 28):
                return
            answers = [dns.an[index] for index in range(min(int(dns.ancount or len(dns.an)), 128))]
            aliases = {name(rr.rrname): (name(rr.rdata), int(rr.ttl))
                       for rr in answers if int(rr.type) == 5}
            owners, owner, ttl = {}, query, DNS_CACHE_TTL
            for _ in range(16):
                if owner in owners or not owner:
                    break
                owners[owner] = ttl
                if owner not in aliases:
                    break
                owner, alias_ttl = aliases[owner]
                ttl = min(ttl, alias_ttl)
            now = time.monotonic()
            learned = {}
            for rr in answers:
                owner = name(rr.rrname)
                if int(rr.type) not in (1, 28) or owner not in owners:
                    continue
                lifetime = min(owners[owner], int(rr.ttl))
                if lifetime > 0:
                    learned[str(ipaddress.ip_address(rr.rdata))] = (query, now + lifetime)
            with self.dns_lock:
                cache = getattr(self, 'dns_observed_names', {})
                cache = {ip: entry for ip, entry in cache.items() if entry[1] > now}
                # Shared hosting may have many names; display the latest query.
                for ip, entry in learned.items():
                    cache.pop(ip, None)
                    cache[ip] = entry
                while len(cache) > DNS_CACHE_MAX_ENTRIES:
                    cache.pop(next(iter(cache)))
                self.dns_observed_names = cache
            self._notify_dns_changed(learned)
        except (ValueError, TypeError, AttributeError, UnicodeError, IndexError):
            return

    @staticmethod
    def _host_endpoint(row):
        return (normalize_target(row.get('dst_ip', '')), normalize_path(row.get('exe', '')),
                row.get('pid'), row.get('protocol'), row.get('lport'), row.get('dport'))

    @staticmethod
    def _connection_group_signature(row):
        """Display identity only; capture and enforcement keep their raw endpoints."""
        try:
            remote = str(ipaddress.ip_address(str(row.get('dst_ip', '')).strip('[]')))
            port = int(row['dport'])
            pid = int(row['pid'])
        except (KeyError, TypeError, ValueError):
            return None
        executable = normalize_path(row.get('exe', ''))
        protocol = str(row.get('protocol', '')).upper()
        direction = row.get('_first_direction', row.get('direction'))
        name = row.get('name')
        if (not isinstance(name, str) or not name.strip() or not executable or pid < 0 or protocol not in {'TCP', 'UDP'} or direction not in {'Incoming', 'Outgoing'}
                or not 1 <= port <= 65535):
            return None
        return name, pid, executable, remote, port, protocol, direction

    @staticmethod
    def _flow_identity(row):
        return row.get('_capture_id', (row.get('key'), row.get('number'), row.get('first_seen'),
                                      normalize_path(row.get('exe')), row.get('pid'), row.get('protocol'),
                                      row.get('lport'), normalize_target(row.get('dst_ip')), row.get('dport')))

    def _retain_alert_flow_totals_locked(self):
        """Attach old snapshots to their own flow, never a reused socket or PID."""
        current = {self._flow_identity(row): row for row in getattr(self, 'active_connections', {}).values()}
        for saved in getattr(self, 'alert_connections', {}).values():
            flow = current.get(self._flow_identity(saved))
            if flow is not None and self._host_endpoint(saved) == self._host_endpoint(flow):
                totals = flow.setdefault('_flow_totals', {side: flow.get(side, 0) for side in ('download', 'upload')})
                saved['_flow_totals'] = totals

    def _prune_display_groups_locked(self):
        active = {self._flow_identity(row) for row in getattr(self, 'active_connections', {}).values()}
        connections = {}
        for iid, row in getattr(self, 'connection_display_groups', {}).items():
            members = [member for member in row.get('_members', ()) if self._flow_identity(member) in active]
            if members:
                connections[iid] = self._aggregate_connection_rows(members, iid)
        self.connection_display_groups = connections
        retained = {event[0] for event in getattr(self, 'alerts', ())}
        alerts = {}
        for iid, row in getattr(self, 'alert_display_groups', {}).items():
            events = [event for event in row.get('_events', ()) if event[0] in retained]
            if not events:
                continue
            members = [getattr(self, 'alert_connections', {})[event[0]] for event in events
                       if event[0] in getattr(self, 'alert_connections', {})]
            updated = self._aggregate_connection_rows(members) if members else dict(row)
            updated['_events'] = events
            updated['_grouped'] = len(events) > 1
            alerts[iid] = updated
        self.alert_display_groups = alerts

    def _retained_host(self, row):
        identity = row.get('_display_endpoint')
        return row.get('display_host', '') if identity is None or identity == self._host_endpoint(row) else ''

    def remote_host(self, row):
        retained = self._retained_host(row)
        if retained:
            return retained
        ip = row.get('dst_ip', '')
        same_endpoint = row.get('_display_endpoint') in (None, self._host_endpoint(row))
        reverse = (row.get('domain', '') or '') if same_endpoint else ''
        friendly = ''
        if hasattr(self, 'dns_lock'):
            with self.dns_lock:
                entry = getattr(self, 'dns_observed_names', {}).get(ip)
                if entry and entry[1] > time.monotonic():
                    friendly = entry[0]
                if time.monotonic() - getattr(self, 'dns_cache_times', {}).get(ip, 0) < DNS_CACHE_TTL:
                    reverse = getattr(self, 'dns_cache', {}).get(ip) or reverse
        if friendly and friendly != reverse:
            return f'{friendly} ({reverse})' if reverse else friendly
        return reverse or friendly

    def _retain_remote_host(self, row, discover=False):
        """Save a display snapshot on this endpoint, separately from DNS/enforcement."""
        identity = self._host_endpoint(row)
        if row.get('_display_endpoint') not in (None, identity):
            row.pop('display_host', None)
            row.pop('_display_endpoint', None)
            row['domain'] = ''
        host = self.remote_host(row)
        if not host and discover and is_ip(row.get('dst_ip', '')):
            domain = self.get_cached_dns(row['dst_ip'])
            if domain:
                row['domain'] = domain
            host = self.remote_host(row)
        if host:
            row['display_host'] = host
            row['_display_endpoint'] = identity
        return host

    @staticmethod
    def _alert_remote_ip(remote):
        remote = normalize_target(remote)
        if not is_ip(remote):
            candidate, _, port = remote.rpartition(':')
            if port.isdecimal() and is_ip(candidate.strip('[]')):
                remote = candidate.strip('[]')
        return remote

    def _refresh_retained_hosts(self, ips=None, live=True, alerts=True, discover=False):
        # Snapshot application records first; never acquire dns_lock under lock.
        with self.lock:
            connections = [(key, row, dict(row)) for key, row in getattr(self, 'active_connections', {}).items()
                           if live and (ips is None or row.get('dst_ip') in ips)]
            history = list(getattr(self, 'alerts', ())) if alerts else []
            saved = {key: dict(row) for key, row in getattr(self, 'alert_connections', {}).items()} if alerts else {}
        updates = []
        for key, original, row in connections:
            if self._retain_remote_host(row, discover):
                updates.append((key, original, row))
        alert_updates = {}
        for alert in history:
            alert_id, _, _, _, _, remote, host, _ = alert
            ip = self._alert_remote_ip(remote)
            if ips is not None and ip not in ips:
                continue
            row = saved.get(alert_id, {'dst_ip': ip})
            if host:
                row['display_host'] = host
                row['_display_endpoint'] = self._host_endpoint(row)
            learned = self._retain_remote_host(row, discover)
            if learned:
                alert_updates[alert_id] = (alert, learned, row)
        live_changed = alerts_changed = False
        with self.lock:
            for key, original, row in updates:
                current = getattr(self, 'active_connections', {}).get(key)
                if current is original and self._host_endpoint(current) == self._host_endpoint(row) and not self._retained_host(current):
                    current['display_host'] = row['display_host']
                    current['_display_endpoint'] = row['_display_endpoint']
                    live_changed = True
            if alert_updates:
                refreshed = []
                for alert in self.alerts:
                    update = alert_updates.get(alert[0])
                    if update and update[0] == alert:
                        _, learned, row = update
                        if not alert[6]:
                            alert = (*alert[:6], learned, alert[7])
                            alerts_changed = True
                        current = getattr(self, 'alert_connections', {}).get(alert[0])
                        if current is not None and self._host_endpoint(current) == self._host_endpoint(row) and not self._retained_host(current):
                            current['display_host'] = learned
                            current['_display_endpoint'] = self._host_endpoint(current)
                    refreshed.append(alert)
                self.alerts.clear()
                self.alerts.extend(refreshed)
        return live_changed, alerts_changed

    def _notify_dns_changed(self, ips):
        """Coalesce worker/passive discoveries into one bounded UI notification."""
        if not ips:
            return
        with self.dns_lock:
            pending = getattr(self, 'dns_changed_ips', set())
            for ip in ips:
                if len(pending) >= DNS_CACHE_MAX_ENTRIES and ip not in pending:
                    pending.pop()
                pending.add(ip)
            self.dns_changed_ips = pending
            notify = not getattr(self, 'dns_notification_pending', False)
            self.dns_notification_pending = True
        if notify:
            self.ui_queue.put(('dns',))

    def _start_dns_workers(self):
        for index in range(DNS_MAX_WORKERS):
            worker = threading.Thread(target=self._dns_worker, daemon=True, name=f'PyFirewall-DNS-{index + 1}')
            worker.start()
            self.dns_workers.append(worker)

    def _dns_worker(self):
        while not self.dns_stop_event.is_set():
            try:
                ip = self.dns_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.resolve_dns(ip)
            except Exception:
                with self.dns_lock:
                    self.dns_pending.discard(ip)
            finally:
                self.dns_queue.task_done()

    def get_cached_dns(self, ip):
        ip = str(ip or '')
        if not ip:
            return ''
        now = time.monotonic()
        with self.dns_lock:
            cached = self.dns_cache.get(ip)
            cached_at = self.dns_cache_times.get(ip, 0.0)
            if cached is not None and (now - cached_at) < DNS_CACHE_TTL:
                return cached
            if cached is not None:
                self.dns_cache.pop(ip, None)
                self.dns_cache_times.pop(ip, None)
            if ip in self.dns_pending or len(self.dns_pending) >= DNS_MAX_PENDING:
                return ''
            self.dns_pending.add(ip)
        try:
            self.dns_queue.put_nowait(ip)
        except queue.Full:
            with self.dns_lock:
                self.dns_pending.discard(ip)
        return ''

    def resolve_dns(self, ip):
        host = ''
        try:
            host = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            pass
        except Exception:
            pass
        with self.dns_lock:
            if len(self.dns_cache) >= DNS_CACHE_MAX_ENTRIES and ip not in self.dns_cache:
                oldest_ip = min(self.dns_cache_times, key=self.dns_cache_times.get, default=None)
                if oldest_ip is not None:
                    self.dns_cache.pop(oldest_ip, None)
                    self.dns_cache_times.pop(oldest_ip, None)
            self.dns_cache[ip] = host
            self.dns_cache_times[ip] = time.monotonic()
            self.dns_pending.discard(ip)
        self._notify_dns_changed((ip,))

    # Traffic accounting and packet handling

    def _prune_traffic_state_locked(self):
        self.last_traffic_prune = time.monotonic()
        self._prune_rates_locked(self.last_traffic_prune)
        self.global_port_traffic = {key: stats for key, stats in self.global_port_traffic.items()
                                    if key in self.global_ports}
        if len(self.ip_traffic) > TRAFFIC_MAX_IP_ENTRIES:
            excess = len(self.ip_traffic) - TRAFFIC_MAX_IP_ENTRIES
            # Keep accumulated rule totals even when the bounded per-IP cache
            # evicts old endpoints. Refreshing the rule list must not reset them.
            targets = {entry['target']: entry for rule in getattr(self, 'global_ports', {}).values()
                       for entry in rule.get('targets', ())}
            networks = {target: self._target_networks(target, data.get('addresses', ()))
                        for target, data in targets.items()}
            self.pruned_target_traffic = {target: stats for target, stats in self.pruned_target_traffic.items()
                                          if target in targets}
            for key, _ in sorted(self.ip_traffic_last_seen.items(), key=lambda item: item[1])[:excess]:
                stats = self.ip_traffic.pop(key, None)
                if stats:
                    for target, ranges in networks.items():
                        if self._traffic_ip_matches(key, ranges):
                            totals = self.pruned_target_traffic.setdefault(target, {'download': 0, 'upload': 0})
                            for side in ('download', 'upload'):
                                totals[side] += stats.get(side, 0)
                self.ip_traffic_last_seen.pop(key, None)
        if len(self.proc_ip_upload) > TRAFFIC_MAX_PROC_IP_ENTRIES:
            excess = len(self.proc_ip_upload) - TRAFFIC_MAX_PROC_IP_ENTRIES
            for key, _ in sorted(self.proc_ip_upload_last_seen.items(), key=lambda item: item[1])[:excess]:
                self.proc_ip_upload.pop(key, None)
                self.proc_ip_upload_last_seen.pop(key, None)
                self.upload_alerted.discard(key)

    @staticmethod
    def port_watch_signal(local_port, remote_port):
        parts = []
        for label, port in (('Remote', remote_port), ('Local', local_port)):
            try:
                desc = WATCH_PORTS.get(int(port))
            except (TypeError, ValueError):
                desc = None
            if desc:
                parts.append(f'{label} {int(port)} ({desc})')
        return f"Port watch: {'; '.join(parts)}" if parts else ''

    def _prune_rates_locked(self, now):
        self.last_rate_prune = now
        window = getattr(self, 'rate_window', 5.0)
        for key, timestamps in list(self.connection_rates.items()):
            while timestamps and now - timestamps[0] > window:
                timestamps.popleft()
            if not timestamps:
                self.connection_rates.pop(key, None)

    def _rate_hit_locked(self, key, now, threshold, window):
        if threshold == 1:
            return True
        if now - getattr(self, 'last_rate_prune', 0) >= min(1.0, window):
            self._prune_rates_locked(now)
        timestamps = self.connection_rates.get(key)
        if timestamps is None:
            if len(self.connection_rates) >= RATE_MAX_KEYS:
                # Preserve in-window histories already tracked. Admission resumes
                # when they expire; saturation is visible, never a capture wait.
                self.untracked_rate_events = getattr(self, 'untracked_rate_events', 0) + 1
                return False
            timestamps = self.connection_rates.setdefault(key, deque())
        while timestamps and now - timestamps[0] > window:
            timestamps.popleft()
        timestamps.append(now)
        if len(timestamps) >= threshold:
            self.connection_rates.pop(key, None)
            return True
        return False

    def packet_handler(self, packet):
        with self.lock:
            if self.is_paused or not self.sniffing or self.closed:
                return
            accepted_token = self._detection_token_locked()
        try:
            packet_size = max(0, len(packet))
            if IP in packet:
                family_key = 2
                src, dst = (packet[IP].src, packet[IP].dst)
            elif IPv6 in packet:
                family_key = 23
                src, dst = (packet[IPv6].src, packet[IPv6].dst)
            else:
                return
            if TCP in packet:
                proto = 'TCP'
                sport, dport = (int(packet[TCP].sport), int(packet[TCP].dport))
            elif UDP in packet:
                proto = 'UDP'
                sport, dport = (int(packet[UDP].sport), int(packet[UDP].dport))
            else:
                return
            if not sport:
                return
            if sport == 53:
                self.refresh_process_cache()
                if normalize_target(dst) in self.local_addresses:
                    self.observe_dns_response(packet)
            outgoing = self.get_process_info(src, sport, dst, dport, proto, family_key)
            incoming = self.get_process_info(dst, dport, src, sport, proto, family_key)
            if outgoing[0] and incoming[0]:
                return
            if outgoing[0] and outgoing[1]:
                proc_name, exe, pid = outgoing
                direction = 'Outgoing'
            elif incoming[0] and incoming[1]:
                proc_name, exe, pid = incoming
                direction = 'Incoming'
            else:
                return
            local_port, remote_ip, remote_port = (sport, dst, dport) if direction == 'Outgoing' else (dport, src, sport)
            key = f'{pid}-{proto}-{local_port}-{remote_ip}-{remote_port}'
            endpoint = {'exe': exe, 'pid': pid, 'protocol': proto, 'lport': local_port,
                        'dst_ip': remote_ip, 'dport': remote_port}
            with self.lock:
                previous = self.active_connections.get(key)
                if previous and self._host_endpoint(previous) == self._host_endpoint(endpoint):
                    endpoint.update({field: previous[field] for field in ('domain', 'display_host', '_display_endpoint')
                                     if field in previous})
            self._retain_remote_host(endpoint, discover=True)
            domain = endpoint.get('domain', '')
            signal = self.port_watch_signal(local_port, remote_port)
            norm_exe = normalize_path(exe) or proc_name.casefold()
            norm_ip = normalize_target(remote_ip)
            now = time.monotonic()
            with self.lock:
                if self.is_paused or not self.sniffing or self.closed or accepted_token != self._detection_token_locked():
                    return
                log_alerts = self.log_alerts_only
                rate_threshold = self.rate_threshold
                rate_window = self.rate_window
                upload_threshold = self.upload_threshold_mb
                self.captured_packets += 1
                self.captured_bytes += packet_size
                if direction == 'Outgoing':
                    self.total_upload += packet_size
                else:
                    self.total_download += packet_size
                pstats = self.proc_traffic.setdefault(norm_exe, {'download': 0, 'upload': 0})
                istats = self.ip_traffic.setdefault(norm_ip, {'download': 0, 'upload': 0})
                side = 'upload' if direction == 'Outgoing' else 'download'
                pstats[side] += packet_size
                istats[side] += packet_size
                # Match this packet's direction, not the connection's first-seen
                # direction. Overlapping global/app rules each retain the bytes.
                endpoint.update(domain=domain, direction=direction, key=key, name=proc_name, signal=signal)
                endpoint['_detection_token'] = accepted_token
                matching = self.matching_global_port_rules(endpoint)
                contribution = (getattr(self, 'global_policy_epoch', 0), tuple(sorted(matching)))
                for rule_key in matching:
                    stats = self.global_port_traffic.setdefault(rule_key, {'download': 0, 'upload': 0})
                    stats[side] += packet_size
                    bucket = stats.setdefault('_contributions', {}).setdefault(contribution, {'download': 0, 'upload': 0})
                    bucket[side] += packet_size
                existing = self.active_connections.get(key)
                is_new = existing is None or self._host_endpoint(existing) != self._host_endpoint(endpoint)
                if is_new:
                    self._capture_serial = getattr(self, '_capture_serial', 0) + 1
                    row = {'key': key, 'number': self.next_connection_number, 'name': proc_name, 'pid': pid, 'direction': direction, 'protocol': proto, 'lport': local_port, 'dst_ip': remote_ip, 'domain': domain, 'dport': remote_port, 'signal': signal, 'exe': exe, 'first_seen': now, 'last_seen': now, 'download': 0, 'upload': 0}
                    row['_capture_id'] = self._capture_serial
                    signature = self._connection_group_signature(row)
                    last = getattr(self, '_last_connection_group', None)
                    row['_run_id'] = last[1] if last and signature == last[0] else f'connection_{self._capture_serial}'
                    self._last_connection_group = (signature, row['_run_id'])
                    row['_flow_totals'] = {'download': 0, 'upload': 0}
                    self.active_connections[key] = row
                    self.next_connection_number += 1
                    self._prune_connection_and_alert_history_locked()
                else:
                    row = self.active_connections[key]
                    row['last_seen'] = now
                    if not row.get('domain') and domain:
                        row['domain'] = domain
                if endpoint.get('display_host') and not self._retained_host(row):
                    row['display_host'] = endpoint['display_host']
                    row['_display_endpoint'] = self._host_endpoint(row)
                # Both packet directions share the same connection key, while
                # process totals above continue to include all its connections.
                row[side] = row.get(side, 0) + packet_size
                row.setdefault('_flow_totals', {})[side] = row[side]
                endpoint.update({field: row[field] for field in ('_capture_id', '_run_id', '_flow_totals', 'number', 'first_seen')})
                # Alert grouping uses the flow's first-seen direction, while the
                # packet direction above remains authoritative for decisions.
                endpoint['_first_direction'] = row['direction']
                upload_key = None
                upload_total = 0
                if direction == 'Outgoing' and remote_ip not in {'127.0.0.1', '::1'}:
                    upload_key = (norm_exe, norm_ip)
                    upload_total = self.proc_ip_upload.get(upload_key, 0) + packet_size
                    self.proc_ip_upload[upload_key] = upload_total
                    self.proc_ip_upload_last_seen[upload_key] = now
                self.ip_traffic_last_seen[norm_ip] = now
                if now - self.last_traffic_prune >= TRAFFIC_PRUNE_INTERVAL:
                    self._prune_traffic_state_locked()
                rate_hit = False
                if is_new and log_alerts:
                    rate_key = (norm_exe, norm_ip)
                    rate_hit = self._rate_hit_locked(rate_key, now, rate_threshold, rate_window)
            if signal and is_new:
                remote_endpoint = f'[{remote_ip}]:{remote_port}' if ':' in remote_ip else f'{remote_ip}:{remote_port}'
                self.queue_alert('Watch', proc_name, pid, remote_endpoint, f'{direction} connection on {proto}; {signal}.',
                                 connection=endpoint)
            if upload_key and log_alerts and (upload_total >= upload_threshold * 1024 * 1024):
                with self.lock:
                    if accepted_token != self._detection_token_locked():
                        return
                    first_upload_alert = upload_key not in self.upload_alerted
                    if first_upload_alert:
                        self.upload_alerted.add(upload_key)
                if first_upload_alert:
                    self.handle_threshold(proc_name, exe, pid, remote_ip, domain, direction, key, 'upload', mb(upload_total), endpoint)
            if rate_hit:
                self.handle_threshold(proc_name, exe, pid, remote_ip, domain, direction, key, 'connection', '', endpoint)
        except Exception as exc:
            log_internal_error('packet_handler', exc)

    # Capture discovery, recovery and shutdown

    def _open_capture_socket(self):
        """Resolve fresh Npcap device identities and validate by opening a socket.

        conf.iface may refer to a removed VPN/USB adapter or to loopback. A
        Windows adapter name alone does not prove Npcap can capture from it.
        """
        if not conf.use_pcap:
            conf.use_pcap = True
        if not conf.use_pcap:
            raise OSError('Npcap capture is unavailable. Install or repair Npcap and restart PyFirewall.')
        conf.ifaces.reload()  # Also refreshes the Windows provider's pcap device list.
        conf.route.resync()
        conf.route6.resync()
        conf.ifaces.load_confiface()
        stats = psutil.net_if_stats()
        candidates = []
        default_name = getattr(conf.iface, 'network_name', '')
        for iface in conf.ifaces.values():
            if not iface.is_valid() or not iface.network_name:
                continue
            if iface.network_name == conf.loopback_name:
                continue
            state = stats.get(iface.name) or stats.get(iface.description)
            if state is not None and not state.isup:
                continue
            addresses = []
            for version in (4, 6):
                for address in iface.ips.get(version, []):
                    try:
                        addresses.append(ipaddress.ip_address(str(address).split('%', 1)[0]))
                    except ValueError:
                        continue
            if not any(not ip.is_loopback and not ip.is_unspecified for ip in addresses):
                continue
            candidates.append(iface)
        candidates.sort(key=lambda iface: (iface.network_name != default_name, iface.network_name))
        errors = []
        for iface in candidates:
            with self.lock:
                if self.closed or not self.sniffing or self.is_paused:
                    return None
            try:
                # Keep the validated socket: avoid a probe/open race and repeated
                # Npcap opens every second. Normal IP capture needs no promiscuity.
                capture_socket = conf.L2listen(iface=iface, filter='ip or ip6', promisc=False)
                with self.lock:
                    self.detection_epoch = getattr(self, 'detection_epoch', 0) + 1
                    self.capture_interface = f'{iface.name} ({iface.network_name})'
                return capture_socket
            except Exception as exc:
                errors.append(f'{iface.name} ({iface.network_name}): {exc}')
        detail = '; '.join(errors) if errors else 'Npcap exposes no active non-loopback IP adapter.'
        raise OSError(f'{detail} Check that your network adapter is connected and Npcap is installed '
                      'and bound to it; repair Npcap if needed. Capture will retry automatically.')

    def _capture_wait(self, seconds):
        # Bounded slices let shutdown/pause interrupt even the longest backoff.
        for _ in range(max(1, int(seconds / 0.25))):
            with self.lock:
                if self.closed or not self.sniffing or self.is_paused:
                    return
            time.sleep(0.25)

    @staticmethod
    def _close_capture_socket(capture_socket):
        if capture_socket is not None:
            try:
                capture_socket.close()
            except Exception as exc:
                log_internal_error('packet_capture_close', exc)

    def start_sniffing(self):
        capture_socket = None
        refresh_at, retry_delay = 0.0, 1.0
        try:
            while True:
                with self.lock:
                    if not self.sniffing or self.closed:
                        return
                    paused = self.is_paused
                if paused:
                    self._close_capture_socket(capture_socket)
                    capture_socket = None
                    time.sleep(0.25)
                    continue
                try:
                    # Periodic rediscovery handles silent disconnects and route
                    # changes even when the old socket never raises an error.
                    if capture_socket is None or time.monotonic() >= refresh_at:
                        self._close_capture_socket(capture_socket)
                        capture_socket = None
                        capture_socket = self._open_capture_socket()
                        if capture_socket is None:
                            continue
                        refresh_at = time.monotonic() + 30.0
                    sniff(opened_socket=capture_socket, prn=self.packet_handler, store=False, timeout=1)
                    # Scapy can swallow receive errors and close a supplied socket.
                    if capture_socket.closed:
                        raise OSError('The capture adapter disconnected or its socket was closed.')
                    with self.lock:
                        recovered = self.capture_error is not None
                        self.capture_healthy = True
                        self.capture_error = None
                    retry_delay = 1.0
                    if recovered:
                        self.queue_alert('Info', 'Packet capture', '', '', 'Packet capture recovered.')
                except Exception as exc:
                    self._close_capture_socket(capture_socket)
                    capture_socket = None
                    with self.lock:
                        changed = self.capture_error != str(exc)
                        self.capture_error = str(exc)
                        self.capture_healthy = False
                        self.capture_interface = None
                    self._invalidate_auto_prompts(close_dialog=True)
                    if changed:
                        log_internal_error('packet_capture', exc)
                        self.queue_alert('High', 'Packet capture', '', '',
                                         f'Monitoring and Auto-Block unavailable: {exc}')
                    self._capture_wait(retry_delay)
                    retry_delay = min(retry_delay * 2, 30.0)
        finally:
            self._close_capture_socket(capture_socket)

    # Per-target traffic totals

    def target_traffic(self, target, addresses=()):
        with self.lock:
            return self._target_traffic_locked(target, addresses)

    def _target_traffic_locked(self, target, addresses=()):
        target = normalize_target(target)
        # Use the rule's resolved endpoints; never block the UI on DNS or infer
        # membership from a PTR name that may not match the firewall filter.
        saved_addresses = [address for rule in getattr(self, 'global_ports', {}).values()
                           for entry in rule.get('targets', ()) if entry['target'] == target
                           for address in entry.get('addresses', ())]
        networks = self._target_networks(target, (*addresses, *saved_addresses))
        previous = getattr(self, 'pruned_target_traffic', {}).get(target, {})
        down, up = previous.get('download', 0), previous.get('upload', 0)
        for ip, stats in self.ip_traffic.items():
            if self._traffic_ip_matches(ip, networks):
                down += stats.get('download', 0)
                up += stats.get('upload', 0)
        return (down, up)

    @staticmethod
    def _target_networks(target, addresses=()):
        networks = set()
        for address in (*target.split(','), *addresses):
            try:
                networks.update(address_networks(normalize_target(address)))
            except ValueError:
                continue
        return networks

    @staticmethod
    def _traffic_ip_matches(ip, networks):
        try:
            remote = ipaddress.ip_address(str(ip).split('%', 1)[0])
        except ValueError:
            return False
        # Count each endpoint once, even for overlapping ranges or duplicates.
        return any(remote in network for network in networks)
