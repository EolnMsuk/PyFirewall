"""Packet capture, process attribution, DNS caching and traffic accounting."""

import ipaddress
import psutil
import queue
import socket
import threading
import time
from collections import deque

from scapy.all import IP, IPv6, TCP, UDP, conf, sniff

from constants import (
    DNS_CACHE_MAX_ENTRIES,
    DNS_CACHE_TTL,
    DNS_MAX_PENDING,
    DNS_MAX_WORKERS,
    TRAFFIC_MAX_IP_ENTRIES,
    TRAFFIC_MAX_PROC_IP_ENTRIES,
    TRAFFIC_PRUNE_INTERVAL,
    WATCH_PORTS,
)
from helpers import log_internal_error, mb, normalize_path, normalize_target

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
        self.ui_queue.put(('dns', ip))

    # Traffic accounting and packet handling

    def _prune_traffic_state_locked(self):
        self.last_traffic_prune = time.monotonic()
        if len(self.ip_traffic) > TRAFFIC_MAX_IP_ENTRIES:
            excess = len(self.ip_traffic) - TRAFFIC_MAX_IP_ENTRIES
            # Keep accumulated rule totals even when the bounded per-IP cache
            # evicts old endpoints. Refreshing the rule list must not reset them.
            targets = {**self.global_blocks, **self.global_allows}
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

    def packet_handler(self, packet):
        with self.lock:
            if self.is_paused or not self.sniffing or self.closed:
                return
            log_alerts = self.log_alerts_only
            rate_threshold = self.rate_threshold
            rate_window = self.rate_window
            upload_threshold = self.upload_threshold_mb
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
            domain = self.get_cached_dns(remote_ip)
            signal = self.port_watch_signal(local_port, remote_port)
            norm_exe = normalize_path(exe) or proc_name.casefold()
            norm_ip = normalize_target(remote_ip)
            now = time.monotonic()
            with self.lock:
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
                is_new = key not in self.active_connections
                if is_new:
                    self.active_connections[key] = {'key': key, 'number': self.next_connection_number, 'name': proc_name, 'pid': pid, 'direction': direction, 'protocol': proto, 'lport': local_port, 'dst_ip': remote_ip, 'domain': domain, 'dport': remote_port, 'signal': signal, 'exe': exe, 'first_seen': now, 'last_seen': now}
                    self.next_connection_number += 1
                    self._prune_connection_and_alert_history_locked()
                else:
                    row = self.active_connections[key]
                    row['last_seen'] = now
                    if not row.get('domain') and domain:
                        row['domain'] = domain
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
                    timestamps = self.connection_rates.setdefault(rate_key, deque())
                    while timestamps and now - timestamps[0] > rate_window:
                        timestamps.popleft()
                    timestamps.append(now)
                    rate_hit = len(timestamps) >= rate_threshold
                    if rate_hit:
                        self.connection_rates.pop(rate_key, None)
            if signal and is_new:
                self.queue_alert('Watch', proc_name, pid, f'{remote_ip}:{remote_port}', f'{direction} connection on {proto}; {signal}.')
            if upload_key and log_alerts and (upload_total >= upload_threshold * 1024 * 1024):
                with self.lock:
                    first_upload_alert = upload_key not in self.upload_alerted
                    if first_upload_alert:
                        self.upload_alerted.add(upload_key)
                if first_upload_alert:
                    self.handle_threshold(proc_name, exe, pid, remote_ip, domain, direction, key, 'upload', mb(upload_total))
            if rate_hit:
                self.handle_threshold(proc_name, exe, pid, remote_ip, domain, direction, key, 'connection', '')
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
        saved = self.global_blocks.get(target, self.global_allows.get(target, {}))
        networks = self._target_networks(target, (*addresses, *saved.get('addresses', ())))
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
        for address in (target, *addresses):
            try:
                networks.add(ipaddress.ip_network(normalize_target(address), strict=False))
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
