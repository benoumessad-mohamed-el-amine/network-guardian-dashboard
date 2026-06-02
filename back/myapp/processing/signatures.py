import time
import threading
import logging

logger = logging.getLogger(__name__)

class SignatureEngine:
    """Signature and threshold-based engine for filtering known normal/malicious packets."""
    
    def __init__(self) -> None:
        self.lock = threading.Lock()
        
        # Track port probing history: { src_ip: [(timestamp, dst_port), ...] }
        self.port_history = {}
        
        # Track SYN packet history (no ACK): { src_ip: [timestamp, ...] }
        self.syn_history = {}
        # Track destination SYN packet history (for distributed attacks): { dst_ip: [timestamp, ...] }
        self.syn_dest_history = {}
        
        # Track UDP packet history: { src_ip: [timestamp, ...] } & { dst_ip: [timestamp, ...] }
        self.udp_source_history = {}
        self.udp_dest_history = {}
        
        # Track ICMP packet history: { src_ip: [timestamp, ...] } & { dst_ip: [timestamp, ...] }
        self.icmp_source_history = {}
        self.icmp_dest_history = {}
        
        # Track overall DDoS packet rates: { src_ip: [timestamp, ...] } & { dst_ip: [(timestamp, src_ip), ...] }
        self.ddos_source_history = {}
        self.ddos_dest_history = {}
        
        # Clean up timer interval (based on packet time)
        self.last_cleanup = None
        
        # Define whitelist ports for local broadcast/multicast/application services
        self.whitelist_ports = {
            53,             # DNS
            123,            # NTP
            137, 138, 139,  # NetBIOS
            1900,           # SSDP (UPnP)
            3702,           # WS-Discovery
            5353,           # mDNS
            5355,           # LLMNR
            67, 68,         # DHCP
            8000,           # Django backend
            5173,           # Vite frontend
            3000,           # Alternate React port
            5432,           # PostgreSQL
            3306,           # MySQL
            6379,           # Redis
            27017,          # MongoDB
            9993,           # ZeroTier VPN
        }

    def check_packet(self, packet: dict) -> str | None:
        """
        Processes a packet against whitelist, blacklist, and rate-limit signatures.
        Returns:
            - 'normal': if packet matches a whitelisted normal pattern or safe established TCP.
            - 'portscan' / 'sync flood' / 'ddos' / 'botnet': if packet matches a signature.
            - None: if no signature matches (delegate to ML).
        """
        # Parse basic fields
        src_ip = str(packet.get('src_ip', '0.0.0.0'))
        dst_ip = str(packet.get('dst_ip', '0.0.0.0'))
        
        try:
            protocol = int(packet.get('protocol', 0) or 0)
        except (ValueError, TypeError):
            protocol = 0
            
        try:
            src_port = int(packet.get('src_port', 0) or 0)
            dst_port = int(packet.get('dst_port', 0) or 0)
        except (ValueError, TypeError):
            src_port = 0
            dst_port = 0
            
        tcp_flags = str(packet.get('tcp_flags', '')).upper().strip()
        timestamp = float(packet.get('timestamp', time.time()))

        # -------------------------------------------------------------
        # Tier 1: Whitelist Rules (Immediate Broadcast/Multicast & App Loopback Noise Elimination)
        # -------------------------------------------------------------
        # Broadcast and Multicast traffic are extremely noisy and should be bypassed immediately
        if dst_ip == '255.255.255.255' or dst_ip.startswith('ff02:') or dst_ip.startswith('ff05:'):
            return 'normal'
        try:
            first_octet = int(dst_ip.split('.')[0])
            if 224 <= first_octet <= 239:
                return 'normal'
        except Exception:
            pass

        # Loopback App Traffic (Frontend-Backend API, WebSockets, DB connections)
        # We immediately whitelist normal local loopback traffic targeting whitelisted application/system ports
        is_loopback = src_ip.startswith('127.') and dst_ip.startswith('127.')
        if is_loopback:
            if dst_port in self.whitelist_ports or src_port in self.whitelist_ports:
                return 'normal'

        # -------------------------------------------------------------
        # Tier 2: Blacklist Flag Rules (Instant Malicious Detections)
        # -------------------------------------------------------------
        if protocol == 6:  # TCP
            # Null Scan: No flags set at all
            if tcp_flags == '' or tcp_flags == '0' or tcp_flags == 'NONE':
                return 'portscan'
                
            # Xmas Scan: FIN, PSH, and URG all set
            if 'F' in tcp_flags and 'P' in tcp_flags and 'U' in tcp_flags:
                return 'portscan'
                
            # FIN Scan: Only FIN set (no ACK or other flags)
            if tcp_flags == 'F':
                return 'portscan'
                
            # SYN-FIN Scan: Invalid RFC flag combination
            if 'S' in tcp_flags and 'F' in tcp_flags:
                return 'portscan'

        # -------------------------------------------------------------
        # Tier 3: Threshold/Rate-Limit Rules (Behavioral Attacks)
        # -------------------------------------------------------------
        with self.lock:
            # Initialize cleanup tracker on first packet
            if self.last_cleanup is None:
                self.last_cleanup = timestamp
                
            # Perform periodic cleanup to keep memory usage low (every 30 seconds of packet stream time)
            if timestamp - self.last_cleanup > 30.0:
                self._cleanup_history(timestamp)
                self.last_cleanup = timestamp

            # --- A. Record Packet History ---
            # Exclude whitelisted loopback traffic from all rate-limit tracking entirely
            is_whitelisted_local = is_loopback and (dst_port in self.whitelist_ports or src_port in self.whitelist_ports)
            
            if not is_whitelisted_local:
                # 1. Portscan Tracker
                if protocol == 6 and dst_port > 0:
                    is_tcp_probe = ('S' in tcp_flags and 'A' not in tcp_flags) or tcp_flags in ('', '0', 'NONE', 'F') or ('F' in tcp_flags and 'P' in tcp_flags and 'U' in tcp_flags)
                    if is_tcp_probe:
                        if src_ip not in self.port_history:
                            self.port_history[src_ip] = []
                        self.port_history[src_ip].append((timestamp, dst_port))
                elif protocol == 17 and dst_port > 0:
                    # Exclude standard local/network UDP services from portscan probes to reduce false positives
                    if dst_port not in self.whitelist_ports and src_port not in self.whitelist_ports:
                        if src_ip not in self.port_history:
                            self.port_history[src_ip] = []
                        self.port_history[src_ip].append((timestamp, dst_port))
                    
                # 2. SYN Flood Tracker
                is_syn = (protocol == 6 and 'S' in tcp_flags and 'A' not in tcp_flags)
                if is_syn:
                    if src_ip not in self.syn_history:
                        self.syn_history[src_ip] = []
                    self.syn_history[src_ip].append(timestamp)
                    
                    if dst_ip not in self.syn_dest_history:
                        self.syn_dest_history[dst_ip] = []
                    self.syn_dest_history[dst_ip].append(timestamp)
                    
                # 3. UDP Flood Tracker
                if protocol == 17:
                    # Exclude standard UDP ports (QUIC, DNS, NTP) from UDP flood tracking to prevent streaming/query false positives
                    is_whitelisted_udp = dst_port in (53, 123, 443) or src_port in (53, 123, 443)
                    if not is_whitelisted_udp:
                        if src_ip not in self.udp_source_history:
                            self.udp_source_history[src_ip] = []
                        self.udp_source_history[src_ip].append(timestamp)
                        
                        if dst_ip not in self.udp_dest_history:
                            self.udp_dest_history[dst_ip] = []
                        self.udp_dest_history[dst_ip].append(timestamp)

                # 4. ICMP Flood Tracker
                if protocol == 1:
                    if src_ip not in self.icmp_source_history:
                        self.icmp_source_history[src_ip] = []
                    self.icmp_source_history[src_ip].append(timestamp)
                    
                    if dst_ip not in self.icmp_dest_history:
                        self.icmp_dest_history[dst_ip] = []
                    self.icmp_dest_history[dst_ip].append(timestamp)

                # 5. General volume Tracker
                # Exclude established TCP traffic (ACK/RST) and whitelisted UDP from general DoS tracking to prevent file download/streaming false positives
                is_established_tcp = (protocol == 6 and any(f in tcp_flags for f in ('A', 'R')))
                is_whitelisted_udp = (protocol == 17 and (dst_port in (53, 123, 443) or src_port in (53, 123, 443)))
                if not is_established_tcp and not is_whitelisted_udp:
                    if src_ip not in self.ddos_source_history:
                        self.ddos_source_history[src_ip] = []
                    self.ddos_source_history[src_ip].append(timestamp)
                    
                    if dst_ip not in self.ddos_dest_history:
                        self.ddos_dest_history[dst_ip] = []
                    self.ddos_dest_history[dst_ip].append((timestamp, src_ip))

            # --- B. Evaluate Portscan (High Priority, before SYN Flood) ---
            if src_ip in self.port_history:
                port_active = [
                    (t, p) for t, p in self.port_history[src_ip]
                    if timestamp - t <= 5.0
                ]
                self.port_history[src_ip] = port_active
                unique_ports = {p for _, p in port_active}
                if len(unique_ports) >= 10:
                    logger.warning(f"[SIGNATURE] Portscan rate-limit triggered for source {src_ip}: {len(unique_ports)} unique ports contacted.")
                    return 'portscan'

            # --- C. Evaluate Coordinated Botnet DDoS ---
            # If the destination overall volume is high, and the traffic is spread across multiple source IPs
            if dst_ip in self.ddos_dest_history:
                dst_active = [
                    (t, sip) for t, sip in self.ddos_dest_history[dst_ip]
                    if timestamp - t <= 2.0
                ]
                self.ddos_dest_history[dst_ip] = dst_active
                
                if len(dst_active) >= 40:
                    # Count distinct source IPs targeting this destination in the active window
                    unique_sources = {sip for _, sip in dst_active if not sip.startswith('127.') and sip != '0.0.0.0'}
                    if len(unique_sources) >= 3:
                        logger.warning(f"[SIGNATURE] Botnet DDoS coordinated flood triggered for destination {dst_ip}: {len(dst_active)} packets from {len(unique_sources)} sources.")
                        return 'botnet'

            # --- D. Evaluate SYN Flood ---
            # Per-source SYN Flood
            if is_syn and src_ip in self.syn_history:
                syn_src_active = [t for t in self.syn_history[src_ip] if timestamp - t <= 2.0]
                self.syn_history[src_ip] = syn_src_active
                
                # Check how many unique ports were targeted to ensure it is not a portscan
                ports_targeted = set()
                if src_ip in self.port_history:
                    ports_targeted = {p for _, p in self.port_history[src_ip] if timestamp - _ <= 2.0}
                
                if len(syn_src_active) >= 20 and len(ports_targeted) < 5:
                    logger.warning(f"[SIGNATURE] SYN Flood rate-limit triggered for source {src_ip}: {len(syn_src_active)} SYN packets in 2s.")
                    return 'sync flood'
            
            # Per-destination SYN Flood (Distributed/Spoofed)
            if is_syn and dst_ip in self.syn_dest_history:
                syn_dst_active = [t for t in self.syn_dest_history[dst_ip] if timestamp - t <= 2.0]
                self.syn_dest_history[dst_ip] = syn_dst_active
                if len(syn_dst_active) >= 40:
                    logger.warning(f"[SIGNATURE] SYN Flood destination rate-limit triggered for destination {dst_ip}: {len(syn_dst_active)} SYN packets in 2s.")
                    return 'sync flood'

            # --- E. Evaluate UDP Flood ---
            # Per-source UDP DoS
            if protocol == 17 and src_ip in self.udp_source_history:
                udp_src_active = [t for t in self.udp_source_history[src_ip] if timestamp - t <= 2.0]
                self.udp_source_history[src_ip] = udp_src_active
                
                ports_targeted = set()
                if src_ip in self.port_history:
                    ports_targeted = {p for _, p in self.port_history[src_ip] if timestamp - _ <= 2.0}
                    
                if len(udp_src_active) >= 50 and len(ports_targeted) < 5:
                    logger.warning(f"[SIGNATURE] UDP Flood rate-limit triggered for source {src_ip}: {len(udp_src_active)} UDP packets in 2s.")
                    return 'ddos'
            
            # Per-destination UDP DDoS
            if protocol == 17 and dst_ip in self.udp_dest_history:
                udp_dst_active = [t for t in self.udp_dest_history[dst_ip] if timestamp - t <= 2.0]
                self.udp_dest_history[dst_ip] = udp_dst_active
                if len(udp_dst_active) >= 150:
                    logger.warning(f"[SIGNATURE] UDP DDoS destination rate-limit triggered for destination {dst_ip}: {len(udp_dst_active)} UDP packets in 2s.")
                    return 'ddos'

            # --- F. Evaluate ICMP Flood ---
            # Per-source ICMP DoS
            if protocol == 1 and src_ip in self.icmp_source_history:
                icmp_src_active = [t for t in self.icmp_source_history[src_ip] if timestamp - t <= 2.0]
                self.icmp_source_history[src_ip] = icmp_src_active
                if len(icmp_src_active) >= 30:
                    logger.warning(f"[SIGNATURE] ICMP Flood rate-limit triggered for source {src_ip}: {len(icmp_src_active)} ICMP packets in 2s.")
                    return 'ddos'
                    
            # Per-destination ICMP DDoS
            if protocol == 1 and dst_ip in self.icmp_dest_history:
                icmp_dst_active = [t for t in self.icmp_dest_history[dst_ip] if timestamp - t <= 2.0]
                self.icmp_dest_history[dst_ip] = icmp_dst_active
                if len(icmp_dst_active) >= 100:
                    logger.warning(f"[SIGNATURE] ICMP DDoS destination rate-limit triggered for destination {dst_ip}: {len(icmp_dst_active)} ICMP packets in 2s.")
                    return 'ddos'

            # --- G. Evaluate General Volume Flood ---
            # Per-source DoS
            if src_ip in self.ddos_source_history:
                src_active = [t for t in self.ddos_source_history[src_ip] if timestamp - t <= 2.0]
                self.ddos_source_history[src_ip] = src_active
                if len(src_active) >= 100:
                    logger.warning(f"[SIGNATURE] DDoS source rate-limit triggered for source {src_ip}: {len(src_active)} packets in 2s.")
                    return 'ddos'
                
            # Per-destination DDoS
            if dst_ip in self.ddos_dest_history:
                dst_gen_active = [t for t, _ in self.ddos_dest_history[dst_ip] if timestamp - t <= 2.0]
                if len(dst_gen_active) >= 200:
                    logger.warning(f"[SIGNATURE] DDoS destination rate-limit triggered for destination {dst_ip}: {len(dst_gen_active)} packets in 2s.")
                    return 'ddos'

        # -------------------------------------------------------------
        # Tier 4: Whitelist Rules (Evaluated AFTER behavioral checks to allow localhost/port testing)
        # -------------------------------------------------------------
        
        # Rule 4.1: Loopback Subnet (127.0.0.0/8)
        if src_ip.startswith('127.') and dst_ip.startswith('127.'):
            return 'normal'

        # Rule 4.2: Standard Local Discovery/Config Ports (SSDP, DNS, NTP, DHCP, NetBIOS)
        if dst_port in self.whitelist_ports or src_port in self.whitelist_ports:
            return 'normal'

        # Rule 4.3: Safe Established TCP / Normal UDP & ICMP
        if protocol == 6:
            # Established flags: ACK or RST should bypass the ML model (to avoid false-positive unknown alerts)
            if any(f in tcp_flags for f in ('A', 'R')):
                return 'normal'
            # Outbound/Low-rate HTTP/HTTPS client connection initiation
            if dst_port in (80, 443):
                return 'normal'
        elif protocol == 17:
            # Low-rate DNS (53), NTP (123), HTTPS/3 (443)
            if dst_port in (53, 123, 443) or src_port in (53, 123, 443):
                return 'normal'
        elif protocol == 1:
            # Normal low-rate ping
            return 'normal'

        return None

    def _cleanup_history(self, reference_time: float) -> None:
        """Removes expired entries from history based on reference_time (packet time) to prevent memory leak."""
        # Cleanup port history (5s window)
        expired_ports = []
        for ip, history in self.port_history.items():
            active = [item for item in history if reference_time - item[0] <= 5.0]
            if not active:
                expired_ports.append(ip)
            else:
                self.port_history[ip] = active
        for ip in expired_ports:
            del self.port_history[ip]

        # Cleanup syn history (2s window)
        expired_syns = []
        for ip, history in self.syn_history.items():
            active = [t for t in history if reference_time - t <= 2.0]
            if not active:
                expired_syns.append(ip)
            else:
                self.syn_history[ip] = active
        for ip in expired_syns:
            del self.syn_history[ip]

        # Cleanup syn dest history (2s window)
        expired_syn_dst = []
        for ip, history in self.syn_dest_history.items():
            active = [t for t in history if reference_time - t <= 2.0]
            if not active:
                expired_syn_dst.append(ip)
            else:
                self.syn_dest_history[ip] = active
        for ip in expired_syn_dst:
            del self.syn_dest_history[ip]

        # Cleanup udp source history (2s window)
        expired_udp_src = []
        for ip, history in self.udp_source_history.items():
            active = [t for t in history if reference_time - t <= 2.0]
            if not active:
                expired_udp_src.append(ip)
            else:
                self.udp_source_history[ip] = active
        for ip in expired_udp_src:
            del self.udp_source_history[ip]

        # Cleanup udp dest history (2s window)
        expired_udp_dst = []
        for ip, history in self.udp_dest_history.items():
            active = [t for t in history if reference_time - t <= 2.0]
            if not active:
                expired_udp_dst.append(ip)
            else:
                self.udp_dest_history[ip] = active
        for ip in expired_udp_dst:
            del self.udp_dest_history[ip]

        # Cleanup icmp source history (2s window)
        expired_icmp_src = []
        for ip, history in self.icmp_source_history.items():
            active = [t for t in history if reference_time - t <= 2.0]
            if not active:
                expired_icmp_src.append(ip)
            else:
                self.icmp_source_history[ip] = active
        for ip in expired_icmp_src:
            del self.icmp_source_history[ip]

        # Cleanup icmp dest history (2s window)
        expired_icmp_dst = []
        for ip, history in self.icmp_dest_history.items():
            active = [t for t in history if reference_time - t <= 2.0]
            if not active:
                expired_icmp_dst.append(ip)
            else:
                self.icmp_dest_history[ip] = active
        for ip in expired_icmp_dst:
            del self.icmp_dest_history[ip]

        # Cleanup DDoS source history (2s window)
        expired_ddos_src = []
        for ip, history in self.ddos_source_history.items():
            active = [t for t in history if reference_time - t <= 2.0]
            if not active:
                expired_ddos_src.append(ip)
            else:
                self.ddos_source_history[ip] = active
        for ip in expired_ddos_src:
            del self.ddos_source_history[ip]

        # Cleanup DDoS dest history (2s window)
        expired_ddos_dst = []
        for ip, history in self.ddos_dest_history.items():
            active = [item for item in history if reference_time - item[0] <= 2.0]
            if not active:
                expired_ddos_dst.append(ip)
            else:
                self.ddos_dest_history[ip] = active
        for ip in expired_ddos_dst:
            del self.ddos_dest_history[ip]
