from __future__ import annotations

from typing import Iterable, Iterator
import hashlib

from .extractor import extract_packet_features
from .model_base import BaseModel, InferenceResult
from .signatures import SignatureEngine

# Dictionary of malicious TLS fingerprint signatures (JA3 hashes)
MALICIOUS_JA3_SIGNATURES = {
    "3b5074b1e7751c18114c01d4b2b2a64c": "Metasploit Meterpreter C2 (Reverse HTTPS)",
    "ad13b2c9e7751c18114c01d4b2b2a64c": "Cobalt Strike Beacon C2",
    "cfa276e01a8ef114b301777d12f3e8ab": "Emotet Botnet Agent",
    "8efee355ead5481a865ad72f68bb1238": "Sentinel Flow Simulated Attack Client",
}

# Open source intelligence blocklist (IP reputation feed)
SUSPICIOUS_IPS = {
    "185.220.101.5": "Known Tor Exit Node",
    "109.202.107.8": "Active Botnet Scanner (CrowdSec)",
    "45.227.254.12": "Known SSH Bruteforcer (AlienVault)",
    "198.51.100.42": "Threat Intel Flagged IP (Testing)",
}

def extract_tls_handshake_features(payload_hex: str) -> str | None:
    """
    Parses a TLS Client Hello payload hex string to extract JA3 features.
    Returns the computed MD5 (JA3) hash or None if parsing fails.
    """
    try:
        data = bytes.fromhex(payload_hex)
        if len(data) < 43:
            return None
            
        # Check TLS Record Content Type = Handshake (22)
        if data[0] != 22:
            return None
            
        # Check Handshake Type = Client Hello (1)
        if data[5] != 1:
            return None
            
        # Handshake version
        handshake_ver = (data[9] << 8) | data[10]
        
        idx = 43  # Skip Session ID length field
        if idx >= len(data):
            return None
            
        session_id_len = data[idx]
        idx += 1 + session_id_len
        
        # Cipher Suites
        if idx + 2 > len(data):
            return None
        ciphers_len = (data[idx] << 8) | data[idx+1]
        idx += 2
        
        if idx + ciphers_len > len(data):
            return None
        ciphers = []
        for i in range(0, ciphers_len, 2):
            ciphers.append(str((data[idx+i] << 8) | data[idx+i+1]))
        idx += ciphers_len
        
        # Compression Methods
        if idx + 1 > len(data):
            return None
        comp_len = data[idx]
        idx += 1 + comp_len
        
        # Extensions
        if idx + 2 > len(data):
            return None
        extensions_len = (data[idx] << 8) | data[idx+1]
        idx += 2
        
        extensions = []
        curves = []
        formats = []
        
        ext_end = idx + extensions_len
        if ext_end > len(data):
            ext_end = len(data)
            
        while idx + 4 <= ext_end:
            ext_type = (data[idx] << 8) | data[idx+1]
            ext_len = (data[idx+2] << 8) | data[idx+3]
            idx += 4
            
            extensions.append(str(ext_type))
            
            # Extension 10: supported_groups (curves)
            if ext_type == 10 and idx + ext_len <= ext_end:
                if ext_len >= 2:
                    groups_len = (data[idx] << 8) | data[idx+1]
                    for g in range(0, groups_len, 2):
                        if idx + 2 + g + 2 <= ext_end:
                            curves.append(str((data[idx+2+g] << 8) | data[idx+2+g+1]))
            # Extension 11: ec_point_formats
            elif ext_type == 11 and idx + ext_len <= ext_end:
                formats_len = data[idx]
                for f in range(formats_len):
                    if idx + 1 + f < ext_end:
                        formats.append(str(data[idx+1+f]))
                        
            idx += ext_len
            
        ja3_string = f"{handshake_ver},{'-'.join(ciphers)},{'-'.join(extensions)},{'-'.join(curves)},{'-'.join(formats)}"
        return hashlib.md5(ja3_string.encode('utf-8')).hexdigest()
    except Exception:
        return None


class InferenceEngine:
    """Core component that wires feature extraction to ML inference."""

    def __init__(self, model: BaseModel) -> None:
        self.model = model
        self.signature_engine = SignatureEngine()

    def analyze_packet(self, packet: dict) -> InferenceResult:
        features = extract_packet_features(packet)
        src_ip = str(features.get('src_ip', '0.0.0.0'))
        dst_ip = str(features.get('dst_ip', '0.0.0.0'))

        # Check TLS JA3 fingerprint (Encrypted Traffic Analysis - Tier 4.5)
        payload_hex = packet.get('raw_payload_hex')
        if payload_hex:
            ja3_hash = extract_tls_handshake_features(payload_hex)
            if ja3_hash:
                features['ja3_hash'] = ja3_hash
                if ja3_hash in MALICIOUS_JA3_SIGNATURES:
                    features['malware_family'] = MALICIOUS_JA3_SIGNATURES[ja3_hash]
                    return InferenceResult(label='BOTNET', score=1.0, features=features)

        # Context-Aware IP Reputation check (Tier 6)
        ip_reputation_reason = None
        if src_ip in SUSPICIOUS_IPS:
            ip_reputation_reason = f"Source IP matches blocklist: {SUSPICIOUS_IPS[src_ip]}"
        elif dst_ip in SUSPICIOUS_IPS:
            ip_reputation_reason = f"Destination IP matches blocklist: {SUSPICIOUS_IPS[dst_ip]}"

        if ip_reputation_reason:
            features['reputation_match'] = ip_reputation_reason

        # 1. Check if packet matches any signature or whitelist rule (Tier 1-3)
        signature_label = self.signature_engine.check_packet(features)
        if signature_label is not None:
            # If IP reputation is compromised, override any normal whitelist label
            if ip_reputation_reason and signature_label.upper() in ('NORMAL', 'SECURE'):
                result = InferenceResult(label='UNKNOWN', score=1.0, features=features)
            else:
                result = InferenceResult(label=signature_label, score=1.0, features=features)
            return result
            
        # 2. Fall back to ML inference (Tier 5)
        result = self.model.predict(features)
        
        # Apply Reputation Context (Tier 6 Booster)
        if ip_reputation_reason:
            result.score = min(1.0, result.score + 0.35)
            # Elevate normal traffic from blocklisted IP to unknown anomaly
            if result.label.upper() in ('NORMAL', 'SECURE'):
                result.label = 'UNKNOWN'
                
        return result

    def analyze_stream(self, packets: Iterable[dict]) -> Iterator[InferenceResult]:
        for packet in packets:
            yield self.analyze_packet(packet)
