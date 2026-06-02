#!/usr/bin/env python3
import sys
import time
import argparse
import os

def check_root():
    if os.geteuid() != 0:
        print("WARNING: This script requires root (sudo) privileges to send raw packets (Scapy).")
        print("Please run with: sudo venv/bin/python simulate_attacks.py ...")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Sentinel Network Intrusion Attack Simulator")
    parser.add_argument("--type", type=str, choices=["portscan", "ddos", "udp"], default="portscan",
                        help="Type of attack to simulate (portscan, ddos, udp)")
    parser.add_argument("--target", type=str, default="127.0.0.1",
                        help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=80,
                        help="Target port for DDoS or UDP (default: 80)")
    parser.add_argument("--count", type=int, default=0,
                        help="Number of packets/ports to send (default: 15 for portscan, 150 for ddos/udp)")
    
    args = parser.parse_args()
    
    check_root()
    
    # Import Scapy
    try:
        from scapy.all import IP, TCP, UDP, send
    except ImportError:
        print("Error: Scapy is not installed in the python environment.")
        print("Please make sure you run the script using the project's virtual environment python.")
        sys.exit(1)
        
    target = args.target
    attack_type = args.type
    
    if attack_type == "portscan":
        count = args.count if args.count > 0 else 15
        print(f"[*] Starting Portscan Simulation against {target} ({count} ports)...")
        start_time = time.time()
        for i in range(count):
            dest_port = 20 + i
            # Avoid sending to whitelisted application ports (8000, 5173, etc.) to ensure we trigger detection
            if dest_port in [8000, 5173, 3000, 53, 123]:
                dest_port = 200 + i
            pkt = IP(dst=target)/TCP(sport=45678, dport=dest_port, flags="S")
            send(pkt, verbose=False)
            print(f"    Sent TCP SYN probe to port {dest_port}")
            time.sleep(0.05)
        print(f"[+] Done. Sent {count} portscan packets in {time.time() - start_time:.2f} seconds.")
        
    elif attack_type == "ddos":
        count = args.count if args.count > 0 else 150
        port = args.port
        print(f"[*] Starting SYN Flood (DDoS) Simulation against {target}:{port} ({count} packets)...")
        start_time = time.time()
        
        # Build batch of packets
        packets = []
        for i in range(count):
            pkt = IP(dst=target)/TCP(sport=1024 + (i % 60000), dport=port, flags="S")
            packets.append(pkt)
            
        send(packets, verbose=False)
        print(f"[+] Done. Sent {count} SYN packets in {time.time() - start_time:.2f} seconds.")
        
    elif attack_type == "udp":
        count = args.count if args.count > 0 else 150
        port = args.port
        print(f"[*] Starting UDP Flood Simulation against {target}:{port} ({count} packets)...")
        start_time = time.time()
        
        # Build batch of packets
        packets = []
        for i in range(count):
            pkt = IP(dst=target)/UDP(sport=1024 + (i % 60000), dport=port)/f"SentinelUDPFloodPacket-{i}"
            packets.append(pkt)
            
        send(packets, verbose=False)
        print(f"[+] Done. Sent {count} UDP packets in {time.time() - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
