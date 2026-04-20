import sys
import os
import json
import time
import socket
from datetime import datetime

ATTACKER_PORT = 9875

def sniff_and_forward(target_ids_ip, interface="eth0"):
    """
    Universal Pluggable Agent
    Can run on any Linux router, Mobile device, or PC.
    Sniffs local traffic and streams JSON to the central AI-IDS.
    """
    print(f"[*] Universal Agent starting on {interface}")
    print(f"[*] Connecting to AI-IDS at {target_ids_ip}:{ATTACKER_PORT}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((target_ids_ip, ATTACKER_PORT))
        print("[+] Connected successfully!")
    except Exception as e:
        print(f"[-] Could not connect to AI-IDS: {e}")
        return

    # In a real deployment, you would hook into libpcap/scapy/eBPF here.
    # For demonstration, we simulate forwarding router/mobile flow logs.
    
    try:
        while True:
            # Simulate a parsed packet/flow record from the edge device
            simulated_flow = {
                "type": "network_event",
                "source": "192.168.1.105",  # The local device IP
                "destination": "8.8.8.8",
                "payload": {
                    "bytes_in": 120,
                    "bytes_out": 40,
                    "port_src": 45012,
                    "port_dst": 53,
                    "protocol": 17,
                    "flags": 0,
                    "entropy": 0.23,
                    "rate_hz": 12.5
                },
                "timestamp": datetime.now().isoformat()
            }
            
            # Stream to central IDS
            payload = json.dumps(simulated_flow) + "\n"
            sock.sendall(payload.encode('utf-8'))
            print(f"[→] Forwarded flow to IDS: {simulated_flow['payload']['port_dst']}")
            
            time.sleep(2.0)
            
    except KeyboardInterrupt:
        print("\n[*] Agent shutting down.")
    finally:
        sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python universal_agent.py <IDS_IP>")
        sys.exit(1)
    
    sniff_and_forward(sys.argv[1])
