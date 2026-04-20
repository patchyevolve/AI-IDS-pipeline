"""
Base attack profile templates.
Each profile defines the raw payload fields that get injected into the pipeline
as network_event payloads — same format as ids_bridge synthetic events.

Fields mirror ids_types.hpp PayloadFeatures:
  bytes_in, bytes_out, port_src, port_dst, protocol, flags, entropy, rate_hz
"""
import random
import math

# Profile schema
# name, bytes_in, bytes_out, port_dst, protocol, flags, entropy, rate_hz,
# burst_prob (chance of a high-rate burst), jitter (noise factor)

BASE_PROFILES = {
    "DoS_SYN_Flood": {
        "bytes_in":   60,   "bytes_out":  0,
        "port_dst":   80,   "protocol":   6,
        "flags":      0x02, "entropy":    0.05,
        "rate_hz":    8000, "burst_prob": 0.8,
        "jitter":     0.15,
    },
    "DoS_UDP_Flood": {
        "bytes_in":   1400, "bytes_out":  0,
        "port_dst":   0,    "protocol":   17,
        "flags":      0x00, "entropy":    0.10,
        "rate_hz":    6000, "burst_prob": 0.7,
        "jitter":     0.20,
    },
    "PortScan_TCP": {
        "bytes_in":   60,   "bytes_out":  0,
        "port_dst":   -1,   "protocol":   6,   # -1 = random
        "flags":      0x02, "entropy":    0.02,
        "rate_hz":    400,  "burst_prob": 0.3,
        "jitter":     0.10,
    },
    "BruteForce_SSH": {
        "bytes_in":   120,  "bytes_out":  80,
        "port_dst":   22,   "protocol":   6,
        "flags":      0x18, "entropy":    0.45,
        "rate_hz":    250,  "burst_prob": 0.2,
        "jitter":     0.25,
    },
    "BruteForce_RDP": {
        "bytes_in":   200,  "bytes_out":  150,
        "port_dst":   3389, "protocol":   6,
        "flags":      0x18, "entropy":    0.50,
        "rate_hz":    180,  "burst_prob": 0.2,
        "jitter":     0.25,
    },
    "C2_Beacon": {
        "bytes_in":   280,  "bytes_out":  120,
        "port_dst":   443,  "protocol":   6,
        "flags":      0x18, "entropy":    0.88,
        "rate_hz":    8,    "burst_prob": 0.05,
        "jitter":     0.30,
    },
    "Exfiltration_HTTPS": {
        "bytes_in":   200,  "bytes_out":  9000,
        "port_dst":   443,  "protocol":   6,
        "flags":      0x18, "entropy":    0.95,
        "rate_hz":    300,  "burst_prob": 0.4,
        "jitter":     0.20,
    },
    "DNS_Tunnel": {
        "bytes_in":   512,  "bytes_out":  256,
        "port_dst":   53,   "protocol":   17,
        "flags":      0x00, "entropy":    0.93,
        "rate_hz":    60,   "burst_prob": 0.1,
        "jitter":     0.15,
    },
    "LateralMovement_SMB": {
        "bytes_in":   400,  "bytes_out":  300,
        "port_dst":   445,  "protocol":   6,
        "flags":      0x18, "entropy":    0.60,
        "rate_hz":    50,   "burst_prob": 0.15,
        "jitter":     0.20,
    },
    "SlowLoris": {
        "bytes_in":   80,   "bytes_out":  40,
        "port_dst":   80,   "protocol":   6,
        "flags":      0x18, "entropy":    0.30,
        "rate_hz":    2,    "burst_prob": 0.0,
        "jitter":     0.40,
    },
}


def sample_payload(profile: dict, mutation: dict = None) -> dict:
    """
    Generate one payload dict from a profile + optional mutation overrides.
    Applies jitter and burst_prob.
    """
    p = {**profile, **(mutation or {})}
    j = p.get("jitter", 0.2)

    def noise(v, factor=None):
        f = factor if factor is not None else j
        return max(0, v * (1 + random.uniform(-f, f)))

    port_dst = p["port_dst"]
    if port_dst == -1:
        port_dst = random.randint(1, 65535)

    # Burst: occasionally spike rate
    rate = p["rate_hz"]
    if random.random() < p.get("burst_prob", 0.0):
        rate *= random.uniform(2.0, 5.0)

    return {
        "bytes_in":  int(noise(p["bytes_in"])),
        "bytes_out": int(noise(p.get("bytes_out", 0))),
        "port_src":  random.randint(1024, 65535),
        "port_dst":  port_dst,
        "protocol":  p["protocol"],
        "flags":     p["flags"],
        "entropy":   round(min(1.0, max(0.0, noise(p["entropy"], j * 0.5))), 4),
        "rate_hz":   round(noise(rate), 2),
    }
