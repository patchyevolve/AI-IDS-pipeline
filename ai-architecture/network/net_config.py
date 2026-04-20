"""
Network Configuration — interface discovery + BPF filter builder
Windows-compatible: uses psutil for interface info, scapy for name mapping.
"""
import socket
import subprocess
import sys
import os
import json

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "net_config.json")

# Preset BPF filters
FILTER_PRESETS = {
    "all traffic":              "",
    "TCP only":                 "tcp",
    "UDP only":                 "udp",
    "HTTP/HTTPS":               "tcp port 80 or tcp port 443",
    "DNS":                      "udp port 53",
    "SSH":                      "tcp port 22",
    "exclude loopback":         "not src net 127.0.0.0/8",
    "high ports (>1024)":       "portrange 1025-65535",
    "suspicious ports":         "tcp port 4444 or tcp port 1337 or tcp port 31337",
    "IDS full (no loopback)":   "ip and not src host 127.0.0.1 and not dst host 127.0.0.1",
}


def _run(cmd: list) -> str:
    try:
        return subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, timeout=4,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        ).decode(errors="ignore")
    except Exception:
        return ""


def _scapy_iface_map() -> dict:
    """
    Returns { friendly_name -> '\\Device\\NPF_{GUID}' } for scapy sniff(iface=...).
    Uses conf.ifaces which has the correct NPF keys scapy actually accepts.
    """
    mapping = {}
    try:
        from scapy.all import conf as scapy_conf
        for npf_key, ifc in scapy_conf.ifaces.items():
            friendly = getattr(ifc, 'name', '') or getattr(ifc, 'description', '')
            if friendly and npf_key:
                mapping[friendly] = npf_key
    except Exception:
        pass
    return mapping


def discover_interfaces() -> list:
    """
    Returns list of dicts:
      { name, description, ip, is_up, is_loopback, scapy_name, speed_mbps }

    scapy_name is what you pass to scapy.sniff(iface=...) on Windows.
    On Linux/macOS scapy_name == name.
    """
    interfaces = []

    # psutil (works on all platforms, most reliable)
    try:
        import psutil
        stats      = psutil.net_if_stats()
        addrs      = psutil.net_if_addrs()
        scapy_map  = _scapy_iface_map() if sys.platform == "win32" else {}

        for name, stat in stats.items():
            ip = ""
            for addr in addrs.get(name, []):
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    break

            # On Windows, scapy needs the NPF GUID name
            scapy_name = scapy_map.get(name, name)

            interfaces.append({
                "name":        name,
                "description": name,
                "ip":          ip,
                "is_up":       stat.isup,
                "is_loopback": (name.lower() in ("lo", "loopback") or
                                ip.startswith("127.") or
                                "loopback" in name.lower()),
                "speed_mbps":  stat.speed,
                "scapy_name":  scapy_name,
            })
        if interfaces:
            return interfaces
    except ImportError:
        pass

    # Windows fallback without psutil: use scapy directly
    if sys.platform == "win32":
        try:
            from scapy.arch.windows import get_windows_if_list
            for iface in get_windows_if_list():
                name = iface.get("name") or iface.get("description", "unknown")
                ip   = iface.get("ips", [""])[0] if iface.get("ips") else ""
                interfaces.append({
                    "name":        name,
                    "description": iface.get("description", name),
                    "ip":          ip,
                    "is_up":       True,
                    "is_loopback": "loopback" in name.lower() or ip.startswith("127."),
                    "speed_mbps":  0,
                    "scapy_name":  iface.get("win_index", name),
                })
            if interfaces:
                return interfaces
        except Exception:
            pass

        # Last resort: ipconfig
        out = _run(["ipconfig"])
        current_name = "Unknown"
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.endswith(":") and not stripped.startswith(" "):
                current_name = stripped.rstrip(":").strip()
            if "IPv4 Address" in stripped:
                ip = stripped.split(":")[-1].strip().replace("(Preferred)", "").strip()
                interfaces.append({
                    "name":        current_name,
                    "description": current_name,
                    "ip":          ip,
                    "is_up":       True,
                    "is_loopback": "loopback" in current_name.lower(),
                    "speed_mbps":  0,
                    "scapy_name":  current_name,
                })
        return interfaces

    # Linux/macOS fallback
    out = _run(["ip", "-o", "link", "show"]) or _run(["ifconfig", "-a"])
    seen = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            name = parts[1].rstrip(":").split("@")[0]
            if name and name not in seen:
                seen.add(name)
                interfaces.append({
                    "name":        name,
                    "description": name,
                    "ip":          "",
                    "is_up":       "UP" in line,
                    "is_loopback": name == "lo",
                    "speed_mbps":  0,
                    "scapy_name":  name,
                })
    return interfaces


def save_config(iface: str, scapy_name: str, bpf_filter: str, mode: str = "live") -> dict:
    cfg = {
        "interface":   iface,
        "scapy_name":  scapy_name,
        "filter":      bpf_filter,
        "mode":        mode,
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)
    return cfg


def load_config() -> dict | None:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return None
