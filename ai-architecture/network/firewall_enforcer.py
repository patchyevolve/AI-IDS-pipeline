"""
Firewall Enforcer — Translates IDS decisions into actual network blocking

When IDS makes a "Block" decision, this module:
1. Updates firewall rules (iptables on Linux, netsh on Windows)
2. Tracks blocked IPs
3. Provides unblocking capability
4. Logs all actions

Usage:
    enforcer = FirewallEnforcer()
    enforcer.block_ip("192.168.1.100")
    enforcer.unblock_ip("192.168.1.100")
"""

import subprocess
import os
import sys
import json
from datetime import datetime
from pathlib import Path


class FirewallEnforcer:
    """
    Enforces IDS decisions at the firewall level.
    
    Supports:
    - Linux: iptables/nftables
    - Windows: netsh advfirewall
    - macOS: pfctl
    """
    
    def __init__(self, log_file: str = "firewall_actions.jsonl"):
        self.blocked_ips = set()
        self.log_file = log_file
        self.platform = sys.platform
        self._load_blocked_ips()
    
    def _load_blocked_ips(self):
        """Load previously blocked IPs from log file"""
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file) as f:
                    for line in f:
                        try:
                            entry = json.loads(line)
                            if entry.get("action") == "block":
                                self.blocked_ips.add(entry.get("ip"))
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                print(f"[firewall] Error loading blocked IPs: {e}")
    
    def _log_action(self, action: str, ip: str, success: bool, error: str = ""):
        """Log firewall action to file"""
        try:
            entry = {
                "timestamp": datetime.now().isoformat(),
                "action": action,
                "ip": ip,
                "success": success,
                "error": error,
                "platform": self.platform,
            }
            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"[firewall] Error logging action: {e}")
    
    def block_ip(self, ip: str) -> bool:
        """Block an IP address at the firewall level"""
        if not self._is_valid_ip(ip):
            print(f"[firewall] Invalid IP address: {ip}")
            return False
        
        if ip in self.blocked_ips:
            print(f"[firewall] IP already blocked: {ip}")
            return True
        
        try:
            if self.platform == "win32":
                return self._block_ip_windows(ip)
            elif self.platform == "linux":
                return self._block_ip_linux(ip)
            elif self.platform == "darwin":
                return self._block_ip_macos(ip)
            else:
                print(f"[firewall] Unsupported platform: {self.platform}")
                return False
        except Exception as e:
            print(f"[firewall] Error blocking {ip}: {e}")
            self._log_action("block", ip, False, str(e))
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address"""
        if ip not in self.blocked_ips:
            print(f"[firewall] IP not blocked: {ip}")
            return True
        
        try:
            if self.platform == "win32":
                return self._unblock_ip_windows(ip)
            elif self.platform == "linux":
                return self._unblock_ip_linux(ip)
            elif self.platform == "darwin":
                return self._unblock_ip_macos(ip)
            else:
                print(f"[firewall] Unsupported platform: {self.platform}")
                return False
        except Exception as e:
            print(f"[firewall] Error unblocking {ip}: {e}")
            self._log_action("unblock", ip, False, str(e))
            return False
    
    def _block_ip_linux(self, ip: str) -> bool:
        """Block IP on Linux using iptables"""
        try:
            # Check if iptables is available
            subprocess.run(
                ["iptables", "--version"],
                capture_output=True,
                check=True,
                timeout=5
            )
            
            # Add DROP rule
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                check=True,
                timeout=5
            )
            
            self.blocked_ips.add(ip)
            print(f"[firewall] Blocked {ip} (iptables)")
            self._log_action("block", ip, True)
            return True
        except subprocess.CalledProcessError as e:
            error = e.stderr.decode() if e.stderr else str(e)
            print(f"[firewall] iptables error: {error}")
            self._log_action("block", ip, False, error)
            return False
        except FileNotFoundError:
            print(f"[firewall] iptables not found (requires root)")
            return False
    
    def _unblock_ip_linux(self, ip: str) -> bool:
        """Unblock IP on Linux using iptables"""
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                check=True,
                timeout=5
            )
            
            self.blocked_ips.discard(ip)
            print(f"[firewall] Unblocked {ip} (iptables)")
            self._log_action("unblock", ip, True)
            return True
        except subprocess.CalledProcessError as e:
            error = e.stderr.decode() if e.stderr else str(e)
            print(f"[firewall] iptables error: {error}")
            self._log_action("unblock", ip, False, error)
            return False
    
    def _block_ip_windows(self, ip: str) -> bool:
        """Block IP on Windows using netsh"""
        try:
            rule_name = f"IDS-Block-{ip.replace('.', '-')}"
            
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}",
                    "protocol=any"
                ],
                capture_output=True,
                check=True,
                timeout=5
            )
            
            self.blocked_ips.add(ip)
            print(f"[firewall] Blocked {ip} (netsh)")
            self._log_action("block", ip, True)
            return True
        except subprocess.CalledProcessError as e:
            error = e.stderr.decode() if e.stderr else str(e)
            print(f"[firewall] netsh error: {error}")
            self._log_action("block", ip, False, error)
            return False
        except FileNotFoundError:
            print(f"[firewall] netsh not found (requires admin)")
            return False
    
    def _unblock_ip_windows(self, ip: str) -> bool:
        """Unblock IP on Windows using netsh"""
        try:
            rule_name = f"IDS-Block-{ip.replace('.', '-')}"
            
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ],
                capture_output=True,
                check=True,
                timeout=5
            )
            
            self.blocked_ips.discard(ip)
            print(f"[firewall] Unblocked {ip} (netsh)")
            self._log_action("unblock", ip, True)
            return True
        except subprocess.CalledProcessError as e:
            error = e.stderr.decode() if e.stderr else str(e)
            print(f"[firewall] netsh error: {error}")
            self._log_action("unblock", ip, False, error)
            return False
    
    def _block_ip_macos(self, ip: str) -> bool:
        """Block IP on macOS using pfctl"""
        try:
            # Create temporary pf rules file
            rules = f"block in quick from {ip} to any\n"
            
            subprocess.run(
                ["sudo", "pfctl", "-f", "-"],
                input=rules.encode(),
                capture_output=True,
                check=True,
                timeout=5
            )
            
            self.blocked_ips.add(ip)
            print(f"[firewall] Blocked {ip} (pfctl)")
            self._log_action("block", ip, True)
            return True
        except subprocess.CalledProcessError as e:
            error = e.stderr.decode() if e.stderr else str(e)
            print(f"[firewall] pfctl error: {error}")
            self._log_action("block", ip, False, error)
            return False
    
    def _unblock_ip_macos(self, ip: str) -> bool:
        """Unblock IP on macOS using pfctl"""
        try:
            subprocess.run(
                ["sudo", "pfctl", "-f", "/etc/pf.conf"],
                capture_output=True,
                check=True,
                timeout=5
            )
            
            self.blocked_ips.discard(ip)
            print(f"[firewall] Unblocked {ip} (pfctl)")
            self._log_action("unblock", ip, True)
            return True
        except subprocess.CalledProcessError as e:
            error = e.stderr.decode() if e.stderr else str(e)
            print(f"[firewall] pfctl error: {error}")
            self._log_action("unblock", ip, False, error)
            return False
    
    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Validate IP address format"""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except ValueError:
            return False
    
    def get_blocked_ips(self) -> set:
        """Get set of currently blocked IPs"""
        return self.blocked_ips.copy()
    
    def clear_all_blocks(self) -> bool:
        """Clear all firewall blocks"""
        ips = list(self.blocked_ips)
        success = True
        for ip in ips:
            if not self.unblock_ip(ip):
                success = False
        return success
    
    def get_stats(self) -> dict:
        """Get firewall statistics"""
        return {
            "platform": self.platform,
            "blocked_ips_count": len(self.blocked_ips),
            "blocked_ips": list(self.blocked_ips),
            "log_file": self.log_file,
        }


if __name__ == "__main__":
    # Test the firewall enforcer
    enforcer = FirewallEnforcer()
    
    print("\n[TEST] Firewall Enforcer")
    print(f"Platform: {enforcer.platform}")
    print(f"Blocked IPs: {enforcer.get_blocked_ips()}")
    
    # Test blocking
    test_ip = "192.168.1.100"
    print(f"\n[TEST] Blocking {test_ip}...")
    if enforcer.block_ip(test_ip):
        print(f"[OK] Successfully blocked {test_ip}")
    else:
        print(f"[FAIL] Could not block {test_ip} (may require admin/root)")
    
    # Show stats
    print(f"\n[STATS] {json.dumps(enforcer.get_stats(), indent=2)}")
    
    # Test unblocking
    print(f"\n[TEST] Unblocking {test_ip}...")
    if enforcer.unblock_ip(test_ip):
        print(f"[OK] Successfully unblocked {test_ip}")
    else:
        print(f"[FAIL] Could not unblock {test_ip}")
