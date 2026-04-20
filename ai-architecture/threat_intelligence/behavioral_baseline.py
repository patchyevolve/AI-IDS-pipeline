"""
Behavioral Baselining Engine

Establishes normal behavior patterns for IPs, users, and hosts.
Detects anomalies based on deviation from baseline.
Supports zero-day detection through statistical analysis.
"""
import json
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
import statistics


class BehavioralBaseline:
    """Tracks and analyzes behavioral patterns."""
    
    def __init__(self, baseline_window_hours: int = 24):
        self.baseline_window = baseline_window_hours * 3600
        
        # Per-IP baselines
        self.ip_baselines = defaultdict(lambda: {
            "ports_accessed": set(),
            "protocols_used": set(),
            "bytes_patterns": [],
            "rate_patterns": [],
            "entropy_patterns": [],
            "time_patterns": defaultdict(int),
            "first_seen": None,
            "last_seen": None,
            "total_events": 0
        })
        
        # Per-host baselines
        self.host_baselines = defaultdict(lambda: {
            "incoming_sources": set(),
            "outgoing_destinations": set(),
            "services_running": set(),
            "typical_traffic_volume": 0,
            "peak_hours": [],
            "first_seen": None,
            "last_seen": None
        })
        
        # Per-user baselines
        self.user_baselines = defaultdict(lambda: {
            "typical_login_times": [],
            "typical_locations": set(),
            "typical_devices": set(),
            "access_patterns": defaultdict(int),
            "first_seen": None,
            "last_seen": None
        })
        
        # Anomaly thresholds
        self.thresholds = {
            "port_deviation": 0.3,  # 30% deviation from baseline
            "rate_deviation": 0.5,  # 50% deviation
            "entropy_deviation": 0.4,  # 40% deviation
            "bytes_deviation": 0.6,  # 60% deviation
            "new_port_threshold": 5,  # Alert if accessing >5 new ports
            "new_protocol_threshold": 2,  # Alert if using >2 new protocols
        }
    
    def update_ip_baseline(self, source_ip: str, event: Dict) -> None:
        """Update baseline for source IP."""
        
        baseline = self.ip_baselines[source_ip]
        now = datetime.now().timestamp()
        
        if baseline["first_seen"] is None:
            baseline["first_seen"] = now
        
        baseline["last_seen"] = now
        baseline["total_events"] += 1
        
        # Track ports
        port_dst = event.get("port_dst", 0)
        if port_dst > 0:
            baseline["ports_accessed"].add(port_dst)
        
        # Track protocols
        protocol = event.get("protocol", 0)
        baseline["protocols_used"].add(protocol)
        
        # Track traffic patterns
        bytes_in = event.get("bytes_in", 0)
        bytes_out = event.get("bytes_out", 0)
        baseline["bytes_patterns"].append(bytes_in + bytes_out)
        
        # Track rate
        rate = event.get("rate_hz", 0)
        baseline["rate_patterns"].append(rate)
        
        # Track entropy
        entropy = event.get("entropy", 0)
        baseline["entropy_patterns"].append(entropy)
        
        # Track time patterns
        hour = datetime.fromtimestamp(now).hour
        baseline["time_patterns"][hour] += 1
        
        # Keep only recent data
        if len(baseline["bytes_patterns"]) > 1000:
            baseline["bytes_patterns"] = baseline["bytes_patterns"][-1000:]
            baseline["rate_patterns"] = baseline["rate_patterns"][-1000:]
            baseline["entropy_patterns"] = baseline["entropy_patterns"][-1000:]
    
    def update_host_baseline(self, host_ip: str, source_ip: str, 
                            event: Dict) -> None:
        """Update baseline for destination host."""
        
        baseline = self.host_baselines[host_ip]
        now = datetime.now().timestamp()
        
        if baseline["first_seen"] is None:
            baseline["first_seen"] = now
        
        baseline["last_seen"] = now
        baseline["incoming_sources"].add(source_ip)
        
        # Track service ports
        port_dst = event.get("port_dst", 0)
        if port_dst > 0:
            baseline["services_running"].add(port_dst)
        
        # Track traffic volume
        bytes_in = event.get("bytes_in", 0)
        baseline["typical_traffic_volume"] += bytes_in
    
    def detect_ip_anomalies(self, source_ip: str, event: Dict) -> List[str]:
        """Detect anomalies in IP behavior."""
        
        baseline = self.ip_baselines[source_ip]
        anomalies = []
        
        # Need baseline data
        if baseline["total_events"] < 10:
            return anomalies
        
        # Check for new ports
        port_dst = event.get("port_dst", 0)
        if port_dst > 0 and port_dst not in baseline["ports_accessed"]:
            if len(baseline["ports_accessed"]) > 0:
                anomalies.append("new_port_accessed")
        
        # Check for new protocols
        protocol = event.get("protocol", 0)
        if protocol not in baseline["protocols_used"]:
            anomalies.append("new_protocol_used")
        
        # Check for rate anomaly
        if baseline["rate_patterns"]:
            baseline_rate = statistics.mean(baseline["rate_patterns"])
            current_rate = event.get("rate_hz", 0)
            
            if baseline_rate > 0:
                deviation = abs(current_rate - baseline_rate) / baseline_rate
                if deviation > self.thresholds["rate_deviation"]:
                    anomalies.append("rate_anomaly")
        
        # Check for entropy anomaly
        if baseline["entropy_patterns"]:
            baseline_entropy = statistics.mean(baseline["entropy_patterns"])
            current_entropy = event.get("entropy", 0)
            
            deviation = abs(current_entropy - baseline_entropy)
            if deviation > self.thresholds["entropy_deviation"]:
                anomalies.append("entropy_anomaly")
        
        # Check for bytes anomaly
        if baseline["bytes_patterns"]:
            baseline_bytes = statistics.mean(baseline["bytes_patterns"])
            current_bytes = event.get("bytes_in", 0) + event.get("bytes_out", 0)
            
            if baseline_bytes > 0:
                deviation = abs(current_bytes - baseline_bytes) / baseline_bytes
                if deviation > self.thresholds["bytes_deviation"]:
                    anomalies.append("bytes_anomaly")
        
        # Check for unusual time
        hour = datetime.now().hour
        if hour not in baseline["time_patterns"]:
            anomalies.append("unusual_time")
        
        return anomalies
    
    def detect_host_anomalies(self, host_ip: str, source_ip: str, 
                             event: Dict) -> List[str]:
        """Detect anomalies in host behavior."""
        
        baseline = self.host_baselines[host_ip]
        anomalies = []
        
        # Check for new source
        if source_ip not in baseline["incoming_sources"]:
            if len(baseline["incoming_sources"]) > 0:
                anomalies.append("new_source_ip")
        
        # Check for new service port
        port_dst = event.get("port_dst", 0)
        if port_dst > 0 and port_dst not in baseline["services_running"]:
            if len(baseline["services_running"]) > 0:
                anomalies.append("new_service_port")
        
        # Check for traffic volume anomaly
        bytes_in = event.get("bytes_in", 0)
        if baseline["typical_traffic_volume"] > 0:
            avg_bytes = baseline["typical_traffic_volume"] / max(1, len(baseline["incoming_sources"]))
            if bytes_in > avg_bytes * 3:  # 3x normal
                anomalies.append("traffic_volume_anomaly")
        
        return anomalies
    
    def get_ip_profile(self, source_ip: str) -> Dict:
        """Get behavioral profile for IP."""
        
        baseline = self.ip_baselines[source_ip]
        
        if baseline["total_events"] == 0:
            return {"source_ip": source_ip, "profile": None}
        
        profile = {
            "source_ip": source_ip,
            "total_events": baseline["total_events"],
            "ports_accessed": len(baseline["ports_accessed"]),
            "protocols_used": list(baseline["protocols_used"]),
            "first_seen": datetime.fromtimestamp(baseline["first_seen"]).isoformat(),
            "last_seen": datetime.fromtimestamp(baseline["last_seen"]).isoformat(),
            "activity_duration_hours": (baseline["last_seen"] - baseline["first_seen"]) / 3600,
        }
        
        # Add statistical patterns
        if baseline["bytes_patterns"]:
            profile["bytes_stats"] = {
                "mean": statistics.mean(baseline["bytes_patterns"]),
                "median": statistics.median(baseline["bytes_patterns"]),
                "stdev": statistics.stdev(baseline["bytes_patterns"]) if len(baseline["bytes_patterns"]) > 1 else 0,
                "min": min(baseline["bytes_patterns"]),
                "max": max(baseline["bytes_patterns"])
            }
        
        if baseline["rate_patterns"]:
            profile["rate_stats"] = {
                "mean": statistics.mean(baseline["rate_patterns"]),
                "median": statistics.median(baseline["rate_patterns"]),
                "stdev": statistics.stdev(baseline["rate_patterns"]) if len(baseline["rate_patterns"]) > 1 else 0,
                "min": min(baseline["rate_patterns"]),
                "max": max(baseline["rate_patterns"])
            }
        
        if baseline["entropy_patterns"]:
            profile["entropy_stats"] = {
                "mean": statistics.mean(baseline["entropy_patterns"]),
                "median": statistics.median(baseline["entropy_patterns"]),
                "stdev": statistics.stdev(baseline["entropy_patterns"]) if len(baseline["entropy_patterns"]) > 1 else 0,
                "min": min(baseline["entropy_patterns"]),
                "max": max(baseline["entropy_patterns"])
            }
        
        # Peak activity hours
        if baseline["time_patterns"]:
            peak_hours = sorted(baseline["time_patterns"].items(), 
                              key=lambda x: x[1], reverse=True)[:3]
            profile["peak_hours"] = [h[0] for h in peak_hours]
        
        return profile
    
    def get_host_profile(self, host_ip: str) -> Dict:
        """Get behavioral profile for host."""
        
        baseline = self.host_baselines[host_ip]
        
        if baseline["first_seen"] is None:
            return {"host_ip": host_ip, "profile": None}
        
        profile = {
            "host_ip": host_ip,
            "incoming_sources": len(baseline["incoming_sources"]),
            "services_running": list(baseline["services_running"]),
            "typical_traffic_volume": baseline["typical_traffic_volume"],
            "first_seen": datetime.fromtimestamp(baseline["first_seen"]).isoformat(),
            "last_seen": datetime.fromtimestamp(baseline["last_seen"]).isoformat(),
        }
        
        return profile
    
    def detect_zero_day(self, source_ip: str, event: Dict) -> Optional[Dict]:
        """Detect potential zero-day attacks through statistical anomalies."""
        
        anomalies = self.detect_ip_anomalies(source_ip, event)
        
        if len(anomalies) >= 3:  # Multiple anomalies suggest zero-day
            return {
                "source_ip": source_ip,
                "zero_day_indicator": True,
                "anomalies": anomalies,
                "confidence": min(0.95, 0.5 + len(anomalies) * 0.15),
                "recommendation": "Investigate immediately - potential zero-day attack",
                "timestamp": datetime.now().isoformat()
            }
        
        return None
    
    def export_baseline_report(self) -> Dict:
        """Export comprehensive baseline report."""
        
        return {
            "report_type": "behavioral_baseline",
            "timestamp": datetime.now().isoformat(),
            "total_ips_tracked": len(self.ip_baselines),
            "total_hosts_tracked": len(self.host_baselines),
            "total_users_tracked": len(self.user_baselines),
            "ip_profiles": {
                ip: self.get_ip_profile(ip)
                for ip in list(self.ip_baselines.keys())[:100]  # Top 100
            },
            "host_profiles": {
                host: self.get_host_profile(host)
                for host in list(self.host_baselines.keys())[:50]  # Top 50
            }
        }
