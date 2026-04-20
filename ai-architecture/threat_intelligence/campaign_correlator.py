"""
Campaign Correlation Engine

Correlates attacks across multiple sources to identify coordinated campaigns.
Detects distributed attacks, multi-stage operations, and threat actor patterns.
"""
import json
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional
import hashlib


class CampaignCorrelator:
    """Correlates attacks into campaigns and identifies threat actors."""
    
    def __init__(self, correlation_window_hours: int = 24):
        self.correlation_window = correlation_window_hours * 3600
        
        # Campaign tracking
        self.campaigns = {}  # campaign_id -> campaign_data
        self.campaign_counter = 0
        
        # Attack correlation
        self.attack_signatures = defaultdict(list)  # signature -> [attacks]
        self.source_clusters = defaultdict(set)  # cluster_id -> {source_ips}
        self.target_clusters = defaultdict(set)  # cluster_id -> {target_ips}
        
        # Threat actor profiles
        self.threat_actors = {}  # actor_id -> actor_profile
        self.actor_counter = 0
        
        # Time-based correlation
        self.time_windows = defaultdict(list)  # time_bucket -> [attacks]
    
    def correlate_attack(self, attack: Dict) -> Optional[str]:
        """Correlate attack to existing campaign or create new one."""
        
        source_ip = attack.get("source_ip")
        attack_class = attack.get("attack_class")
        timestamp = attack.get("timestamp", datetime.now().timestamp())
        
        # Generate attack signature
        signature = self._generate_signature(attack)
        
        # Find similar attacks
        similar_attacks = self.attack_signatures[signature]
        
        # Check for campaign correlation
        campaign_id = None
        
        if similar_attacks:
            # Check if attacks are within correlation window
            for prev_attack in similar_attacks[-10:]:  # Check last 10
                time_diff = abs(timestamp - prev_attack.get("timestamp", 0))
                
                if time_diff < self.correlation_window:
                    # Found correlated attack
                    campaign_id = prev_attack.get("campaign_id")
                    break
        
        # Create new campaign if needed
        if campaign_id is None:
            campaign_id = self._create_campaign(attack)
        
        # Update campaign
        self._update_campaign(campaign_id, attack)
        
        # Track attack
        attack["campaign_id"] = campaign_id
        self.attack_signatures[signature].append(attack)
        
        return campaign_id
    
    def _generate_signature(self, attack: Dict) -> str:
        """Generate signature for attack pattern matching."""
        
        components = [
            attack.get("attack_class", "unknown"),
            attack.get("protocol", ""),
            attack.get("port_dst", ""),
            attack.get("entropy", "")
        ]
        
        signature_str = "|".join(str(c) for c in components)
        return hashlib.md5(signature_str.encode()).hexdigest()[:16]
    
    def _create_campaign(self, attack: Dict) -> str:
        """Create new campaign."""
        
        self.campaign_counter += 1
        campaign_id = f"CAMP_{self.campaign_counter:06d}"
        
        self.campaigns[campaign_id] = {
            "id": campaign_id,
            "created": datetime.now().isoformat(),
            "attack_class": attack.get("attack_class"),
            "source_ips": set(),
            "target_ips": set(),
            "attacks": [],
            "severity": attack.get("severity", 5),
            "status": "active",
            "threat_actor": None
        }
        
        return campaign_id
    
    def _update_campaign(self, campaign_id: str, attack: Dict) -> None:
        """Update campaign with new attack."""
        
        if campaign_id not in self.campaigns:
            return
        
        campaign = self.campaigns[campaign_id]
        
        source_ip = attack.get("source_ip")
        target_ip = attack.get("destination_ip")
        
        campaign["source_ips"].add(source_ip)
        campaign["target_ips"].add(target_ip)
        campaign["attacks"].append(attack)
        campaign["last_seen"] = datetime.now().isoformat()
        
        # Update severity
        campaign["severity"] = max(campaign["severity"], 
                                  attack.get("severity", 5))
        
        # Detect if distributed
        if len(campaign["source_ips"]) > 5:
            campaign["type"] = "distributed"
        elif len(campaign["target_ips"]) > 5:
            campaign["type"] = "multi_target"
        else:
            campaign["type"] = "single_source"
    
    def detect_distributed_attack(self, target_ip: str, 
                                 time_window_seconds: int = 300) -> Optional[Dict]:
        """Detect distributed attack on single target."""
        
        now = datetime.now().timestamp()
        recent_attacks = []
        
        # Find attacks on target within time window
        for campaign in self.campaigns.values():
            if target_ip in campaign["target_ips"]:
                for attack in campaign["attacks"]:
                    if now - attack.get("timestamp", 0) < time_window_seconds:
                        recent_attacks.append(attack)
        
        if len(recent_attacks) >= 5:  # Threshold for distributed attack
            source_ips = set(a.get("source_ip") for a in recent_attacks)
            
            return {
                "target_ip": target_ip,
                "distributed_attack": True,
                "num_sources": len(source_ips),
                "source_ips": list(source_ips),
                "num_attacks": len(recent_attacks),
                "time_window": time_window_seconds,
                "severity": 9,
                "recommendation": "Implement DDoS mitigation immediately"
            }
        
        return None
    
    def detect_multi_stage_attack(self, source_ip: str) -> Optional[Dict]:
        """Detect multi-stage attack progression."""
        
        # Find all attacks from source
        source_attacks = []
        for campaign in self.campaigns.values():
            if source_ip in campaign["source_ips"]:
                source_attacks.extend(campaign["attacks"])
        
        if len(source_attacks) < 2:
            return None
        
        # Sort by timestamp
        source_attacks.sort(key=lambda x: x.get("timestamp", 0))
        
        # Detect progression patterns
        attack_classes = [a.get("attack_class") for a in source_attacks]
        
        # Common progression patterns
        patterns = {
            "reconnaissance_to_exploitation": ["PortScan", "Reconnaissance", "BruteForce"],
            "initial_access_to_persistence": ["BruteForce", "Malware", "C2_Beacon"],
            "lateral_movement_chain": ["LateralMovement", "Reconnaissance", "BruteForce"],
        }
        
        detected_patterns = []
        for pattern_name, pattern in patterns.items():
            if self._matches_progression(attack_classes, pattern):
                detected_patterns.append(pattern_name)
        
        if detected_patterns:
            return {
                "source_ip": source_ip,
                "multi_stage_attack": True,
                "attack_progression": attack_classes,
                "detected_patterns": detected_patterns,
                "num_stages": len(source_attacks),
                "severity": 8,
                "recommendation": "Implement incident response procedures"
            }
        
        return None
    
    def _matches_progression(self, sequence: List[str], 
                            pattern: List[str]) -> bool:
        """Check if attack sequence matches progression pattern."""
        
        if len(sequence) < len(pattern):
            return False
        
        # Allow some flexibility in ordering
        pattern_set = set(pattern)
        sequence_set = set(sequence)
        
        return pattern_set.issubset(sequence_set)
    
    def identify_threat_actor(self, campaign_id: str) -> Optional[str]:
        """Identify threat actor from campaign characteristics."""
        
        if campaign_id not in self.campaigns:
            return None
        
        campaign = self.campaigns[campaign_id]
        
        # Analyze campaign characteristics
        num_sources = len(campaign["source_ips"])
        num_targets = len(campaign["target_ips"])
        attack_class = campaign.get("attack_class")
        severity = campaign.get("severity")
        
        # Threat actor classification
        if num_sources > 100 and severity >= 8:
            actor_type = "APT (Advanced Persistent Threat)"
        elif num_sources > 20 and severity >= 7:
            actor_type = "Organized Cybercriminal Group"
        elif num_sources > 5 and severity >= 6:
            actor_type = "Coordinated Attack Group"
        elif attack_class == "BruteForce" and num_targets > 50:
            actor_type = "Credential Harvesting Group"
        elif attack_class == "DoS/DDoS":
            actor_type = "DDoS-for-Hire Service"
        else:
            actor_type = "Opportunistic Attacker"
        
        # Create or update threat actor profile
        actor_id = self._get_or_create_actor(actor_type, campaign)
        campaign["threat_actor"] = actor_id
        
        return actor_id
    
    def _get_or_create_actor(self, actor_type: str, campaign: Dict) -> str:
        """Get or create threat actor profile."""
        
        # Check if similar actor exists
        for actor_id, actor in self.threat_actors.items():
            if actor.get("type") == actor_type:
                actor["campaigns"].append(campaign["id"])
                return actor_id
        
        # Create new actor
        self.actor_counter += 1
        actor_id = f"ACTOR_{self.actor_counter:06d}"
        
        self.threat_actors[actor_id] = {
            "id": actor_id,
            "type": actor_type,
            "created": datetime.now().isoformat(),
            "campaigns": [campaign["id"]],
            "total_attacks": len(campaign["attacks"]),
            "target_count": len(campaign["target_ips"]),
            "source_count": len(campaign["source_ips"])
        }
        
        return actor_id
    
    def get_campaign_details(self, campaign_id: str) -> Optional[Dict]:
        """Get detailed campaign information."""
        
        if campaign_id not in self.campaigns:
            return None
        
        campaign = self.campaigns[campaign_id]
        
        return {
            "id": campaign["id"],
            "created": campaign["created"],
            "last_seen": campaign.get("last_seen"),
            "attack_class": campaign["attack_class"],
            "type": campaign.get("type", "unknown"),
            "status": campaign["status"],
            "severity": campaign["severity"],
            "threat_actor": campaign.get("threat_actor"),
            "source_ips": list(campaign["source_ips"]),
            "target_ips": list(campaign["target_ips"]),
            "num_attacks": len(campaign["attacks"]),
            "num_sources": len(campaign["source_ips"]),
            "num_targets": len(campaign["target_ips"]),
            "attack_timeline": [
                {
                    "timestamp": a.get("timestamp"),
                    "source": a.get("source_ip"),
                    "target": a.get("destination_ip"),
                    "class": a.get("attack_class")
                }
                for a in sorted(campaign["attacks"], 
                              key=lambda x: x.get("timestamp", 0))
            ]
        }
    
    def get_active_campaigns(self) -> List[Dict]:
        """Get list of active campaigns."""
        
        active = []
        for campaign_id, campaign in self.campaigns.items():
            if campaign["status"] == "active":
                active.append(self.get_campaign_details(campaign_id))
        
        return sorted(active, key=lambda x: x["severity"], reverse=True)
    
    def export_campaign_report(self) -> Dict:
        """Export comprehensive campaign report."""
        
        return {
            "report_type": "campaign_correlation",
            "timestamp": datetime.now().isoformat(),
            "total_campaigns": len(self.campaigns),
            "active_campaigns": len([c for c in self.campaigns.values() 
                                    if c["status"] == "active"]),
            "total_threat_actors": len(self.threat_actors),
            "campaigns": [
                self.get_campaign_details(cid)
                for cid in list(self.campaigns.keys())[:50]  # Top 50
            ],
            "threat_actors": list(self.threat_actors.values())
        }
