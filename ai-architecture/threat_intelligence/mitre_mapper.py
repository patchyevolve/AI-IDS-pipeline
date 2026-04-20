"""
MITRE ATT&CK Framework Mapper

Maps detected attacks to MITRE ATT&CK tactics and techniques.
Provides threat context, severity scoring, and attack chain analysis.
"""
import json
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple, Optional


# MITRE ATT&CK Tactics
TACTICS = {
    "reconnaissance": {
        "id": "TA0043",
        "description": "Gather information used to plan future operations",
        "techniques": ["T1592", "T1589", "T1590", "T1598", "T1597", "T1591"]
    },
    "resource_development": {
        "id": "TA0042",
        "description": "Establish resources for conducting operations",
        "techniques": ["T1583", "T1586", "T1583", "T1583"]
    },
    "initial_access": {
        "id": "TA0001",
        "description": "Techniques used to gain initial foothold",
        "techniques": ["T1189", "T1190", "T1133", "T1200", "T1566"]
    },
    "execution": {
        "id": "TA0002",
        "description": "Techniques to run malicious code",
        "techniques": ["T1059", "T1203", "T1559", "T1559"]
    },
    "persistence": {
        "id": "TA0003",
        "description": "Techniques to maintain access",
        "techniques": ["T1098", "T1197", "T1547", "T1547"]
    },
    "privilege_escalation": {
        "id": "TA0004",
        "description": "Techniques to gain higher privileges",
        "techniques": ["T1548", "T1134", "T1547", "T1547"]
    },
    "defense_evasion": {
        "id": "TA0005",
        "description": "Techniques to avoid detection",
        "techniques": ["T1548", "T1197", "T1140", "T1197"]
    },
    "credential_access": {
        "id": "TA0006",
        "description": "Techniques to steal credentials",
        "techniques": ["T1110", "T1555", "T1187", "T1040"]
    },
    "discovery": {
        "id": "TA0007",
        "description": "Techniques to explore the environment",
        "techniques": ["T1087", "T1010", "T1217", "T1580"]
    },
    "lateral_movement": {
        "id": "TA0008",
        "description": "Techniques to move through network",
        "techniques": ["T1570", "T1570", "T1021", "T1570"]
    },
    "collection": {
        "id": "TA0009",
        "description": "Techniques to gather data",
        "techniques": ["T1557", "T1123", "T1119", "T1115"]
    },
    "command_and_control": {
        "id": "TA0011",
        "description": "Techniques to communicate with compromised systems",
        "techniques": ["T1071", "T1092", "T1001", "T1008"]
    },
    "exfiltration": {
        "id": "TA0010",
        "description": "Techniques to steal data",
        "techniques": ["T1020", "T1030", "T1048", "T1041"]
    },
    "impact": {
        "id": "TA0040",
        "description": "Techniques to disrupt availability/integrity",
        "techniques": ["T1531", "T1561", "T1485", "T1561"]
    }
}


# Attack Class to MITRE Mapping
ATTACK_CLASS_MAPPING = {
    "DoS/DDoS": {
        "tactics": ["impact"],
        "techniques": ["T1561"],  # Disk Wipe (impact)
        "severity": 8,
        "description": "Denial of Service attack attempting to disrupt availability"
    },
    "PortScan": {
        "tactics": ["reconnaissance", "discovery"],
        "techniques": ["T1592", "T1580"],  # Gather network info
        "severity": 3,
        "description": "Network reconnaissance to identify open ports and services"
    },
    "BruteForce": {
        "tactics": ["credential_access"],
        "techniques": ["T1110"],  # Brute Force
        "severity": 7,
        "description": "Credential attack attempting unauthorized access"
    },
    "Malware": {
        "tactics": ["execution", "persistence", "defense_evasion"],
        "techniques": ["T1059", "T1547", "T1140"],  # Command execution, persistence
        "severity": 9,
        "description": "Malicious code execution detected"
    },
    "Reconnaissance": {
        "tactics": ["reconnaissance", "discovery"],
        "techniques": ["T1592", "T1589"],  # Gather info
        "severity": 2,
        "description": "Information gathering for future attacks"
    },
    "C2_Beacon": {
        "tactics": ["command_and_control"],
        "techniques": ["T1071"],  # Application Layer Protocol
        "severity": 9,
        "description": "Command and control communication detected"
    },
    "Exfiltration": {
        "tactics": ["exfiltration"],
        "techniques": ["T1041"],  # Exfiltration Over C2 Channel
        "severity": 8,
        "description": "Data exfiltration attempt detected"
    },
    "LateralMovement": {
        "tactics": ["lateral_movement"],
        "techniques": ["T1021"],  # Remote Services
        "severity": 8,
        "description": "Lateral movement within network detected"
    }
}


class MITREMapper:
    """Maps attack detections to MITRE ATT&CK framework."""
    
    def __init__(self):
        self.attack_history = defaultdict(list)
        self.campaign_chains = defaultdict(list)
        self.threat_actors = {}
        
    def map_attack(self, attack_class: str, source_ip: str, 
                   destination_ip: str, timestamp: float) -> Dict:
        """Map detected attack to MITRE tactics and techniques."""
        
        if attack_class not in ATTACK_CLASS_MAPPING:
            return {"error": f"Unknown attack class: {attack_class}"}
        
        mapping = ATTACK_CLASS_MAPPING[attack_class]
        
        result = {
            "attack_class": attack_class,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "timestamp": datetime.fromtimestamp(timestamp).isoformat(),
            "tactics": [],
            "techniques": [],
            "severity": mapping["severity"],
            "description": mapping["description"]
        }
        
        # Add tactic details
        for tactic_name in mapping["tactics"]:
            if tactic_name in TACTICS:
                tactic = TACTICS[tactic_name]
                result["tactics"].append({
                    "name": tactic_name,
                    "id": tactic["id"],
                    "description": tactic["description"]
                })
        
        # Add technique details
        for technique_id in mapping["techniques"]:
            result["techniques"].append({
                "id": technique_id,
                "name": self._get_technique_name(technique_id)
            })
        
        # Track in history
        self.attack_history[source_ip].append(result)
        
        return result
    
    def _get_technique_name(self, technique_id: str) -> str:
        """Get technique name from ID."""
        technique_names = {
            "T1592": "Gather Victim Host Information",
            "T1589": "Gather Victim Identity Information",
            "T1590": "Gather Victim Network Information",
            "T1598": "Phishing for Information",
            "T1597": "Search Open Websites/Domains",
            "T1591": "Gather Victim Organization Information",
            "T1583": "Acquire Infrastructure",
            "T1586": "Compromise Accounts",
            "T1189": "Drive-by Compromise",
            "T1190": "Exploit Public-Facing Application",
            "T1133": "External Remote Services",
            "T1200": "Hardware Additions",
            "T1566": "Phishing",
            "T1059": "Command and Scripting Interpreter",
            "T1203": "Exploitation for Client Execution",
            "T1559": "Inter-Process Communication",
            "T1098": "Account Manipulation",
            "T1197": "BITS Jobs",
            "T1547": "Boot or Logon Autostart Execution",
            "T1548": "Abuse Elevation Control Mechanism",
            "T1134": "Access Token Manipulation",
            "T1140": "Deobfuscate/Decode Files or Information",
            "T1555": "Credentials from Password Stores",
            "T1187": "Forced Authentication",
            "T1040": "Network Sniffing",
            "T1087": "Account Discovery",
            "T1010": "Application Window Discovery",
            "T1217": "Browser Bookmark Discovery",
            "T1580": "Cloud Infrastructure Discovery",
            "T1570": "Lateral Tool Transfer",
            "T1021": "Remote Services",
            "T1557": "Adversary-in-the-Middle",
            "T1123": "Audio Capture",
            "T1119": "Automated Exfiltration",
            "T1115": "Clipboard Data",
            "T1071": "Application Layer Protocol",
            "T1092": "Communication Through Removable Media",
            "T1001": "Data Obfuscation",
            "T1008": "Fallback Channels",
            "T1020": "Automated Exfiltration",
            "T1030": "Data Transfer Size Limits",
            "T1048": "Exfiltration Over Alternative Protocol",
            "T1041": "Exfiltration Over C2 Channel",
            "T1531": "Account Access Removal",
            "T1561": "Disk Wipe",
            "T1485": "Data Destruction",
        }
        return technique_names.get(technique_id, f"Unknown ({technique_id})")
    
    def detect_attack_chain(self, source_ip: str, 
                           attack_sequence: List[str]) -> Dict:
        """Detect multi-stage attack chains."""
        
        if len(attack_sequence) < 2:
            return {"chain_detected": False}
        
        # Common attack chains
        chains = {
            "reconnaissance_to_exploitation": [
                "PortScan", "Reconnaissance", "BruteForce"
            ],
            "initial_access_to_persistence": [
                "BruteForce", "Malware", "C2_Beacon"
            ],
            "lateral_movement_chain": [
                "LateralMovement", "Reconnaissance", "BruteForce"
            ],
            "exfiltration_chain": [
                "C2_Beacon", "Exfiltration", "LateralMovement"
            ]
        }
        
        detected_chains = []
        for chain_name, pattern in chains.items():
            if self._matches_pattern(attack_sequence, pattern):
                detected_chains.append(chain_name)
        
        result = {
            "source_ip": source_ip,
            "attack_sequence": attack_sequence,
            "chain_detected": len(detected_chains) > 0,
            "detected_chains": detected_chains,
            "severity": self._calculate_chain_severity(detected_chains)
        }
        
        if detected_chains:
            self.campaign_chains[source_ip].append(result)
        
        return result
    
    def _matches_pattern(self, sequence: List[str], pattern: List[str]) -> bool:
        """Check if attack sequence matches pattern."""
        if len(sequence) < len(pattern):
            return False
        
        # Allow some flexibility in ordering
        pattern_set = set(pattern)
        sequence_set = set(sequence)
        
        return pattern_set.issubset(sequence_set)
    
    def _calculate_chain_severity(self, chains: List[str]) -> int:
        """Calculate severity based on detected chains."""
        if not chains:
            return 0
        
        severity_map = {
            "reconnaissance_to_exploitation": 7,
            "initial_access_to_persistence": 8,
            "lateral_movement_chain": 8,
            "exfiltration_chain": 9
        }
        
        return max(severity_map.get(c, 5) for c in chains)
    
    def get_threat_actor_profile(self, source_ip: str) -> Dict:
        """Build threat actor profile from attack history."""
        
        if source_ip not in self.attack_history:
            return {"source_ip": source_ip, "profile": None}
        
        attacks = self.attack_history[source_ip]
        
        profile = {
            "source_ip": source_ip,
            "total_attacks": len(attacks),
            "attack_types": list(set(a["attack_class"] for a in attacks)),
            "tactics_used": list(set(
                t["name"] for a in attacks for t in a["tactics"]
            )),
            "severity_levels": [a["severity"] for a in attacks],
            "average_severity": sum(a["severity"] for a in attacks) / len(attacks),
            "first_seen": attacks[0]["timestamp"],
            "last_seen": attacks[-1]["timestamp"],
            "attack_frequency": len(attacks) / max(1, 
                (datetime.fromisoformat(attacks[-1]["timestamp"]) - 
                 datetime.fromisoformat(attacks[0]["timestamp"])).total_seconds() / 3600
            ),  # attacks per hour
            "campaigns": self.campaign_chains.get(source_ip, [])
        }
        
        # Classify threat actor
        profile["classification"] = self._classify_threat_actor(profile)
        
        return profile
    
    def _classify_threat_actor(self, profile: Dict) -> str:
        """Classify threat actor based on behavior."""
        
        avg_severity = profile["average_severity"]
        num_tactics = len(profile["tactics_used"])
        attack_freq = profile["attack_frequency"]
        
        if avg_severity >= 8 and num_tactics >= 5:
            return "APT (Advanced Persistent Threat)"
        elif avg_severity >= 7 and num_tactics >= 3:
            return "Organized Cybercriminal"
        elif attack_freq > 10:
            return "Automated Scanner/Botnet"
        elif avg_severity >= 6:
            return "Skilled Attacker"
        else:
            return "Opportunistic Attacker"
    
    def get_active_campaigns(self) -> List[Dict]:
        """Get list of active attack campaigns."""
        
        campaigns = []
        for source_ip, chains in self.campaign_chains.items():
            if chains:
                campaigns.append({
                    "source_ip": source_ip,
                    "num_chains": len(chains),
                    "latest_chain": chains[-1],
                    "threat_actor": self._classify_threat_actor(
                        self.get_threat_actor_profile(source_ip)
                    )
                })
        
        return sorted(campaigns, 
                     key=lambda x: x["latest_chain"]["severity"], 
                     reverse=True)
    
    def export_threat_report(self, source_ip: str = None) -> Dict:
        """Export comprehensive threat report."""
        
        if source_ip:
            return {
                "report_type": "single_source",
                "source_ip": source_ip,
                "profile": self.get_threat_actor_profile(source_ip),
                "attack_history": self.attack_history.get(source_ip, [])
            }
        else:
            return {
                "report_type": "global",
                "total_sources": len(self.attack_history),
                "active_campaigns": self.get_active_campaigns(),
                "threat_actors": {
                    ip: self._classify_threat_actor(
                        self.get_threat_actor_profile(ip)
                    )
                    for ip in self.attack_history.keys()
                }
            }
