"""
Advanced Threat Intelligence Engine

Integrates MITRE mapping, behavioral baselining, and campaign correlation
to provide comprehensive threat analysis and intelligence.
"""
import json
from datetime import datetime
from typing import Dict, List, Optional
from .mitre_mapper import MITREMapper
from .behavioral_baseline import BehavioralBaseline
from .campaign_correlator import CampaignCorrelator


class ThreatIntelligenceEngine:
    """Main threat intelligence engine."""
    
    def __init__(self):
        self.mitre_mapper = MITREMapper()
        self.behavioral_baseline = BehavioralBaseline()
        self.campaign_correlator = CampaignCorrelator()
        
        # Intelligence cache
        self.threat_reports = {}
        self.intelligence_feeds = []
        self.indicators_of_compromise = set()
    
    def process_attack(self, attack: Dict) -> Dict:
        """Process attack through all intelligence modules."""
        
        source_ip = attack.get("source_ip")
        destination_ip = attack.get("destination_ip")
        attack_class = attack.get("attack_class")
        timestamp = attack.get("timestamp", datetime.now().timestamp())
        
        intelligence = {
            "timestamp": datetime.now().isoformat(),
            "attack": attack,
            "mitre_mapping": None,
            "behavioral_analysis": None,
            "campaign_correlation": None,
            "threat_level": "unknown",
            "recommendations": []
        }
        
        # 1. MITRE Mapping
        mitre_result = self.mitre_mapper.map_attack(
            attack_class, source_ip, destination_ip, timestamp
        )
        intelligence["mitre_mapping"] = mitre_result
        
        # 2. Behavioral Analysis
        self.behavioral_baseline.update_ip_baseline(source_ip, attack)
        self.behavioral_baseline.update_host_baseline(destination_ip, source_ip, attack)
        
        ip_anomalies = self.behavioral_baseline.detect_ip_anomalies(source_ip, attack)
        host_anomalies = self.behavioral_baseline.detect_host_anomalies(
            destination_ip, source_ip, attack
        )
        
        zero_day_indicator = self.behavioral_baseline.detect_zero_day(source_ip, attack)
        
        intelligence["behavioral_analysis"] = {
            "ip_anomalies": ip_anomalies,
            "host_anomalies": host_anomalies,
            "zero_day_indicator": zero_day_indicator,
            "ip_profile": self.behavioral_baseline.get_ip_profile(source_ip),
            "host_profile": self.behavioral_baseline.get_host_profile(destination_ip)
        }
        
        # 3. Campaign Correlation
        campaign_id = self.campaign_correlator.correlate_attack(attack)
        
        distributed_attack = self.campaign_correlator.detect_distributed_attack(
            destination_ip
        )
        multi_stage_attack = self.campaign_correlator.detect_multi_stage_attack(source_ip)
        
        threat_actor = self.campaign_correlator.identify_threat_actor(campaign_id)
        
        intelligence["campaign_correlation"] = {
            "campaign_id": campaign_id,
            "distributed_attack": distributed_attack,
            "multi_stage_attack": multi_stage_attack,
            "threat_actor": threat_actor,
            "campaign_details": self.campaign_correlator.get_campaign_details(campaign_id)
        }
        
        # 4. Threat Level Assessment
        intelligence["threat_level"] = self._assess_threat_level(intelligence)
        
        # 5. Generate Recommendations
        intelligence["recommendations"] = self._generate_recommendations(intelligence)
        
        # 6. Extract Indicators of Compromise
        self._extract_iocs(intelligence)
        
        return intelligence
    
    def _assess_threat_level(self, intelligence: Dict) -> str:
        """Assess overall threat level."""
        
        score = 0
        
        # MITRE severity
        mitre = intelligence.get("mitre_mapping", {})
        score += mitre.get("severity", 0)
        
        # Behavioral anomalies
        behavioral = intelligence.get("behavioral_analysis", {})
        if behavioral.get("zero_day_indicator"):
            score += 30
        
        anomalies = len(behavioral.get("ip_anomalies", []))
        score += anomalies * 5
        
        # Campaign characteristics
        campaign = intelligence.get("campaign_correlation", {})
        if campaign.get("distributed_attack"):
            score += 25
        if campaign.get("multi_stage_attack"):
            score += 20
        
        # Determine level
        if score >= 70:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        elif score >= 10:
            return "LOW"
        else:
            return "INFO"
    
    def _generate_recommendations(self, intelligence: Dict) -> List[str]:
        """Generate actionable recommendations."""
        
        recommendations = []
        threat_level = intelligence.get("threat_level")
        
        # Based on threat level
        if threat_level == "CRITICAL":
            recommendations.append("IMMEDIATE: Isolate affected systems")
            recommendations.append("IMMEDIATE: Activate incident response team")
            recommendations.append("IMMEDIATE: Block source IP at firewall")
        elif threat_level == "HIGH":
            recommendations.append("URGENT: Increase monitoring on affected systems")
            recommendations.append("URGENT: Prepare incident response procedures")
            recommendations.append("URGENT: Consider blocking source IP")
        elif threat_level == "MEDIUM":
            recommendations.append("Monitor for escalation")
            recommendations.append("Review access logs")
            recommendations.append("Consider rate limiting")
        
        # Based on attack type
        behavioral = intelligence.get("behavioral_analysis", {})
        if behavioral.get("zero_day_indicator"):
            recommendations.append("Investigate potential zero-day attack")
            recommendations.append("Consult threat intelligence feeds")
            recommendations.append("Consider vendor notification")
        
        campaign = intelligence.get("campaign_correlation", {})
        if campaign.get("distributed_attack"):
            recommendations.append("Implement DDoS mitigation")
            recommendations.append("Contact ISP for upstream filtering")
        
        if campaign.get("multi_stage_attack"):
            recommendations.append("Assume breach - conduct forensics")
            recommendations.append("Review all access logs from source")
            recommendations.append("Check for lateral movement")
        
        return recommendations
    
    def _extract_iocs(self, intelligence: Dict) -> None:
        """Extract indicators of compromise."""
        
        attack = intelligence.get("attack", {})
        source_ip = attack.get("source_ip")
        
        if source_ip:
            self.indicators_of_compromise.add(source_ip)
        
        # Add other IOCs as needed
        campaign = intelligence.get("campaign_correlation", {})
        if campaign.get("campaign_id"):
            self.indicators_of_compromise.add(campaign["campaign_id"])
    
    def get_threat_actor_profile(self, source_ip: str) -> Dict:
        """Get comprehensive threat actor profile."""
        
        profile = {
            "source_ip": source_ip,
            "timestamp": datetime.now().isoformat(),
            "behavioral_profile": self.behavioral_baseline.get_ip_profile(source_ip),
            "threat_actor_classification": self.mitre_mapper.get_threat_actor_profile(source_ip),
            "campaigns": self.campaign_correlator.campaigns,
            "indicators_of_compromise": list(self.indicators_of_compromise)
        }
        
        return profile
    
    def get_active_threats(self) -> Dict:
        """Get summary of active threats."""
        
        return {
            "timestamp": datetime.now().isoformat(),
            "active_campaigns": self.campaign_correlator.get_active_campaigns(),
            "threat_actors": list(self.campaign_correlator.threat_actors.values()),
            "indicators_of_compromise": list(self.indicators_of_compromise),
            "critical_threats": [
                c for c in self.campaign_correlator.get_active_campaigns()
                if c.get("severity", 0) >= 8
            ]
        }
    
    def export_intelligence_report(self, report_type: str = "full") -> Dict:
        """Export comprehensive intelligence report."""
        
        if report_type == "full":
            return {
                "report_type": "full_threat_intelligence",
                "timestamp": datetime.now().isoformat(),
                "mitre_report": self.mitre_mapper.export_threat_report(),
                "behavioral_report": self.behavioral_baseline.export_baseline_report(),
                "campaign_report": self.campaign_correlator.export_campaign_report(),
                "active_threats": self.get_active_threats(),
                "indicators_of_compromise": list(self.indicators_of_compromise)
            }
        elif report_type == "executive":
            active_threats = self.get_active_threats()
            return {
                "report_type": "executive_summary",
                "timestamp": datetime.now().isoformat(),
                "total_campaigns": len(self.campaign_correlator.campaigns),
                "active_campaigns": len(active_threats["active_campaigns"]),
                "threat_actors": len(self.campaign_correlator.threat_actors),
                "critical_threats": len(active_threats["critical_threats"]),
                "indicators_of_compromise": len(self.indicators_of_compromise),
                "top_threats": active_threats["critical_threats"][:5]
            }
        elif report_type == "ioc":
            return {
                "report_type": "indicators_of_compromise",
                "timestamp": datetime.now().isoformat(),
                "indicators": list(self.indicators_of_compromise),
                "count": len(self.indicators_of_compromise)
            }
        else:
            return {"error": f"Unknown report type: {report_type}"}
    
    def add_intelligence_feed(self, feed_data: Dict) -> None:
        """Add external threat intelligence feed."""
        
        self.intelligence_feeds.append({
            "timestamp": datetime.now().isoformat(),
            "data": feed_data
        })
    
    def correlate_with_feeds(self, source_ip: str) -> List[Dict]:
        """Correlate source IP with threat intelligence feeds."""
        
        matches = []
        
        for feed in self.intelligence_feeds:
            feed_data = feed.get("data", {})
            
            # Check if source IP is in feed
            if source_ip in feed_data.get("malicious_ips", []):
                matches.append({
                    "feed": feed_data.get("name"),
                    "source": feed_data.get("source"),
                    "confidence": feed_data.get("confidence", 0.5),
                    "description": feed_data.get("description")
                })
        
        return matches
