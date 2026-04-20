"""
Advanced Threat Intelligence Module

Provides comprehensive threat analysis including:
- MITRE ATT&CK framework mapping
- Behavioral baselining and anomaly detection
- Campaign correlation and threat actor identification
- Zero-day detection through statistical analysis
- Indicators of compromise extraction
"""

from .mitre_mapper import MITREMapper
from .behavioral_baseline import BehavioralBaseline
from .campaign_correlator import CampaignCorrelator
from .threat_intelligence_engine import ThreatIntelligenceEngine

__all__ = [
    "MITREMapper",
    "BehavioralBaseline",
    "CampaignCorrelator",
    "ThreatIntelligenceEngine"
]
