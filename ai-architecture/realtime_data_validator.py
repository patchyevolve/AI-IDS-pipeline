#!/usr/bin/env python3
"""
Real-Time Data Validator
Verifies threats vs normal traffic in real-time to avoid FN/FP
Uses ground truth from multiple sources to validate decisions
"""
import sys
import os
import json
import time
import threading
from datetime import datetime
from collections import defaultdict, deque
import numpy as np

sys.path.insert(0, '.')

from event_bus import EventBus
from database.db_engine import DatabaseEngine, EMBEDDING_DIM


class RealTimeDataValidator:
    """
    Validates incoming traffic against known threats and benign patterns
    Prevents FN/FP by cross-checking multiple validation sources
    """
    
    def __init__(self, event_bus, db=None, output_dir="validation"):
        self.event_bus = event_bus
        self.db = db or DatabaseEngine(event_bus)
        self.output_dir = output_dir
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Validation metrics
        self.metrics = {
            "total_events": 0,
            "threats_detected": 0,
            "benign_detected": 0,
            "fn_count": 0,  # False Negatives (threat missed)
            "fp_count": 0,  # False Positives (benign blocked)
            "tp_count": 0,  # True Positives (threat detected)
            "tn_count": 0,  # True Negatives (benign allowed)
        }
        
        # Ground truth sources
        self.threat_signatures = self._load_threat_signatures()
        self.benign_patterns = self._load_benign_patterns()
        self.ip_reputation = self._load_ip_reputation()
        
        # Real-time tracking
        self.recent_events = deque(maxlen=10000)
        self.per_source_stats = defaultdict(lambda: {
            "total": 0, "threats": 0, "benign": 0, "fn": 0, "fp": 0
        })
        
        # Subscribe to events
        self.event_bus.subscribe("decoder_output", self.validate_decision)
        
        print("[validator] Real-time data validator initialized")
        print(f"  - Threat signatures: {len(self.threat_signatures)}")
        print(f"  - Benign patterns: {len(self.benign_patterns)}")
        print(f"  - IP reputation entries: {len(self.ip_reputation)}")
    
    def _load_threat_signatures(self) -> dict:
        """Load known threat signatures from database"""
        signatures = {}
        try:
            db_dir = "database"
            sig_file = os.path.join(db_dir, "ids_signatures.jsonl")
            
            if os.path.exists(sig_file):
                with open(sig_file, 'r') as f:
                    for line in f:
                        rec = json.loads(line)
                        label = rec.get("label", "unknown")
                        if label not in signatures:
                            signatures[label] = []
                        signatures[label].append({
                            "embedding": rec.get("embedding", []),
                            "score": rec.get("score", 0.0),
                            "decision": rec.get("decision", "Alert"),
                        })
        except Exception as e:
            print(f"[validator] Error loading threat signatures: {e}")
        
        return signatures
    
    def _load_benign_patterns(self) -> dict:
        """Load known benign traffic patterns"""
        patterns = {
            "dns": {
                "ports": [53],
                "protocols": [17],  # UDP
                "rate_threshold": 100,  # packets/sec
            },
            "http": {
                "ports": [80, 8080],
                "protocols": [6],  # TCP
                "rate_threshold": 1000,
            },
            "https": {
                "ports": [443, 8443],
                "protocols": [6],  # TCP
                "rate_threshold": 1000,
            },
            "ssh": {
                "ports": [22],
                "protocols": [6],  # TCP
                "rate_threshold": 100,
            },
            "ntp": {
                "ports": [123],
                "protocols": [17],  # UDP
                "rate_threshold": 50,
            },
        }
        return patterns
    
    def _load_ip_reputation(self) -> dict:
        """Load IP reputation database"""
        reputation = {
            "known_malicious": set(),
            "known_benign": set(),
            "internal_ips": set(),
        }
        
        # Add common internal IP ranges
        internal_ranges = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
        ]
        
        for ip_range in internal_ranges:
            reputation["internal_ips"].add(ip_range)
        
        return reputation
    
    def validate_decision(self, event: dict):
        """Validate a decoder decision against ground truth"""
        self.metrics["total_events"] += 1
        
        source = event.get("source", "")
        destination = event.get("destination", "")
        decision = event.get("decision", "Ignore")
        confidence = event.get("confidence", 0.0)
        attack_class = event.get("attack_class", "none")
        
        # Get ground truth
        is_threat = self._is_threat(event)
        is_benign = self._is_benign(event)
        
        # Validate decision
        validation_result = self._validate_against_ground_truth(
            decision, is_threat, is_benign, confidence, attack_class
        )
        
        # Update metrics
        self._update_metrics(validation_result, source)
        
        # Track event
        self.recent_events.append({
            "timestamp": datetime.now().isoformat(),
            "source": source,
            "destination": destination,
            "decision": decision,
            "confidence": confidence,
            "attack_class": attack_class,
            "is_threat": is_threat,
            "is_benign": is_benign,
            "validation": validation_result,
        })
        
        # Log issues
        if validation_result["status"] == "FN":
            print(f"[validator] FN: Threat missed! {source} -> {destination} "
                  f"(class={attack_class}, conf={confidence:.3f})")
        elif validation_result["status"] == "FP":
            print(f"[validator] FP: False alarm! {source} -> {destination} "
                  f"(decision={decision}, conf={confidence:.3f})")
    
    def _is_threat(self, event: dict) -> bool:
        """Determine if event is a threat using multiple sources"""
        source = event.get("source", "")
        destination = event.get("destination", "")
        attack_class = event.get("attack_class", "none")
        confidence = event.get("confidence", 0.0)
        
        # Check 1: Attack class indicates threat
        if attack_class and attack_class != "none":
            return True
        
        # Check 2: High confidence score
        if confidence >= 0.75:
            return True
        
        # Check 3: Known malicious IP
        if source in self._load_ip_reputation()["known_malicious"]:
            return True
        
        # Check 4: Signature match
        embedding = event.get("feature_vector", [])
        if embedding and self._matches_threat_signature(embedding, attack_class):
            return True
        
        return False
    
    def _is_benign(self, event: dict) -> bool:
        """Determine if event is benign using multiple sources"""
        port_dst = event.get("port_dst", 0)
        protocol = event.get("protocol", 0)
        rate_hz = event.get("rate_hz", 0)
        entropy = event.get("entropy", 0)
        attack_class = event.get("attack_class", "none")
        confidence = event.get("confidence", 0.0)
        
        # Check 1: Explicitly marked as benign
        if attack_class == "none" and confidence < 0.25:
            return True
        
        # Check 2: Matches known benign pattern
        for pattern_name, pattern in self.benign_patterns.items():
            if (port_dst in pattern["ports"] and 
                protocol in pattern["protocols"] and
                rate_hz <= pattern["rate_threshold"]):
                return True
        
        # Check 3: Low entropy (structured data)
        if entropy < 2.0:
            return True
        
        # Check 4: Known benign IP
        source = event.get("source", "")
        if source in self._load_ip_reputation()["known_benign"]:
            return True
        
        return False
    
    def _matches_threat_signature(self, embedding: list, attack_class: str) -> bool:
        """Check if embedding matches known threat signatures"""
        if not embedding or attack_class not in self.threat_signatures:
            return False
        
        embedding = np.array(embedding)
        
        # Compare against signatures of same class
        for sig in self.threat_signatures[attack_class][:10]:  # Check top 10
            sig_emb = np.array(sig["embedding"])
            
            # Cosine similarity
            similarity = np.dot(embedding, sig_emb) / (
                np.linalg.norm(embedding) * np.linalg.norm(sig_emb) + 1e-9
            )
            
            if similarity > 0.85:  # High similarity threshold
                return True
        
        return False
    
    def _validate_against_ground_truth(self, decision: str, is_threat: bool, 
                                       is_benign: bool, confidence: float, 
                                       attack_class: str) -> dict:
        """Validate decision against ground truth"""
        
        # Determine ground truth
        if is_threat:
            ground_truth = "threat"
        elif is_benign:
            ground_truth = "benign"
        else:
            ground_truth = "unknown"
        
        # Determine decision category
        if decision in ("Block", "Escalate"):
            decision_category = "threat"
        elif decision in ("Ignore", "Log"):
            decision_category = "benign"
        else:
            decision_category = "unknown"
        
        # Validate
        if ground_truth == "threat":
            if decision_category == "threat":
                status = "TP"  # True Positive
                confidence_ok = confidence >= 0.60
            else:
                status = "FN"  # False Negative
                confidence_ok = False
        elif ground_truth == "benign":
            if decision_category == "benign":
                status = "TN"  # True Negative
                confidence_ok = confidence < 0.50
            else:
                status = "FP"  # False Positive
                confidence_ok = False
        else:
            status = "UNKNOWN"
            confidence_ok = None
        
        return {
            "status": status,
            "ground_truth": ground_truth,
            "decision_category": decision_category,
            "confidence_ok": confidence_ok,
            "attack_class": attack_class,
        }
    
    def _update_metrics(self, validation: dict, source: str):
        """Update validation metrics"""
        status = validation["status"]
        
        if status == "TP":
            self.metrics["tp_count"] += 1
            self.metrics["threats_detected"] += 1
        elif status == "TN":
            self.metrics["tn_count"] += 1
            self.metrics["benign_detected"] += 1
        elif status == "FN":
            self.metrics["fn_count"] += 1
            self.metrics["threats_detected"] += 1
        elif status == "FP":
            self.metrics["fp_count"] += 1
            self.metrics["benign_detected"] += 1
        
        # Update per-source stats
        self.per_source_stats[source]["total"] += 1
        if validation["ground_truth"] == "threat":
            self.per_source_stats[source]["threats"] += 1
            if status == "FN":
                self.per_source_stats[source]["fn"] += 1
        elif validation["ground_truth"] == "benign":
            self.per_source_stats[source]["benign"] += 1
            if status == "FP":
                self.per_source_stats[source]["fp"] += 1
    
    def get_accuracy_metrics(self) -> dict:
        """Calculate accuracy metrics"""
        tp = self.metrics["tp_count"]
        tn = self.metrics["tn_count"]
        fp = self.metrics["fp_count"]
        fn = self.metrics["fn_count"]
        
        total = tp + tn + fp + fn
        
        if total == 0:
            return {
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0,
                "false_positive_rate": 0.0,
                "false_negative_rate": 0.0,
            }
        
        accuracy = (tp + tn) / total if total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        
        return {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "total": total,
        }
    
    def get_report(self) -> dict:
        """Generate validation report"""
        accuracy = self.get_accuracy_metrics()
        
        # Top sources by threat count
        top_sources = sorted(
            self.per_source_stats.items(),
            key=lambda x: x[1]["threats"],
            reverse=True
        )[:10]
        
        # Top sources by FN count
        top_fn_sources = sorted(
            self.per_source_stats.items(),
            key=lambda x: x[1]["fn"],
            reverse=True
        )[:5]
        
        # Top sources by FP count
        top_fp_sources = sorted(
            self.per_source_stats.items(),
            key=lambda x: x[1]["fp"],
            reverse=True
        )[:5]
        
        return {
            "timestamp": datetime.now().isoformat(),
            "total_events": self.metrics["total_events"],
            "accuracy_metrics": accuracy,
            "top_threat_sources": [
                {
                    "source": src,
                    "threats": stats["threats"],
                    "benign": stats["benign"],
                    "fn": stats["fn"],
                    "fp": stats["fp"],
                }
                for src, stats in top_sources
            ],
            "top_fn_sources": [
                {
                    "source": src,
                    "fn_count": stats["fn"],
                    "total": stats["total"],
                }
                for src, stats in top_fn_sources
            ],
            "top_fp_sources": [
                {
                    "source": src,
                    "fp_count": stats["fp"],
                    "total": stats["total"],
                }
                for src, stats in top_fp_sources
            ],
        }
    
    def print_summary(self):
        """Print validation summary"""
        report = self.get_report()
        accuracy = report["accuracy_metrics"]
        
        print("\n" + "="*80)
        print("REAL-TIME DATA VALIDATION SUMMARY")
        print("="*80)
        print(f"\nTotal Events: {report['total_events']}")
        print(f"\nAccuracy Metrics:")
        print(f"  - Accuracy:  {accuracy['accuracy']:.4f}")
        print(f"  - Precision: {accuracy['precision']:.4f}")
        print(f"  - Recall:    {accuracy['recall']:.4f}")
        print(f"  - F1 Score:  {accuracy['f1_score']:.4f}")
        print(f"\nError Rates:")
        print(f"  - False Positive Rate: {accuracy['false_positive_rate']:.4f}")
        print(f"  - False Negative Rate: {accuracy['false_negative_rate']:.4f}")
        print(f"\nConfusion Matrix:")
        print(f"  - TP (True Positive):   {accuracy['tp']}")
        print(f"  - TN (True Negative):   {accuracy['tn']}")
        print(f"  - FP (False Positive):  {accuracy['fp']}")
        print(f"  - FN (False Negative):  {accuracy['fn']}")
        
        if report["top_threat_sources"]:
            print(f"\nTop Threat Sources:")
            for item in report["top_threat_sources"][:5]:
                print(f"  - {item['source']}: {item['threats']} threats, "
                      f"{item['fn']} FN, {item['fp']} FP")
        
        if report["top_fn_sources"]:
            print(f"\nTop False Negative Sources (Threats Missed):")
            for item in report["top_fn_sources"]:
                print(f"  - {item['source']}: {item['fn_count']} missed threats")
        
        if report["top_fp_sources"]:
            print(f"\nTop False Positive Sources (False Alarms):")
            for item in report["top_fp_sources"]:
                print(f"  - {item['source']}: {item['fp_count']} false alarms")
        
        print("\n" + "="*80 + "\n")
    
    def save_report(self):
        """Save validation report to file"""
        report = self.get_report()
        
        report_file = os.path.join(self.output_dir, "validation_report.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[validator] Report saved to {report_file}")


if __name__ == "__main__":
    # Test the validator
    bus = EventBus()
    db = DatabaseEngine(bus)
    validator = RealTimeDataValidator(bus, db=db)
    
    # Simulate some events
    print("\n[test] Simulating validation events...\n")
    
    # Test 1: True Positive (threat detected correctly)
    tp_event = {
        "source": "192.168.1.100",
        "destination": "10.0.0.50",
        "decision": "Block",
        "confidence": 0.85,
        "attack_class": "DoS/DDoS",
        "feature_vector": [0.8] * 64,
        "port_dst": 80,
        "protocol": 6,
        "rate_hz": 5000,
        "entropy": 7.2,
    }
    validator.validate_decision(tp_event)
    
    # Test 2: True Negative (benign allowed correctly)
    tn_event = {
        "source": "192.168.1.50",
        "destination": "8.8.8.8",
        "decision": "Ignore",
        "confidence": 0.15,
        "attack_class": "none",
        "feature_vector": [0.1] * 64,
        "port_dst": 53,
        "protocol": 17,
        "rate_hz": 10,
        "entropy": 1.5,
    }
    validator.validate_decision(tn_event)
    
    # Test 3: False Negative (threat missed)
    fn_event = {
        "source": "203.0.113.50",
        "destination": "192.168.1.10",
        "decision": "Ignore",
        "confidence": 0.20,
        "attack_class": "BruteForce",
        "feature_vector": [0.7] * 64,
        "port_dst": 22,
        "protocol": 6,
        "rate_hz": 500,
        "entropy": 6.5,
    }
    validator.validate_decision(fn_event)
    
    # Test 4: False Positive (benign blocked)
    fp_event = {
        "source": "192.168.1.75",
        "destination": "1.1.1.1",
        "decision": "Block",
        "confidence": 0.70,
        "attack_class": "UnknownHighSeverity",
        "feature_vector": [0.2] * 64,
        "port_dst": 443,
        "protocol": 6,
        "rate_hz": 50,
        "entropy": 2.0,
    }
    validator.validate_decision(fp_event)
    
    # Print summary
    validator.print_summary()
    validator.save_report()
