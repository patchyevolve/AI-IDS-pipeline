"""
Test validation metrics tracking.
Demonstrates FP/FN authentication during training.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from validation.metrics_tracker import MetricsTracker, ValidationAuthenticator
from datetime import datetime


def test_metrics_tracker():
    """Test basic metrics tracking."""
    print("\n" + "=" * 70)
    print("TEST: Metrics Tracker")
    print("=" * 70)
    
    tracker = MetricsTracker(output_dir="validation")
    
    # Simulate events
    events = [
        # True Positives (attack correctly detected)
        {"is_attack": True, "decision": "Block", "attack_class": "DoS/DDoS", "confidence": 0.95},
        {"is_attack": True, "decision": "Alert", "attack_class": "PortScan", "confidence": 0.88},
        {"is_attack": True, "decision": "Escalate", "attack_class": "BruteForce", "confidence": 0.92},
        
        # True Negatives (benign correctly allowed)
        {"is_attack": False, "decision": "Ignore", "attack_class": "benign", "confidence": 0.05},
        {"is_attack": False, "decision": "Log", "attack_class": "benign", "confidence": 0.15},
        
        # False Positives (benign incorrectly blocked)
        {"is_attack": False, "decision": "Block", "attack_class": "benign", "confidence": 0.72},
        {"is_attack": False, "decision": "Alert", "attack_class": "benign", "confidence": 0.68},
        
        # False Negatives (attack incorrectly ignored)
        {"is_attack": True, "decision": "Ignore", "attack_class": "DoS/DDoS", "confidence": 0.35},
        {"is_attack": True, "decision": "Log", "attack_class": "PortScan", "confidence": 0.42},
    ]
    
    for event in events:
        tracker.log_event(event)
    
    # Print summary
    tracker.print_summary()
    
    # Save report
    report_file = tracker.save_report()
    print(f"Report saved to: {report_file}\n")


def test_validation_authenticator():
    """Test validation authenticator."""
    print("\n" + "=" * 70)
    print("TEST: Validation Authenticator")
    print("=" * 70)
    
    tracker = MetricsTracker(output_dir="validation")
    auth = ValidationAuthenticator(tracker)
    
    # Register ground truth for events
    auth.register_ground_truth("evt_001", is_attack=True, attack_class="DoS/DDoS")
    auth.register_ground_truth("evt_002", is_attack=False, attack_class="benign")
    auth.register_ground_truth("evt_003", is_attack=True, attack_class="PortScan")
    auth.register_ground_truth("evt_004", is_attack=False, attack_class="benign")
    
    # Simulate IDS decisions
    decisions = [
        ("evt_001", {"decision": "Block", "confidence": 0.95}),      # TP
        ("evt_002", {"decision": "Ignore", "confidence": 0.08}),     # TN
        ("evt_003", {"decision": "Log", "confidence": 0.35}),        # FN (missed attack)
        ("evt_004", {"decision": "Alert", "confidence": 0.72}),      # FP (false alarm)
    ]
    
    print("\nAuthenticating decisions:")
    print("-" * 70)
    for event_id, decision in decisions:
        result = auth.authenticate_decision(event_id, decision)
        if result:
            status = "CORRECT" if result["is_correct"] else f"ERROR ({result['error_type']})"
            print(f"{event_id}: {status}")
            print(f"  Ground Truth: {'Attack' if result['ground_truth'] else 'Benign'}")
            print(f"  IDS Decision: {result['ids_decision']}")
    
    # Print summary
    tracker.print_summary()
    
    # Save report
    report_file = tracker.save_report()
    print(f"Report saved to: {report_file}\n")


if __name__ == "__main__":
    test_metrics_tracker()
    test_validation_authenticator()
