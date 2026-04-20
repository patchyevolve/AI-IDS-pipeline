"""
Test auto-correction: Real-time database updates when FP/FN detected.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from validation.auto_corrector import ValidationWithAutoCorrection
from event_bus import EventBus
from database.db_engine import DatabaseEngine


def test_auto_correction():
    """Test auto-correction in action."""
    print("\n" + "=" * 70)
    print("TEST: Auto-Correction System")
    print("=" * 70)
    
    # Setup
    bus = EventBus()
    db = DatabaseEngine(bus)
    validator = ValidationWithAutoCorrection(db, bus, output_dir="validation")
    
    print("\nInitial database size:", db.memory.total_size())
    
    # Simulate events with errors
    events = [
        # Correct decisions (no correction needed)
        {
            "is_attack": True,
            "decision": "Block",
            "attack_class": "DoS/DDoS",
            "confidence": 0.95,
            "feature_vector": [0.9] * 64,
            "source": "192.168.1.100",
            "destination": "10.0.0.1",
            "port_dst": 80,
            "protocol": 6,
            "flags": 0x02,
            "rate_hz": 500.0,
            "frame_id": 1,
        },
        {
            "is_attack": False,
            "decision": "Ignore",
            "attack_class": "benign",
            "confidence": 0.05,
            "feature_vector": [0.1] * 64,
            "source": "192.168.1.50",
            "destination": "10.0.0.1",
            "port_dst": 443,
            "protocol": 6,
            "flags": 0x02,
            "rate_hz": 100.0,
            "frame_id": 2,
        },
        
        # FALSE NEGATIVE: Attack was missed (incorrectly ignored)
        {
            "is_attack": True,
            "decision": "Ignore",  # WRONG! Should have been blocked
            "attack_class": "PortScan",
            "confidence": 0.35,
            "feature_vector": [0.7] * 64,
            "source": "192.168.1.200",
            "destination": "10.0.0.1",
            "port_dst": 22,
            "protocol": 6,
            "flags": 0x02,
            "rate_hz": 1000.0,
            "frame_id": 3,
        },
        
        # FALSE POSITIVE: Benign was blocked
        {
            "is_attack": False,
            "decision": "Block",  # WRONG! Should have been ignored
            "attack_class": "benign",
            "confidence": 0.72,
            "feature_vector": [0.2] * 64,
            "source": "192.168.1.75",
            "destination": "10.0.0.1",
            "port_dst": 8080,
            "protocol": 6,
            "flags": 0x02,
            "rate_hz": 150.0,
            "frame_id": 4,
        },
        
        # Another FALSE NEGATIVE
        {
            "is_attack": True,
            "decision": "Log",  # WRONG! Should have been blocked
            "attack_class": "BruteForce",
            "confidence": 0.42,
            "feature_vector": [0.8] * 64,
            "source": "192.168.1.150",
            "destination": "10.0.0.1",
            "port_dst": 3389,
            "protocol": 6,
            "flags": 0x02,
            "rate_hz": 800.0,
            "frame_id": 5,
        },
    ]
    
    print("\nProcessing events with validation and auto-correction...\n")
    for event in events:
        validator.validate_and_correct(event)
    
    print("\nFinal database size:", db.memory.total_size())
    
    # Print summary
    validator.print_summary()
    
    # Save reports
    validator.tracker.save_report()
    print("Reports saved to validation/ directory")


if __name__ == "__main__":
    test_auto_correction()
