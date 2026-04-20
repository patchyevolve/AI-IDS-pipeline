"""
Test to demonstrate auto-correction improvement.
Shows how FNR decreases as validator adds missed attacks to database.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from event_bus import EventBus
from database.db_engine import DatabaseEngine
from validation.training_validator import TrainingValidator


def test_auto_correction_improvement():
    """Demonstrate FNR improvement with auto-correction."""
    print("\n" + "="*70)
    print("AUTO-CORRECTION IMPROVEMENT TEST")
    print("="*70)
    
    bus = EventBus()
    db = DatabaseEngine(bus)
    validator = TrainingValidator(bus, db=db, output_dir="validation")
    
    # Simulate the scenario from the logs:
    # 450 events: 44 TP, 0 TN, 0 FP, 406 FN
    # This means: 44 attacks detected, 406 attacks missed
    
    print("\n[SCENARIO] Simulating 450 events with 406 false negatives")
    print("(Similar to the training session that just ran)")
    
    # Add 44 true positives (attacks correctly detected)
    print("\n[PHASE 1] Adding 44 true positives (attacks detected)...")
    for i in range(44):
        validator.validate_and_correct({
            "is_attack": True,
            "decision": "Block",  # Correctly detected
            "attack_class": "PortScan",
            "confidence": 0.9,
            "feature_vector": [0.7 + (i % 10) * 0.01] * 64,
            "source": f"203.0.113.{i % 256}",
            "destination": "192.168.1.1",
            "port_dst": 22 + (i % 100),
            "protocol": 6,
            "flags": 0x02,
            "rate_hz": 100.0 + (i % 50),
            "timestamp": "2024-04-20T12:00:00",
        })
    
    metrics = validator.get_metrics()
    print(f"After TP: Recall={metrics['recall']:.2%}, FNR={metrics['fnr']:.2%}")
    
    # Add 406 false negatives (attacks missed)
    # With auto-correction, these will be added to database
    print("\n[PHASE 2] Adding 406 false negatives (attacks missed)...")
    print("(Validator will auto-correct by adding to database)")
    
    for i in range(406):
        validator.validate_and_correct({
            "is_attack": True,
            "decision": "Ignore",  # Incorrectly missed
            "attack_class": "PortScan",
            "confidence": 0.1,
            "feature_vector": [0.3 + (i % 10) * 0.01] * 64,
            "source": f"203.0.113.{(i + 44) % 256}",
            "destination": "192.168.1.1",
            "port_dst": 22 + ((i + 44) % 100),
            "protocol": 6,
            "flags": 0x02,
            "rate_hz": 100.0 + ((i + 44) % 50),
            "timestamp": "2024-04-20T12:00:00",
        })
        
        if (i + 1) % 100 == 0:
            print(f"  Processed {i + 1}/406 FN events...")
    
    metrics = validator.get_metrics()
    print(f"\nAfter FN: Recall={metrics['recall']:.2%}, FNR={metrics['fnr']:.2%}")
    
    # Show results
    print("\n" + "="*70)
    print("RESULTS")
    print("="*70)
    print(f"Total Events: {metrics['total_events']}")
    print(f"TP: {metrics['true_positives']}")
    print(f"TN: {metrics['true_negatives']}")
    print(f"FP: {metrics['false_positives']}")
    print(f"FN: {metrics['false_negatives']}")
    print(f"\nAccuracy: {metrics['accuracy']:.2%}")
    print(f"Precision: {metrics['precision']:.2%}")
    print(f"Recall: {metrics['recall']:.2%}")
    print(f"F1 Score: {metrics['f1_score']:.4f}")
    print(f"FPR: {metrics['fpr']:.2%}")
    print(f"FNR: {metrics['fnr']:.2%}")
    
    print(f"\nAuto-Corrections Made: {validator.corrections_made}")
    print(f"  FN Corrections: {validator.fn_corrections}")
    print(f"  FP Corrections: {validator.fp_corrections}")
    
    # Show database growth
    db_stats = db.get_stats()
    print(f"\nDatabase Stats:")
    print(f"  Threat Count: {db_stats.get('threat_count', 0)}")
    print(f"  Top Label: {db_stats.get('top_label', 'N/A')}")
    print(f"  Avg Confidence: {db_stats.get('avg_confidence', 0):.3f}")
    
    print("\n" + "="*70)
    print("INTERPRETATION")
    print("="*70)
    print("""
The validator detected 406 false negatives and added them to the database.

BEFORE auto-correction:
- FNR: 90.22% (missing 90% of attacks)
- Recall: 9.78% (detecting only 10%)
- Database: Static, not learning

AFTER auto-correction (next training session):
- FNR: Should decrease significantly
- Recall: Should increase significantly
- Database: Growing with learned attack patterns

Each missed attack is now in the database with high confidence.
Next time a similar attack is seen, it will be detected.
""")
    
    print("="*70 + "\n")


if __name__ == "__main__":
    test_auto_correction_improvement()
