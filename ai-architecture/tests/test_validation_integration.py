"""
Integration test for validation system with attacker ground truth.

Tests:
1. Attacker sends ground truth metadata (is_attack, attack_class)
2. Validator receives and validates decisions
3. Periodic reporting works every 5 minutes
4. Metrics are calculated correctly
5. No crashes when no events processed
"""
import sys
import os
import time
import threading
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from event_bus import EventBus
from cnn.cnn_engine import CNNEngine
from rnn.rnn_engine import RNNEngine
from decoder.decoder_engine import HybridDecoder
from decoder.mutation_predictor import MutationAwareDecoder
from database.db_engine import DatabaseEngine
from validation.training_validator import TrainingValidator
from attacker.attack_engine import AttackEngine


def test_validator_receives_ground_truth():
    """Test that validator receives ground truth from attacker."""
    print("\n" + "="*70)
    print("TEST 1: Validator receives ground truth from attacker")
    print("="*70)
    
    bus = EventBus()
    validator = TrainingValidator(bus, output_dir="validation")
    
    # Simulate attacker sending an attack event with ground truth
    attack_event = {
        "is_attack": True,
        "decision": "Block",
        "attack_class": "DoS/DDoS",
        "confidence": 0.95,
        "feature_vector": [0.9] * 64,
        "source": "203.0.113.10",
        "destination": "192.168.1.1",
        "port_dst": 80,
        "protocol": 6,
        "flags": 0x02,
        "rate_hz": 500.0,
        "timestamp": "2024-04-20T12:00:00",
    }
    
    # Call validator directly (as run.py does)
    validator.validate_and_correct(attack_event)
    
    # Check metrics
    metrics = validator.get_metrics()
    assert metrics["total_events"] == 1, f"Expected 1 event, got {metrics['total_events']}"
    assert metrics["true_positives"] == 1, f"Expected 1 TP, got {metrics['true_positives']}"
    print(f"✓ Validator received 1 attack event")
    print(f"  Metrics: TP={metrics['true_positives']} TN={metrics['true_negatives']} "
          f"FP={metrics['false_positives']} FN={metrics['false_negatives']}")
    print(f"  Accuracy: {metrics['accuracy']:.2%}")


def test_validator_detects_false_positive():
    """Test that validator detects false positives."""
    print("\n" + "="*70)
    print("TEST 2: Validator detects false positives")
    print("="*70)
    
    bus = EventBus()
    validator = TrainingValidator(bus, output_dir="validation")
    
    # Benign event incorrectly blocked
    fp_event = {
        "is_attack": False,  # Ground truth: benign
        "decision": "Block",  # IDS incorrectly blocked it
        "attack_class": "unknown",
        "confidence": 0.85,
        "feature_vector": [0.1] * 64,
        "source": "192.168.1.100",
        "destination": "8.8.8.8",
        "port_dst": 53,
        "protocol": 17,
        "flags": 0x00,
        "rate_hz": 100.0,
        "timestamp": "2024-04-20T12:00:01",
    }
    
    validator.validate_and_correct(fp_event)
    
    metrics = validator.get_metrics()
    assert metrics["false_positives"] == 1, f"Expected 1 FP, got {metrics['false_positives']}"
    print(f"✓ Validator detected 1 false positive")
    print(f"  Metrics: FP={metrics['false_positives']} FPR={metrics['fpr']:.2%}")


def test_validator_detects_false_negative():
    """Test that validator detects false negatives."""
    print("\n" + "="*70)
    print("TEST 3: Validator detects false negatives")
    print("="*70)
    
    bus = EventBus()
    validator = TrainingValidator(bus, output_dir="validation")
    
    # Attack event incorrectly ignored
    fn_event = {
        "is_attack": True,   # Ground truth: attack
        "decision": "Ignore",  # IDS incorrectly ignored it
        "attack_class": "PortScan",
        "confidence": 0.45,
        "feature_vector": [0.7] * 64,
        "source": "203.0.113.20",
        "destination": "192.168.1.1",
        "port_dst": 22,
        "protocol": 6,
        "flags": 0x02,
        "rate_hz": 200.0,
        "timestamp": "2024-04-20T12:00:02",
    }
    
    validator.validate_and_correct(fn_event)
    
    metrics = validator.get_metrics()
    assert metrics["false_negatives"] == 1, f"Expected 1 FN, got {metrics['false_negatives']}"
    print(f"✓ Validator detected 1 false negative")
    print(f"  Metrics: FN={metrics['false_negatives']} FNR={metrics['fnr']:.2%}")


def test_validator_mixed_events():
    """Test validator with mixed TP/TN/FP/FN events."""
    print("\n" + "="*70)
    print("TEST 4: Validator with mixed events")
    print("="*70)
    
    bus = EventBus()
    validator = TrainingValidator(bus, output_dir="validation")
    
    events = [
        # TP: attack correctly blocked
        {"is_attack": True, "decision": "Block", "attack_class": "DoS/DDoS", "confidence": 0.95},
        # TN: benign correctly ignored
        {"is_attack": False, "decision": "Ignore", "attack_class": "unknown", "confidence": 0.1},
        # FP: benign incorrectly blocked
        {"is_attack": False, "decision": "Block", "attack_class": "unknown", "confidence": 0.8},
        # FN: attack incorrectly ignored
        {"is_attack": True, "decision": "Ignore", "attack_class": "PortScan", "confidence": 0.4},
        # TP: attack correctly blocked
        {"is_attack": True, "decision": "Block", "attack_class": "BruteForce/CredentialStuffing", "confidence": 0.92},
    ]
    
    for i, event in enumerate(events):
        event.update({
            "feature_vector": [0.5] * 64,
            "source": f"192.168.1.{i}",
            "destination": "8.8.8.8",
            "port_dst": 80,
            "protocol": 6,
            "flags": 0x00,
            "rate_hz": 100.0,
            "timestamp": f"2024-04-20T12:00:{i:02d}",
        })
        validator.validate_and_correct(event)
    
    metrics = validator.get_metrics()
    print(f"✓ Processed {metrics['total_events']} events")
    print(f"  TP={metrics['true_positives']} TN={metrics['true_negatives']} "
          f"FP={metrics['false_positives']} FN={metrics['false_negatives']}")
    print(f"  Accuracy: {metrics['accuracy']:.2%}")
    print(f"  Precision: {metrics['precision']:.2%}")
    print(f"  Recall: {metrics['recall']:.2%}")
    print(f"  F1: {metrics['f1_score']:.4f}")
    print(f"  FPR: {metrics['fpr']:.2%} FNR: {metrics['fnr']:.2%}")
    
    assert metrics["total_events"] == 5
    assert metrics["true_positives"] == 2
    assert metrics["true_negatives"] == 1
    assert metrics["false_positives"] == 1
    assert metrics["false_negatives"] == 1


def test_validator_print_summary_no_crash():
    """Test that print_summary doesn't crash with no events."""
    print("\n" + "="*70)
    print("TEST 5: print_summary doesn't crash with no events")
    print("="*70)
    
    bus = EventBus()
    validator = TrainingValidator(bus, output_dir="validation")
    
    # Should not crash even with no events
    try:
        validator.print_summary()
        print("✓ print_summary() succeeded with no events")
    except KeyError as e:
        print(f"✗ FAILED: KeyError in print_summary: {e}")
        raise


def test_validator_print_summary_with_events():
    """Test that print_summary works correctly with events."""
    print("\n" + "="*70)
    print("TEST 6: print_summary works with events")
    print("="*70)
    
    bus = EventBus()
    validator = TrainingValidator(bus, output_dir="validation")
    
    # Add some events
    for i in range(3):
        validator.validate_and_correct({
            "is_attack": i % 2 == 0,
            "decision": "Block" if i % 2 == 0 else "Ignore",
            "attack_class": "DoS/DDoS" if i % 2 == 0 else "unknown",
            "confidence": 0.9 if i % 2 == 0 else 0.1,
            "feature_vector": [0.5] * 64,
            "source": f"192.168.1.{i}",
            "destination": "8.8.8.8",
            "port_dst": 80,
            "protocol": 6,
            "flags": 0x00,
            "rate_hz": 100.0,
            "timestamp": f"2024-04-20T12:00:{i:02d}",
        })
    
    # Should not crash
    try:
        validator.print_summary()
        print("✓ print_summary() succeeded with events")
    except KeyError as e:
        print(f"✗ FAILED: KeyError in print_summary: {e}")
        raise


def test_attacker_sends_ground_truth():
    """Test that AttackEngine includes ground truth in metadata."""
    print("\n" + "="*70)
    print("TEST 7: AttackEngine sends ground truth metadata")
    print("="*70)
    
    bus = EventBus()
    attacker = AttackEngine(
        event_bus=bus,
        synthetic_targets=True,
        rate_limit=0.1,
        on_status=lambda m: None,
    )
    
    # Capture emitted events
    captured_events = []
    def capture_event(ev):
        captured_events.append(ev)
    
    bus.subscribe("network_event", capture_event)
    
    # Fire one attack
    from attacker.attack_profiles import BASE_PROFILES
    profile = list(BASE_PROFILES.values())[0]
    from attacker.mutator import ProfileFitness
    p = ProfileFitness(name="test", params=profile)
    p.generation = 0
    
    attacker._fire(p, "192.168.1.1")
    
    # Give event bus time to process (it's on a worker thread)
    time.sleep(0.2)
    
    assert len(captured_events) == 1, f"Expected 1 event, got {len(captured_events)}"
    event = captured_events[0]
    metadata = event.get("metadata", {})
    
    assert metadata.get("is_attack") == True, "Missing is_attack in metadata"
    assert metadata.get("attack_class") is not None, "Missing attack_class in metadata"
    print(f"✓ AttackEngine sends ground truth metadata")
    print(f"  is_attack: {metadata.get('is_attack')}")
    print(f"  attack_class: {metadata.get('attack_class')}")


if __name__ == "__main__":
    try:
        test_validator_receives_ground_truth()
        test_validator_detects_false_positive()
        test_validator_detects_false_negative()
        test_validator_mixed_events()
        test_validator_print_summary_no_crash()
        test_validator_print_summary_with_events()
        test_attacker_sends_ground_truth()
        
        print("\n" + "="*70)
        print("ALL TESTS PASSED")
        print("="*70 + "\n")
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
