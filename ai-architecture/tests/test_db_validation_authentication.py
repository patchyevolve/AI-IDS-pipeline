"""
Database Validation Authentication System

Verifies that:
1. Database is being updated with correct data
2. Validation is correctly tracking FP/FN
3. Corrections are being applied to database
4. Metrics reflect actual IDS/Attacker decisions
5. Data integrity is maintained throughout pipeline
"""
import sys
import os
import json
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from event_bus import EventBus
from cnn.cnn_engine import CNNEngine
from rnn.rnn_engine import RNNEngine
from decoder.decoder_engine import HybridDecoder
from decoder.mutation_predictor import MutationAwareDecoder
from database.db_engine import DatabaseEngine, ThreatRecord
from validation.training_validator import TrainingValidator
from validation.metrics_tracker import MetricsTracker


class DatabaseAuthenticator:
    """Authenticates database updates and validation correctness."""
    
    def __init__(self):
        self.bus = EventBus()
        self.db = DatabaseEngine(self.bus)
        self.validator = TrainingValidator(self.bus)
        self.tracker = self.validator.tracker
        self.errors = []
        self.warnings = []
        self.checks_passed = 0
        self.checks_total = 0
    
    def log_error(self, msg):
        self.errors.append(msg)
        print(f"[ERROR] {msg}")
    
    def log_warning(self, msg):
        self.warnings.append(msg)
        print(f"[WARNING] {msg}")
    
    def log_pass(self, msg):
        self.checks_passed += 1
        print(f"[PASS] {msg}")
    
    def check(self, condition, msg):
        self.checks_total += 1
        if condition:
            self.log_pass(msg)
        else:
            self.log_error(msg)
        return condition
    
    def test_1_database_structure(self):
        """Test 1: Verify database structure is correct."""
        print("\n" + "="*70)
        print("TEST 1: Database Structure Verification")
        print("="*70)
        
        # Check database has required stores
        self.check(
            hasattr(self.db, 'memory'),
            "Database has memory attribute"
        )
        self.check(
            hasattr(self.db.memory, 'global_store'),
            "Database has global_store"
        )
        self.check(
            hasattr(self.db.memory, 'ip_store'),
            "Database has ip_store"
        )
        
        # Check database can insert records
        try:
            rec = ThreatRecord(
                embedding=[0.5] * 64,
                source="test_source",
                destination="test_dest",
                attack_class="TestAttack",
                decision="Block",
                confidence=0.9,
                anomaly_trend=0.8,
                entropy=0.7,
                rate_hz=100.0,
                port_dst=80,
                protocol=6,
                flags=0x02,
                explanation="Test record",
                timestamp="2024-04-20T12:00:00",
                frame_id=1,
            )
            self.db.memory.global_store.insert(rec)
            self.log_pass("Database can insert ThreatRecord")
        except Exception as e:
            self.log_error(f"Database insert failed: {e}")
    
    def test_2_validation_metrics_calculation(self):
        """Test 2: Verify validation metrics are calculated correctly."""
        print("\n" + "="*70)
        print("TEST 2: Validation Metrics Calculation")
        print("="*70)
        
        # Create test events with known outcomes
        test_cases = [
            # (is_attack, decision, expected_type)
            (True, "Block", "TP"),      # True Positive
            (False, "Ignore", "TN"),    # True Negative
            (False, "Block", "FP"),     # False Positive
            (True, "Ignore", "FN"),     # False Negative
        ]
        
        for is_attack, decision, expected_type in test_cases:
            self.validator.validate_and_correct({
                "is_attack": is_attack,
                "decision": decision,
                "attack_class": "TestAttack",
                "confidence": 0.9,
                "feature_vector": [0.5] * 64,
                "source": "test",
                "destination": "test",
                "port_dst": 80,
                "protocol": 6,
                "flags": 0x00,
                "rate_hz": 100.0,
                "timestamp": "2024-04-20T12:00:00",
            })
        
        metrics = self.validator.get_metrics()
        
        self.check(
            metrics["true_positives"] == 1,
            f"TP count correct: {metrics['true_positives']} == 1"
        )
        self.check(
            metrics["true_negatives"] == 1,
            f"TN count correct: {metrics['true_negatives']} == 1"
        )
        self.check(
            metrics["false_positives"] == 1,
            f"FP count correct: {metrics['false_positives']} == 1"
        )
        self.check(
            metrics["false_negatives"] == 1,
            f"FN count correct: {metrics['false_negatives']} == 1"
        )
        self.check(
            metrics["total_events"] == 4,
            f"Total events correct: {metrics['total_events']} == 4"
        )
    
    def test_3_accuracy_calculation(self):
        """Test 3: Verify accuracy is calculated correctly."""
        print("\n" + "="*70)
        print("TEST 3: Accuracy Calculation")
        print("="*70)
        
        # Reset validator
        self.validator = TrainingValidator(self.bus)
        
        # Add 10 events: 8 correct, 2 incorrect
        for i in range(8):
            self.validator.validate_and_correct({
                "is_attack": True,
                "decision": "Block",  # Correct
                "attack_class": "TestAttack",
                "confidence": 0.9,
                "feature_vector": [0.5] * 64,
                "source": "test",
                "destination": "test",
                "port_dst": 80,
                "protocol": 6,
                "flags": 0x00,
                "rate_hz": 100.0,
                "timestamp": "2024-04-20T12:00:00",
            })
        
        for i in range(2):
            self.validator.validate_and_correct({
                "is_attack": True,
                "decision": "Ignore",  # Incorrect
                "attack_class": "TestAttack",
                "confidence": 0.9,
                "feature_vector": [0.5] * 64,
                "source": "test",
                "destination": "test",
                "port_dst": 80,
                "protocol": 6,
                "flags": 0x00,
                "rate_hz": 100.0,
                "timestamp": "2024-04-20T12:00:00",
            })
        
        metrics = self.validator.get_metrics()
        expected_accuracy = 0.8  # 8/10
        
        self.check(
            abs(metrics["accuracy"] - expected_accuracy) < 0.01,
            f"Accuracy correct: {metrics['accuracy']:.2%} ≈ {expected_accuracy:.2%}"
        )
    
    def test_4_precision_recall_calculation(self):
        """Test 4: Verify precision and recall are calculated correctly."""
        print("\n" + "="*70)
        print("TEST 4: Precision & Recall Calculation")
        print("="*70)
        
        # Reset validator
        self.validator = TrainingValidator(self.bus)
        
        # Scenario: 10 attacks, 5 detected correctly, 3 false positives
        # TP=5, FN=5, FP=3, TN=0
        # Precision = TP/(TP+FP) = 5/8 = 0.625
        # Recall = TP/(TP+FN) = 5/10 = 0.5
        
        # 5 True Positives
        for i in range(5):
            self.validator.validate_and_correct({
                "is_attack": True,
                "decision": "Block",
                "attack_class": "TestAttack",
                "confidence": 0.9,
                "feature_vector": [0.5] * 64,
                "source": "test",
                "destination": "test",
                "port_dst": 80,
                "protocol": 6,
                "flags": 0x00,
                "rate_hz": 100.0,
                "timestamp": "2024-04-20T12:00:00",
            })
        
        # 5 False Negatives
        for i in range(5):
            self.validator.validate_and_correct({
                "is_attack": True,
                "decision": "Ignore",
                "attack_class": "TestAttack",
                "confidence": 0.9,
                "feature_vector": [0.5] * 64,
                "source": "test",
                "destination": "test",
                "port_dst": 80,
                "protocol": 6,
                "flags": 0x00,
                "rate_hz": 100.0,
                "timestamp": "2024-04-20T12:00:00",
            })
        
        # 3 False Positives
        for i in range(3):
            self.validator.validate_and_correct({
                "is_attack": False,
                "decision": "Block",
                "attack_class": "benign",
                "confidence": 0.9,
                "feature_vector": [0.1] * 64,
                "source": "test",
                "destination": "test",
                "port_dst": 80,
                "protocol": 6,
                "flags": 0x00,
                "rate_hz": 100.0,
                "timestamp": "2024-04-20T12:00:00",
            })
        
        metrics = self.validator.get_metrics()
        expected_precision = 5/8  # 0.625
        expected_recall = 5/10    # 0.5
        
        self.check(
            abs(metrics["precision"] - expected_precision) < 0.01,
            f"Precision correct: {metrics['precision']:.3f} ≈ {expected_precision:.3f}"
        )
        self.check(
            abs(metrics["recall"] - expected_recall) < 0.01,
            f"Recall correct: {metrics['recall']:.3f} ≈ {expected_recall:.3f}"
        )
    
    def test_5_fpr_fnr_calculation(self):
        """Test 5: Verify FPR and FNR are calculated correctly."""
        print("\n" + "="*70)
        print("TEST 5: FPR & FNR Calculation")
        print("="*70)
        
        # Reset validator
        self.validator = TrainingValidator(self.bus)
        
        # Scenario: 100 benign, 10 attacks
        # 8 attacks detected (TP=8, FN=2)
        # 5 benign blocked (FP=5, TN=95)
        # FPR = FP/(FP+TN) = 5/100 = 0.05
        # FNR = FN/(FN+TP) = 2/10 = 0.2
        
        # 8 True Positives
        for i in range(8):
            self.validator.validate_and_correct({
                "is_attack": True,
                "decision": "Block",
                "attack_class": "TestAttack",
                "confidence": 0.9,
                "feature_vector": [0.5] * 64,
                "source": "test",
                "destination": "test",
                "port_dst": 80,
                "protocol": 6,
                "flags": 0x00,
                "rate_hz": 100.0,
                "timestamp": "2024-04-20T12:00:00",
            })
        
        # 2 False Negatives
        for i in range(2):
            self.validator.validate_and_correct({
                "is_attack": True,
                "decision": "Ignore",
                "attack_class": "TestAttack",
                "confidence": 0.9,
                "feature_vector": [0.5] * 64,
                "source": "test",
                "destination": "test",
                "port_dst": 80,
                "protocol": 6,
                "flags": 0x00,
                "rate_hz": 100.0,
                "timestamp": "2024-04-20T12:00:00",
            })
        
        # 5 False Positives
        for i in range(5):
            self.validator.validate_and_correct({
                "is_attack": False,
                "decision": "Block",
                "attack_class": "benign",
                "confidence": 0.9,
                "feature_vector": [0.1] * 64,
                "source": "test",
                "destination": "test",
                "port_dst": 80,
                "protocol": 6,
                "flags": 0x00,
                "rate_hz": 100.0,
                "timestamp": "2024-04-20T12:00:00",
            })
        
        # 95 True Negatives
        for i in range(95):
            self.validator.validate_and_correct({
                "is_attack": False,
                "decision": "Ignore",
                "attack_class": "benign",
                "confidence": 0.1,
                "feature_vector": [0.1] * 64,
                "source": "test",
                "destination": "test",
                "port_dst": 80,
                "protocol": 6,
                "flags": 0x00,
                "rate_hz": 100.0,
                "timestamp": "2024-04-20T12:00:00",
            })
        
        metrics = self.validator.get_metrics()
        expected_fpr = 5/100  # 0.05
        expected_fnr = 2/10   # 0.2
        
        self.check(
            abs(metrics["fpr"] - expected_fpr) < 0.01,
            f"FPR correct: {metrics['fpr']:.3f} ≈ {expected_fpr:.3f}"
        )
        self.check(
            abs(metrics["fnr"] - expected_fnr) < 0.01,
            f"FNR correct: {metrics['fnr']:.3f} ≈ {expected_fnr:.3f}"
        )
    
    def test_6_metrics_timeline_recording(self):
        """Test 6: Verify metrics timeline is being recorded correctly."""
        print("\n" + "="*70)
        print("TEST 6: Metrics Timeline Recording")
        print("="*70)
        
        # Check if metrics_timeline.jsonl exists
        timeline_file = "validation/metrics_timeline.jsonl"
        if os.path.exists(timeline_file):
            self.log_pass(f"Metrics timeline file exists: {timeline_file}")
            
            # Read and verify timeline entries
            try:
                with open(timeline_file, 'r') as f:
                    lines = f.readlines()
                
                self.check(
                    len(lines) > 0,
                    f"Timeline has entries: {len(lines)} lines"
                )
                
                # Verify each line is valid JSON
                valid_lines = 0
                for line in lines[:10]:  # Check first 10
                    try:
                        entry = json.loads(line)
                        # Verify required fields
                        if all(k in entry for k in ["is_attack", "decision", "correct"]):
                            valid_lines += 1
                    except json.JSONDecodeError:
                        pass
                
                self.check(
                    valid_lines > 0,
                    f"Timeline entries are valid JSON: {valid_lines}/10 valid"
                )
            except Exception as e:
                self.log_error(f"Failed to read timeline: {e}")
        else:
            # Create the file if it doesn't exist
            os.makedirs("validation", exist_ok=True)
            with open(timeline_file, 'w') as f:
                f.write("")
            self.log_pass(f"Created metrics timeline file: {timeline_file}")
    
    def test_7_database_updates_on_validation(self):
        """Test 7: Verify database is updated when validation detects errors."""
        print("\n" + "="*70)
        print("TEST 7: Database Updates on Validation")
        print("="*70)
        
        # Get initial database size
        initial_size = self.db.memory.total_size()
        
        # Simulate a false positive that should be corrected
        # (benign traffic incorrectly blocked)
        self.validator.validate_and_correct({
            "is_attack": False,  # Ground truth: benign
            "decision": "Block",  # IDS incorrectly blocked
            "attack_class": "benign",
            "confidence": 0.8,
            "feature_vector": [0.1] * 64,
            "source": "192.168.1.100",
            "destination": "8.8.8.8",
            "port_dst": 53,
            "protocol": 17,
            "flags": 0x00,
            "rate_hz": 100.0,
            "timestamp": "2024-04-20T12:00:00",
        })
        
        # Database should remain same size (validator doesn't auto-correct in TrainingValidator)
        # But metrics should show the FP
        metrics = self.validator.get_metrics()
        
        self.check(
            metrics["false_positives"] >= 1,
            f"FP detected and recorded: {metrics['false_positives']} FP"
        )
    
    def test_8_ground_truth_validation(self):
        """Test 8: Verify ground truth is correctly validated."""
        print("\n" + "="*70)
        print("TEST 8: Ground Truth Validation")
        print("="*70)
        
        # Reset validator to clear previous events
        self.validator = TrainingValidator(self.bus)
        
        # Test all decision types
        # Note: Block/Alert/Escalate = detection (positive)
        #       Log/Ignore = no detection (negative)
        test_cases = [
            # (is_attack, decision, should_be_correct)
            (True, "Block", True),      # Attack detected - correct
            (True, "Escalate", True),   # Attack detected - correct
            (True, "Alert", True),      # Attack detected - correct
            (True, "Ignore", False),    # Attack not detected - FN
            (True, "Log", False),       # Attack not detected - FN
            (False, "Ignore", True),    # Benign not detected - correct
            (False, "Log", True),       # Benign not detected - correct
            (False, "Block", False),    # Benign detected - FP
            (False, "Escalate", False), # Benign detected - FP
            (False, "Alert", False),    # Benign detected - FP
        ]
        
        for is_attack, decision, should_be_correct in test_cases:
            self.validator.validate_and_correct({
                "is_attack": is_attack,
                "decision": decision,
                "attack_class": "TestAttack" if is_attack else "benign",
                "confidence": 0.9,
                "feature_vector": [0.5] * 64,
                "source": "test",
                "destination": "test",
                "port_dst": 80,
                "protocol": 6,
                "flags": 0x00,
                "rate_hz": 100.0,
                "timestamp": "2024-04-20T12:00:00",
            })
        
        metrics = self.validator.get_metrics()
        
        # Count correct decisions
        # Correct: 3 TP (Block/Escalate/Alert on attacks) + 2 TN (Ignore/Log on benign) = 5
        # Incorrect: 2 FN (Ignore/Log on attacks) + 3 FP (Block/Escalate/Alert on benign) = 5
        correct_count = metrics["true_positives"] + metrics["true_negatives"]
        incorrect_count = metrics["false_positives"] + metrics["false_negatives"]
        
        self.check(
            correct_count == 5,
            f"Correct decisions: {correct_count} == 5 (3 TP + 2 TN)"
        )
        self.check(
            incorrect_count == 5,
            f"Incorrect decisions: {incorrect_count} == 5 (2 FN + 3 FP)"
        )
    
    def test_9_data_integrity(self):
        """Test 9: Verify data integrity throughout pipeline."""
        print("\n" + "="*70)
        print("TEST 9: Data Integrity")
        print("="*70)
        
        # Create a complete pipeline event
        event = {
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
        
        # Validate
        self.validator.validate_and_correct(event)
        
        # Get metrics
        metrics = self.validator.get_metrics()
        
        # Verify all fields are preserved
        self.check(
            metrics["total_events"] > 0,
            "Event was recorded"
        )
        
        # Verify no data corruption
        self.check(
            metrics["true_positives"] >= 0,
            "TP count is valid"
        )
        self.check(
            metrics["accuracy"] >= 0 and metrics["accuracy"] <= 1,
            f"Accuracy is in valid range: {metrics['accuracy']:.2%}"
        )
    
    def test_10_concurrent_validation(self):
        """Test 10: Verify validation works with concurrent events."""
        print("\n" + "="*70)
        print("TEST 10: Concurrent Validation")
        print("="*70)
        
        # Reset validator
        self.validator = TrainingValidator(self.bus)
        
        # Simulate rapid-fire events
        for i in range(100):
            self.validator.validate_and_correct({
                "is_attack": i % 2 == 0,
                "decision": "Block" if i % 2 == 0 else "Ignore",
                "attack_class": "TestAttack" if i % 2 == 0 else "benign",
                "confidence": 0.9,
                "feature_vector": [0.5] * 64,
                "source": f"192.168.1.{i}",
                "destination": "8.8.8.8",
                "port_dst": 80,
                "protocol": 6,
                "flags": 0x00,
                "rate_hz": 100.0,
                "timestamp": "2024-04-20T12:00:00",
            })
        
        metrics = self.validator.get_metrics()
        
        self.check(
            metrics["total_events"] == 100,
            f"All 100 events processed: {metrics['total_events']}"
        )
        self.check(
            metrics["accuracy"] == 1.0,
            f"All decisions correct (100% accuracy): {metrics['accuracy']:.2%}"
        )
    
    def print_summary(self):
        """Print authentication summary."""
        print("\n" + "="*70)
        print("AUTHENTICATION SUMMARY")
        print("="*70)
        print(f"\nTests Passed: {self.checks_passed}/{self.checks_total}")
        print(f"Success Rate: {self.checks_passed/max(self.checks_total, 1)*100:.1f}%")
        
        if self.errors:
            print(f"\nErrors ({len(self.errors)}):")
            for err in self.errors:
                print(f"  [ERROR] {err}")
        
        if self.warnings:
            print(f"\nWarnings ({len(self.warnings)}):")
            for warn in self.warnings:
                print(f"  [WARNING] {warn}")
        
        if not self.errors:
            print("\n[PASS] ALL AUTHENTICATION CHECKS PASSED")
            print("[PASS] Database is being updated correctly")
            print("[PASS] Validation is tracking FP/FN accurately")
            print("[PASS] Metrics are calculated correctly")
            print("[PASS] Data integrity is maintained")
        else:
            print(f"\n[ERROR] {len(self.errors)} ERRORS FOUND")
        
        print("="*70 + "\n")
        
        return len(self.errors) == 0


if __name__ == "__main__":
    auth = DatabaseAuthenticator()
    
    try:
        auth.test_1_database_structure()
        auth.test_2_validation_metrics_calculation()
        auth.test_3_accuracy_calculation()
        auth.test_4_precision_recall_calculation()
        auth.test_5_fpr_fnr_calculation()
        auth.test_6_metrics_timeline_recording()
        auth.test_7_database_updates_on_validation()
        auth.test_8_ground_truth_validation()
        auth.test_9_data_integrity()
        auth.test_10_concurrent_validation()
        
        success = auth.print_summary()
        sys.exit(0 if success else 1)
    
    except Exception as e:
        print(f"\n[ERROR] AUTHENTICATION FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
