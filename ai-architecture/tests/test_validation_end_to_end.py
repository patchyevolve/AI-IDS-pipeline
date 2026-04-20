"""
End-to-End Validation System Test

Demonstrates the complete validation pipeline:
1. Attack events are generated with ground truth metadata
2. IDS makes decisions (Block/Alert/Ignore/Log)
3. Validator checks if decision matches ground truth
4. Database is updated with corrections for FN/FP
5. Metrics are tracked and reported

This test simulates a realistic attack session with:
- Multiple attack types
- Mixed correct/incorrect IDS decisions
- Real-time database corrections
- Metrics tracking and reporting
"""
import sys
import os
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from event_bus import EventBus
from database.db_engine import DatabaseEngine, ThreatRecord
from validation.training_validator import TrainingValidator
from datetime import datetime


class EndToEndValidator:
    """Simulates complete validation pipeline."""
    
    def __init__(self):
        self.bus = EventBus()
        self.db = DatabaseEngine(self.bus)
        self.validator = TrainingValidator(self.bus, db=self.db)
        self.session_events = []
    
    def simulate_attack_session(self, num_attacks: int = 100):
        """Simulate an attack session with mixed outcomes."""
        print("\n" + "="*70)
        print(f"SIMULATING ATTACK SESSION: {num_attacks} events")
        print("="*70)
        
        attack_types = [
            "DoS/DDoS",
            "PortScan",
            "BruteForce",
            "SQLInjection",
            "XSS",
            "Botnet",
            "Exfiltration",
        ]
        
        decisions = ["Block", "Alert", "Escalate", "Log", "Ignore"]
        
        stats = {
            "total": 0,
            "attacks": 0,
            "benign": 0,
            "correct": 0,
            "incorrect": 0,
            "tp": 0,
            "tn": 0,
            "fp": 0,
            "fn": 0,
        }
        
        for i in range(num_attacks):
            # 70% attacks, 30% benign
            is_attack = i % 10 < 7
            
            if is_attack:
                stats["attacks"] += 1
                attack_class = attack_types[i % len(attack_types)]
                
                # 80% of attacks are correctly detected
                if i % 5 < 4:
                    decision = "Block"  # Correct
                    stats["correct"] += 1
                    stats["tp"] += 1
                else:
                    decision = "Ignore"  # Incorrect (FN)
                    stats["incorrect"] += 1
                    stats["fn"] += 1
            else:
                stats["benign"] += 1
                attack_class = "benign"
                
                # 95% of benign traffic is correctly allowed
                if i % 20 < 19:
                    decision = "Ignore"  # Correct
                    stats["correct"] += 1
                    stats["tn"] += 1
                else:
                    decision = "Block"  # Incorrect (FP)
                    stats["incorrect"] += 1
                    stats["fp"] += 1
            
            # Create event with ground truth
            event = {
                "is_attack": is_attack,
                "decision": decision,
                "attack_class": attack_class,
                "confidence": 0.9 if is_attack else 0.1,
                "feature_vector": [0.9 if is_attack else 0.1] * 64,
                "source": f"203.0.113.{i % 256}",
                "destination": "192.168.1.1",
                "port_dst": 80 + (i % 100),
                "protocol": 6,
                "flags": 0x02,
                "rate_hz": 500.0 if is_attack else 100.0,
                "timestamp": datetime.now().isoformat(),
            }
            
            # Validate and correct
            self.validator.validate_and_correct(event)
            self.session_events.append(event)
            stats["total"] += 1
            
            # Progress indicator
            if (i + 1) % 20 == 0:
                print(f"  Processed {i + 1}/{num_attacks} events...")
        
        return stats
    
    def verify_corrections(self):
        """Verify that corrections were applied to database."""
        print("\n" + "="*70)
        print("VERIFYING DATABASE CORRECTIONS")
        print("="*70)
        
        metrics = self.validator.get_metrics()
        
        print(f"\nValidation Metrics:")
        print(f"  Total Events: {metrics['total_events']}")
        print(f"  True Positives: {metrics['true_positives']}")
        print(f"  True Negatives: {metrics['true_negatives']}")
        print(f"  False Positives: {metrics['false_positives']}")
        print(f"  False Negatives: {metrics['false_negatives']}")
        
        print(f"\nPerformance Metrics:")
        print(f"  Accuracy: {metrics['accuracy']:.2%}")
        print(f"  Precision: {metrics['precision']:.2%}")
        print(f"  Recall: {metrics['recall']:.2%}")
        print(f"  F1 Score: {metrics['f1_score']:.4f}")
        
        print(f"\nError Rates:")
        print(f"  False Positive Rate: {metrics['fpr']:.2%}")
        print(f"  False Negative Rate: {metrics['fnr']:.2%}")
        
        print(f"\nAuto-Corrections:")
        print(f"  Total Corrections: {self.validator.corrections_made}")
        print(f"  FN Corrections: {self.validator.fn_corrections}")
        print(f"  FP Corrections: {self.validator.fp_corrections}")
        
        # Verify database was updated
        db_size = self.db.memory.total_size()
        print(f"\nDatabase State:")
        print(f"  Total Records: {db_size}")
        
        return metrics
    
    def verify_timeline_recording(self):
        """Verify metrics timeline was recorded."""
        print("\n" + "="*70)
        print("VERIFYING METRICS TIMELINE")
        print("="*70)
        
        timeline_file = "validation/metrics_timeline.jsonl"
        
        if os.path.exists(timeline_file):
            with open(timeline_file, 'r') as f:
                lines = f.readlines()
            
            print(f"Timeline file: {timeline_file}")
            print(f"Total entries: {len(lines)}")
            
            # Show last 5 entries
            print(f"\nLast 5 timeline entries:")
            for line in lines[-5:]:
                entry = json.loads(line)
                print(f"  {entry['timestamp']}: {entry['decision']} "
                      f"(attack={entry['is_attack']}, correct={entry['correct']})")
            
            return True
        else:
            print(f"[WARNING] Timeline file not found: {timeline_file}")
            return False
    
    def verify_data_integrity(self):
        """Verify data integrity throughout pipeline."""
        print("\n" + "="*70)
        print("VERIFYING DATA INTEGRITY")
        print("="*70)
        
        checks = []
        
        # Check 1: All events were processed
        metrics = self.validator.get_metrics()
        total_events = metrics['total_events']
        expected_events = len(self.session_events)
        
        check1 = total_events == expected_events
        checks.append(check1)
        print(f"[{'PASS' if check1 else 'FAIL'}] All events processed: "
              f"{total_events} == {expected_events}")
        
        # Check 2: Confusion matrix adds up
        tp = metrics['true_positives']
        tn = metrics['true_negatives']
        fp = metrics['false_positives']
        fn = metrics['false_negatives']
        
        check2 = (tp + tn + fp + fn) == total_events
        checks.append(check2)
        print(f"[{'PASS' if check2 else 'FAIL'}] Confusion matrix valid: "
              f"{tp}+{tn}+{fp}+{fn} == {total_events}")
        
        # Check 3: Metrics are in valid ranges
        check3 = (0 <= metrics['accuracy'] <= 1 and
                  0 <= metrics['precision'] <= 1 and
                  0 <= metrics['recall'] <= 1 and
                  0 <= metrics['fpr'] <= 1 and
                  0 <= metrics['fnr'] <= 1)
        checks.append(check3)
        print(f"[{'PASS' if check3 else 'FAIL'}] Metrics in valid ranges")
        
        # Check 4: Accuracy formula correct
        expected_accuracy = (tp + tn) / total_events if total_events > 0 else 0
        check4 = abs(metrics['accuracy'] - expected_accuracy) < 0.001
        checks.append(check4)
        print(f"[{'PASS' if check4 else 'FAIL'}] Accuracy formula correct: "
              f"{metrics['accuracy']:.4f} ≈ {expected_accuracy:.4f}")
        
        # Check 5: Precision formula correct
        expected_precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        check5 = abs(metrics['precision'] - expected_precision) < 0.001
        checks.append(check5)
        print(f"[{'PASS' if check5 else 'FAIL'}] Precision formula correct: "
              f"{metrics['precision']:.4f} ≈ {expected_precision:.4f}")
        
        # Check 6: Recall formula correct
        expected_recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        check6 = abs(metrics['recall'] - expected_recall) < 0.001
        checks.append(check6)
        print(f"[{'PASS' if check6 else 'FAIL'}] Recall formula correct: "
              f"{metrics['recall']:.4f} ≈ {expected_recall:.4f}")
        
        # Check 7: FPR formula correct
        expected_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        check7 = abs(metrics['fpr'] - expected_fpr) < 0.001
        checks.append(check7)
        print(f"[{'PASS' if check7 else 'FAIL'}] FPR formula correct: "
              f"{metrics['fpr']:.4f} ≈ {expected_fpr:.4f}")
        
        # Check 8: FNR formula correct
        expected_fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        check8 = abs(metrics['fnr'] - expected_fnr) < 0.001
        checks.append(check8)
        print(f"[{'PASS' if check8 else 'FAIL'}] FNR formula correct: "
              f"{metrics['fnr']:.4f} ≈ {expected_fnr:.4f}")
        
        return all(checks)
    
    def print_final_report(self):
        """Print final validation report."""
        print("\n" + "="*70)
        print("FINAL VALIDATION REPORT")
        print("="*70)
        
        metrics = self.validator.get_metrics()
        
        print(f"\nSession Summary:")
        print(f"  Total Events Validated: {metrics['total_events']}")
        print(f"  Attacks Detected: {metrics['true_positives']}/{metrics['true_positives'] + metrics['false_negatives']}")
        print(f"  Benign Allowed: {metrics['true_negatives']}/{metrics['true_negatives'] + metrics['false_positives']}")
        
        print(f"\nValidation Accuracy:")
        print(f"  Overall Accuracy: {metrics['accuracy']:.2%}")
        print(f"  Precision (TP/(TP+FP)): {metrics['precision']:.2%}")
        print(f"  Recall (TP/(TP+FN)): {metrics['recall']:.2%}")
        print(f"  F1 Score: {metrics['f1_score']:.4f}")
        
        print(f"\nError Analysis:")
        print(f"  False Positive Rate: {metrics['fpr']:.2%} ({metrics['false_positives']} events)")
        print(f"  False Negative Rate: {metrics['fnr']:.2%} ({metrics['false_negatives']} events)")
        
        print(f"\nDatabase Corrections:")
        print(f"  Total Corrections Made: {self.validator.corrections_made}")
        print(f"  FN Corrections (missed attacks added): {self.validator.fn_corrections}")
        print(f"  FP Corrections (benign added): {self.validator.fp_corrections}")
        
        print(f"\nDatabase State:")
        print(f"  Total Records in DB: {self.db.memory.total_size()}")
        
        print("\n" + "="*70)


if __name__ == "__main__":
    validator = EndToEndValidator()
    
    try:
        # Simulate attack session
        stats = validator.simulate_attack_session(num_attacks=100)
        
        # Verify corrections
        metrics = validator.verify_corrections()
        
        # Verify timeline
        validator.verify_timeline_recording()
        
        # Verify data integrity
        integrity_ok = validator.verify_data_integrity()
        
        # Print final report
        validator.print_final_report()
        
        # Exit with success if all checks passed
        sys.exit(0 if integrity_ok else 1)
    
    except Exception as e:
        print(f"\n[ERROR] End-to-end validation failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
