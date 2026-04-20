"""
Auto-Corrector: Real-time self-correction for IDS mistakes
When FP/FN detected, immediately updates database to prevent recurrence.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from database.db_engine import ThreatRecord
from datetime import datetime


class AutoCorrector:
    """
    Automatically corrects IDS mistakes in real-time.
    
    When a False Positive is detected:
        - Add the event to database with decision="Ignore" (it's benign)
        - Mark with high confidence so it won't be blocked again
    
    When a False Negative is detected:
        - Add the event to database with decision="Block" (it's an attack)
        - Mark with high confidence so it will be blocked next time
    """
    
    def __init__(self, db, event_bus):
        self.db = db
        self.bus = event_bus
        self.corrections_made = 0
        self.fp_corrections = 0
        self.fn_corrections = 0
    
    def correct_false_positive(self, event: dict):
        """
        Correct a False Positive: benign traffic was incorrectly blocked.
        
        Add to database with decision="Ignore" so it won't be blocked again.
        """
        print(f"\n[AUTO-CORRECTOR] FP CORRECTION: Benign traffic was blocked")
        print(f"  Event: {event.get('source', '?')} -> {event.get('destination', '?')}")
        print(f"  IDS incorrectly decided: {event.get('ids_decision', '?')}")
        
        # Create corrected record
        rec = ThreatRecord(
            embedding    = event.get("feature_vector", [0.1] * 64),
            source       = event.get("source", "unknown"),
            destination  = event.get("destination", "unknown"),
            attack_class = "benign",
            decision     = "Ignore",  # Correct decision: allow it
            confidence   = 0.95,      # High confidence so it won't be blocked again
            anomaly_trend= 0.05,      # Low anomaly for benign
            entropy      = 0.3,       # Low entropy for benign
            rate_hz      = event.get("rate_hz", 100.0),
            port_dst     = event.get("port_dst", 0),
            protocol     = event.get("protocol", 6),
            flags        = event.get("flags", 0),
            explanation  = f"[FP-CORRECTION] Was incorrectly {event.get('ids_decision', '?')} - "
                          f"now marked as benign to prevent recurrence",
            timestamp    = datetime.now().isoformat(),
            frame_id     = event.get("frame_id", -1),
        )
        
        # Write to database
        self.db.memory.global_store.insert(rec)
        self.db.memory.ip_store[rec.source].insert(rec)
        
        self.corrections_made += 1
        self.fp_corrections += 1
        
        print(f"  CORRECTED: Added to database as benign (Ignore)")
        print(f"  Total corrections: {self.corrections_made}\n")
        
        # Emit event for logging
        self.bus.emit("fp_corrected", {
            "source": rec.source,
            "destination": rec.destination,
            "timestamp": rec.timestamp,
        })
    
    def correct_false_negative(self, event: dict):
        """
        Correct a False Negative: attack was incorrectly ignored.
        
        Add to database with decision="Block" so it will be blocked next time.
        """
        print(f"\n[AUTO-CORRECTOR] FN CORRECTION: Attack was missed")
        print(f"  Event: {event.get('source', '?')} -> {event.get('destination', '?')}")
        print(f"  IDS incorrectly decided: {event.get('ids_decision', '?')}")
        print(f"  Attack class: {event.get('attack_class', '?')}")
        
        # Create corrected record
        rec = ThreatRecord(
            embedding    = event.get("feature_vector", [0.9] * 64),
            source       = event.get("source", "unknown"),
            destination  = event.get("destination", "unknown"),
            attack_class = event.get("attack_class", "UnknownHighSeverity"),
            decision     = "Block",    # Correct decision: block it
            confidence   = 0.95,       # High confidence so it will be blocked next time
            anomaly_trend= 0.85,       # High anomaly for attack
            entropy      = 0.85,       # High entropy for attack
            rate_hz      = event.get("rate_hz", 500.0),
            port_dst     = event.get("port_dst", 0),
            protocol     = event.get("protocol", 6),
            flags        = event.get("flags", 0),
            explanation  = f"[FN-CORRECTION] Was incorrectly {event.get('ids_decision', '?')} - "
                          f"now marked as {event.get('attack_class', '?')} to prevent recurrence",
            timestamp    = datetime.now().isoformat(),
            frame_id     = event.get("frame_id", -1),
        )
        
        # Write to database
        self.db.memory.global_store.insert(rec)
        self.db.memory.ip_store[rec.source].insert(rec)
        
        self.corrections_made += 1
        self.fn_corrections += 1
        
        print(f"  CORRECTED: Added to database as {event.get('attack_class', '?')} (Block)")
        print(f"  Total corrections: {self.corrections_made}\n")
        
        # Emit event for logging
        self.bus.emit("fn_corrected", {
            "source": rec.source,
            "destination": rec.destination,
            "attack_class": rec.attack_class,
            "timestamp": rec.timestamp,
        })
    
    def get_stats(self) -> dict:
        """Get correction statistics."""
        return {
            "total_corrections": self.corrections_made,
            "false_positive_corrections": self.fp_corrections,
            "false_negative_corrections": self.fn_corrections,
        }
    
    def print_stats(self):
        """Print correction statistics."""
        stats = self.get_stats()
        print("\n" + "=" * 70)
        print("AUTO-CORRECTOR STATISTICS")
        print("=" * 70)
        print(f"Total Corrections Made: {stats['total_corrections']}")
        print(f"  False Positive Corrections: {stats['false_positive_corrections']}")
        print(f"  False Negative Corrections: {stats['false_negative_corrections']}")
        print("=" * 70 + "\n")


class ValidationWithAutoCorrection:
    """
    Combines validation tracking with automatic correction.
    
    When FP/FN detected:
    1. Report it in metrics
    2. Automatically correct the database
    3. Prevent the same mistake from happening again
    """
    
    def __init__(self, db, event_bus, output_dir: str = "validation"):
        from validation.metrics_tracker import MetricsTracker
        
        self.db = db
        self.bus = event_bus
        self.tracker = MetricsTracker(output_dir=output_dir)
        self.corrector = AutoCorrector(db, event_bus)
        self.event_counter = 0
    
    def validate_and_correct(self, event: dict):
        """
        Validate a decision and auto-correct if FP/FN detected.
        
        event = {
            "is_attack": bool,           # Ground truth
            "decision": str,             # IDS decision
            "attack_class": str,
            "confidence": float,
            "feature_vector": list,
            "source": str,
            "destination": str,
            "port_dst": int,
            "protocol": int,
            "flags": int,
            "rate_hz": float,
            "frame_id": int,
        }
        """
        self.event_counter += 1
        
        is_attack = event.get("is_attack", False)
        decision = event.get("decision", "Ignore")
        detected = decision in ("Block", "Alert", "Escalate")
        
        # Log to tracker
        self.tracker.log_event({
            "is_attack": is_attack,
            "decision": decision,
            "attack_class": event.get("attack_class", "unknown"),
            "confidence": event.get("confidence", 0),
            "timestamp": event.get("timestamp", datetime.now().isoformat()),
        })
        
        # Detect and correct errors
        if is_attack and not detected:
            # False Negative: attack was missed
            self.corrector.correct_false_negative(event)
        elif not is_attack and detected:
            # False Positive: benign was blocked
            self.corrector.correct_false_positive(event)
    
    def get_metrics(self) -> dict:
        """Get validation metrics."""
        return self.tracker.get_metrics()
    
    def get_corrections(self) -> dict:
        """Get correction statistics."""
        return self.corrector.get_stats()
    
    def print_summary(self):
        """Print full summary."""
        print("\n" + "=" * 70)
        print("VALIDATION & AUTO-CORRECTION SUMMARY")
        print("=" * 70)
        
        # Metrics
        m = self.tracker.get_metrics()
        print(f"\nValidation Metrics:")
        print(f"  Total Events: {m.get('total_events', 0)}")
        
        if m.get('total_events', 0) > 0:
            print(f"  Accuracy: {m.get('accuracy', 0):.2%}")
            print(f"  Precision: {m.get('precision', 0):.2%}")
            print(f"  Recall: {m.get('recall', 0):.2%}")
            print(f"  F1 Score: {m.get('f1_score', 0):.4f}")
            print(f"  FPR: {m.get('fpr', 0):.2%} | FNR: {m.get('fnr', 0):.2%}")
        else:
            print(f"  (no events validated yet)")
        
        # Corrections
        c = self.corrector.get_stats()
        print(f"\nAuto-Corrections Made:")
        print(f"  Total: {c['total_corrections']}")
        print(f"  False Positive Corrections: {c['false_positive_corrections']}")
        print(f"  False Negative Corrections: {c['false_negative_corrections']}")
        
        print("=" * 70 + "\n")
