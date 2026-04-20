"""
Training Validator Hook
Integrates validation metrics into the IDS training pipeline.
Tracks FP/FN in real-time during training and auto-corrects database.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from validation.metrics_tracker import MetricsTracker
from database.db_engine import ThreatRecord
from datetime import datetime


class TrainingValidator:
    """
    Hooks into the IDS pipeline to validate decisions in real-time.
    Tracks false positives and false negatives during training.
    Auto-corrects database when errors detected.
    
    NOTE: This validator can be called in two ways:
    1. Directly from run.py's on_network_event handler (Python pipeline)
    2. Via event bus subscription to decoder_output (works with C++ pipeline too)
    
    The validator receives ground truth from the attacker's metadata (is_attack, attack_class).
    """
    
    def __init__(self, event_bus, db=None, output_dir: str = "validation"):
        self.bus = event_bus
        self.db = db
        self.tracker = MetricsTracker(output_dir=output_dir)
        self.event_counter = 0
        self.last_report_time = datetime.now()
        self.report_interval = 300  # Report every 5 minutes
        self.corrections_made = 0
        self.fn_corrections = 0
        self.fp_corrections = 0
        
        # Subscribe to decoder_output events so validation works with both Python and C++ pipelines
        self.bus.subscribe("decoder_output", self._on_decoder_output)
    
    def validate_and_correct(self, event: dict):
        """
        Validate a decision and track metrics.
        Auto-correct database if FN/FP detected.
        
        Called from run.py's on_network_event handler with:
        {
            "is_attack": bool,           # Ground truth from attacker
            "decision": str,             # IDS decision
            "attack_class": str,
            "confidence": float,
            "feature_vector": list,
            "source": str,
            "destination": str,
            ...
        }
        """
        self.event_counter += 1
        
        is_attack = event.get("is_attack", False)
        decision = event.get("decision", "Ignore")
        confidence = event.get("confidence", 0.0)
        attack_class = event.get("attack_class", "unknown")
        detected = decision in ("Block", "Alert", "Escalate")
        
        # Log to tracker
        self.tracker.log_event({
            "is_attack": is_attack,
            "decision": decision,
            "attack_class": attack_class,
            "confidence": confidence,
            "timestamp": event.get("timestamp", datetime.now().isoformat()),
        })
        
        # ✓ AUTO-CORRECT: Update database when errors detected
        if self.db:
            if is_attack and not detected:
                # False Negative: attack was missed - add to DB so it's detected next time
                self._correct_false_negative(event)
            elif not is_attack and detected:
                # False Positive: benign was blocked - add to DB so it's allowed next time
                self._correct_false_positive(event)
        
        # Periodic reporting
        now = datetime.now()
        if (now - self.last_report_time).total_seconds() >= self.report_interval:
            self._print_periodic_report()
            self.last_report_time = now
    
    def _on_decoder_output(self, data: dict):
        """
        Event handler for decoder_output events.
        Works with both Python and C++ pipelines.
        Validates decisions against ground truth metadata.
        """
        metadata = data.get("metadata", {})
        
        # Only validate if we have ground truth (from attacker)
        if metadata.get("is_attack") is not None:
            self.validate_and_correct({
                "is_attack": metadata.get("is_attack", False),
                "decision": data.get("decision", "Ignore"),
                "attack_class": metadata.get("attack_class", "unknown"),
                "confidence": data.get("confidence", 0.0),
                "feature_vector": data.get("feature_vector", [0.5] * 64),
                "source": data.get("source", ""),
                "destination": data.get("destination", ""),
                "port_dst": data.get("port_dst", 0),
                "protocol": data.get("protocol", 0),
                "flags": data.get("flags", 0),
                "rate_hz": data.get("rate_hz", 0.0),
                "timestamp": data.get("timestamp", datetime.now().isoformat()),
            })
    
    def _correct_false_negative(self, event: dict):
        """Correct FN: attack was missed, add to DB with high confidence."""
        try:
            rec = ThreatRecord(
                embedding=event.get("feature_vector", [0.9] * 64),
                source=event.get("source", "unknown"),
                destination=event.get("destination", "unknown"),
                attack_class=event.get("attack_class", "UnknownHighSeverity"),
                decision="Block",  # Correct decision: block this attack
                confidence=0.95,   # High confidence
                anomaly_trend=0.85,
                entropy=0.85,
                rate_hz=event.get("rate_hz", 500.0),
                port_dst=event.get("port_dst", 0),
                protocol=event.get("protocol", 6),
                flags=event.get("flags", 0),
                explanation=f"[FN-CORRECTION] Was incorrectly {event.get('decision')} - now marked as {event.get('attack_class')}",
                timestamp=event.get("timestamp", datetime.now().isoformat()),
                frame_id=event.get("frame_id", -1),
            )
            self.db.memory.global_store.insert(rec)
            self.db.memory.ip_store[rec.source].insert(rec)
            self.corrections_made += 1
            self.fn_corrections += 1
            print(f"[VALIDATOR] FN-CORRECTION: Added {event.get('attack_class')} to DB (was missed)")
        except Exception as e:
            print(f"[VALIDATOR] FN correction error: {e}")
    
    def _correct_false_positive(self, event: dict):
        """Correct FP: benign was blocked, add to DB with low confidence."""
        try:
            rec = ThreatRecord(
                embedding=event.get("feature_vector", [0.1] * 64),
                source=event.get("source", "unknown"),
                destination=event.get("destination", "unknown"),
                attack_class="benign",
                decision="Ignore",  # Correct decision: allow this traffic
                confidence=0.95,    # High confidence it's benign
                anomaly_trend=0.05,
                entropy=0.3,
                rate_hz=event.get("rate_hz", 100.0),
                port_dst=event.get("port_dst", 0),
                protocol=event.get("protocol", 6),
                flags=event.get("flags", 0),
                explanation=f"[FP-CORRECTION] Was incorrectly {event.get('decision')} - now marked as benign",
                timestamp=event.get("timestamp", datetime.now().isoformat()),
                frame_id=event.get("frame_id", -1),
            )
            self.db.memory.global_store.insert(rec)
            self.db.memory.ip_store[rec.source].insert(rec)
            self.corrections_made += 1
            self.fp_corrections += 1
            print(f"[VALIDATOR] FP-CORRECTION: Added benign traffic to DB (was blocked)")
        except Exception as e:
            print(f"[VALIDATOR] FP correction error: {e}")
    
    def _print_periodic_report(self):
        """Print periodic validation report."""
        m = self.tracker.get_metrics()
        
        if m["total_events"] == 0:
            return
        
        print("\n" + "─" * 70)
        print(f"[VALIDATION] Events: {m['total_events']} | "
              f"TP: {m['true_positives']} | "
              f"TN: {m['true_negatives']} | "
              f"FP: {m['false_positives']} | "
              f"FN: {m['false_negatives']}")
        print(f"[VALIDATION] Accuracy: {m['accuracy']:.2%} | "
              f"Precision: {m['precision']:.2%} | "
              f"Recall: {m['recall']:.2%} | "
              f"F1: {m['f1_score']:.4f}")
        print(f"[VALIDATION] FPR: {m['fpr']:.2%} | FNR: {m['fnr']:.2%}")
        if self.corrections_made > 0:
            print(f"[VALIDATION] Corrections: {self.corrections_made} total ({self.fn_corrections} FN, {self.fp_corrections} FP)")
        print("─" * 70)
    
    def get_metrics(self) -> dict:
        """Get current validation metrics."""
        return self.tracker.get_metrics()
    
    def get_report(self) -> dict:
        """Get current validation report."""
        return self.tracker.get_metrics()
    
    def save_report(self):
        """Save validation report to file."""
        return self.tracker.save_report()
    
    def print_summary(self):
        """Print final validation summary."""
        m = self.tracker.get_metrics()
        print("\n" + "=" * 70)
        print("VALIDATION SUMMARY")
        print("=" * 70)
        print(f"Total Events: {m.get('total_events', 0)}")
        
        if m.get('total_events', 0) > 0:
            print(f"Accuracy: {m.get('accuracy', 0):.2%}")
            print(f"Precision: {m.get('precision', 0):.2%}")
            print(f"Recall: {m.get('recall', 0):.2%}")
            print(f"F1 Score: {m.get('f1_score', 0):.4f}")
            print(f"FPR: {m.get('fpr', 0):.2%} | FNR: {m.get('fnr', 0):.2%}")
            print(f"\nTrue Positives: {m.get('true_positives', 0)}")
            print(f"True Negatives: {m.get('true_negatives', 0)}")
            print(f"False Positives: {m.get('false_positives', 0)}")
            print(f"False Negatives: {m.get('false_negatives', 0)}")
            print(f"\nAuto-Corrections: {self.corrections_made} ({self.fn_corrections} FN, {self.fp_corrections} FP)")
        else:
            print("(no events validated yet)")
        
        print("=" * 70 + "\n")


def integrate_validator(bus, db=None, output_dir: str = "validation") -> TrainingValidator:
    """
    Integrate validation into the training pipeline.
    
    Usage in run.py:
        validator = integrate_validator(bus, db)
        # ... training runs ...
        validator.print_summary()
        validator.save_report()
    """
    return TrainingValidator(bus, db=db, output_dir=output_dir)
