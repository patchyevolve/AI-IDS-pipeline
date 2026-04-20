"""
Training Validator Hook
Integrates validation metrics into the IDS training pipeline.
Tracks FP/FN in real-time during training.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from validation.metrics_tracker import MetricsTracker
from datetime import datetime


class TrainingValidator:
    """
    Hooks into the IDS pipeline to validate decisions in real-time.
    Tracks false positives and false negatives during training.
    
    NOTE: This validator is called from run.py's on_network_event handler,
    not via event bus subscription. The validator receives ground truth
    from the attacker's metadata (is_attack, attack_class).
    """
    
    def __init__(self, event_bus, output_dir: str = "validation"):
        self.bus = event_bus
        self.tracker = MetricsTracker(output_dir=output_dir)
        self.event_counter = 0
        self.last_report_time = datetime.now()
        self.report_interval = 300  # Report every 5 minutes
    
    def validate_and_correct(self, event: dict):
        """
        Validate a decision and track metrics.
        
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
        
        # Log to tracker
        self.tracker.log_event({
            "is_attack": is_attack,
            "decision": decision,
            "attack_class": attack_class,
            "confidence": confidence,
            "timestamp": event.get("timestamp", datetime.now().isoformat()),
        })
        
        # Periodic reporting
        now = datetime.now()
        if (now - self.last_report_time).total_seconds() >= self.report_interval:
            self._print_periodic_report()
            self.last_report_time = now
    
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
        else:
            print("(no events validated yet)")
        
        print("=" * 70 + "\n")


def integrate_validator(bus, output_dir: str = "validation") -> TrainingValidator:
    """
    Integrate validation into the training pipeline.
    
    Usage in run.py:
        validator = integrate_validator(bus)
        # ... training runs ...
        validator.print_summary()
        validator.save_report()
    """
    return TrainingValidator(bus, output_dir=output_dir)
