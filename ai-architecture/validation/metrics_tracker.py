"""
Validation Metrics Tracker
Monitors False Positives (FP) and False Negatives (FN) during IDS training.

FP = Benign traffic incorrectly blocked/alerted
FN = Attack traffic incorrectly ignored/logged
"""
import json
import time
from datetime import datetime
from pathlib import Path
from collections import defaultdict


class MetricsTracker:
    """Track FP/FN metrics during training."""
    
    def __init__(self, output_dir: str = "validation"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.metrics = {
            "session_start": datetime.now().isoformat(),
            "total_events": 0,
            "true_positives": 0,      # Attack correctly blocked/alerted
            "true_negatives": 0,      # Benign correctly ignored/logged
            "false_positives": 0,     # Benign incorrectly blocked/alerted
            "false_negatives": 0,     # Attack incorrectly ignored/logged
            "by_class": defaultdict(lambda: {
                "tp": 0, "tn": 0, "fp": 0, "fn": 0
            }),
            "by_decision": defaultdict(lambda: {
                "correct": 0, "incorrect": 0
            }),
        }
        self.report_file = self.output_dir / "validation_report.json"
        self.timeline_file = self.output_dir / "metrics_timeline.jsonl"
    
    def log_event(self, event: dict):
        """
        Log an event with ground truth vs IDS decision.
        
        event = {
            "is_attack": bool,           # Ground truth: is this an attack?
            "decision": str,             # IDS decision: "Block", "Alert", "Log", "Ignore"
            "attack_class": str,         # Attack class if known
            "confidence": float,         # IDS confidence
            "timestamp": str,
        }
        """
        self.metrics["total_events"] += 1
        
        is_attack = event.get("is_attack", False)
        decision = event.get("decision", "Ignore")
        attack_class = event.get("attack_class", "unknown")
        
        # Determine if decision was correct
        # Block/Alert = treat as positive detection
        # Log/Ignore = treat as negative detection
        detected = decision in ("Block", "Alert", "Escalate")
        
        if is_attack and detected:
            # True Positive: correctly detected attack
            self.metrics["true_positives"] += 1
            self.metrics["by_class"][attack_class]["tp"] += 1
            self.metrics["by_decision"][decision]["correct"] += 1
        elif is_attack and not detected:
            # False Negative: missed attack
            self.metrics["false_negatives"] += 1
            self.metrics["by_class"][attack_class]["fn"] += 1
            self.metrics["by_decision"][decision]["incorrect"] += 1
        elif not is_attack and detected:
            # False Positive: blocked benign traffic
            self.metrics["false_positives"] += 1
            self.metrics["by_class"]["benign"]["fp"] += 1
            self.metrics["by_decision"][decision]["incorrect"] += 1
        else:
            # True Negative: correctly allowed benign traffic
            self.metrics["true_negatives"] += 1
            self.metrics["by_class"]["benign"]["tn"] += 1
            self.metrics["by_decision"][decision]["correct"] += 1
        
        # Append to timeline
        with open(self.timeline_file, "a") as f:
            f.write(json.dumps({
                "timestamp": event.get("timestamp", datetime.now().isoformat()),
                "is_attack": is_attack,
                "decision": decision,
                "attack_class": attack_class,
                "correct": (is_attack == detected),
            }) + "\n")
    
    def get_metrics(self) -> dict:
        """Get current metrics."""
        total = self.metrics["total_events"]
        if total == 0:
            return self.metrics
        
        tp = self.metrics["true_positives"]
        tn = self.metrics["true_negatives"]
        fp = self.metrics["false_positives"]
        fn = self.metrics["false_negatives"]
        
        # Calculate rates
        metrics = dict(self.metrics)
        metrics["accuracy"] = round((tp + tn) / total, 4) if total > 0 else 0
        metrics["precision"] = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0
        metrics["recall"] = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0
        metrics["f1_score"] = round(
            2 * (metrics["precision"] * metrics["recall"]) / 
            (metrics["precision"] + metrics["recall"]), 4
        ) if (metrics["precision"] + metrics["recall"]) > 0 else 0
        
        # False positive rate (FPR)
        metrics["fpr"] = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0
        # False negative rate (FNR)
        metrics["fnr"] = round(fn / (fn + tp), 4) if (fn + tp) > 0 else 0
        
        return metrics
    
    def save_report(self):
        """Save metrics report to JSON."""
        metrics = self.get_metrics()
        metrics["session_end"] = datetime.now().isoformat()
        
        with open(self.report_file, "w") as f:
            json.dump(metrics, f, indent=2, default=str)
        
        return self.report_file
    
    def print_summary(self):
        """Print metrics summary to console."""
        m = self.get_metrics()
        
        print("\n" + "=" * 70)
        print("VALIDATION METRICS SUMMARY")
        print("=" * 70)
        print(f"Total Events: {m['total_events']}")
        print(f"\nConfusion Matrix:")
        print(f"  True Positives (TP):   {m['true_positives']}")
        print(f"  True Negatives (TN):   {m['true_negatives']}")
        print(f"  False Positives (FP):  {m['false_positives']}")
        print(f"  False Negatives (FN):  {m['false_negatives']}")
        print(f"\nPerformance Metrics:")
        print(f"  Accuracy:  {m['accuracy']:.2%}")
        print(f"  Precision: {m['precision']:.2%}")
        print(f"  Recall:    {m['recall']:.2%}")
        print(f"  F1 Score:  {m['f1_score']:.4f}")
        print(f"\nError Rates:")
        print(f"  False Positive Rate (FPR): {m['fpr']:.2%}")
        print(f"  False Negative Rate (FNR): {m['fnr']:.2%}")
        print("=" * 70 + "\n")


class ValidationAuthenticator:
    """
    Authenticates IDS decisions against ground truth.
    Used during training to validate model quality.
    """
    
    def __init__(self, tracker: MetricsTracker):
        self.tracker = tracker
        self.ground_truth_db = {}  # Map event_id -> is_attack
    
    def register_ground_truth(self, event_id: str, is_attack: bool, attack_class: str = ""):
        """Register ground truth for an event."""
        self.ground_truth_db[event_id] = {
            "is_attack": is_attack,
            "attack_class": attack_class,
        }
    
    def authenticate_decision(self, event_id: str, decision: dict) -> dict:
        """
        Authenticate an IDS decision against ground truth.
        
        Returns:
            {
                "event_id": str,
                "is_correct": bool,
                "ground_truth": bool,
                "ids_decision": str,
                "error_type": str or None,  # "FP", "FN", or None
            }
        """
        if event_id not in self.ground_truth_db:
            return None  # No ground truth for this event
        
        gt = self.ground_truth_db[event_id]
        is_attack = gt["is_attack"]
        ids_decision = decision.get("decision", "Ignore")
        detected = ids_decision in ("Block", "Alert", "Escalate")
        
        is_correct = (is_attack == detected)
        error_type = None
        
        if not is_correct:
            if is_attack and not detected:
                error_type = "FN"  # False Negative
            elif not is_attack and detected:
                error_type = "FP"  # False Positive
        
        # Log to tracker
        self.tracker.log_event({
            "is_attack": is_attack,
            "decision": ids_decision,
            "attack_class": gt.get("attack_class", "unknown"),
            "confidence": decision.get("confidence", 0),
            "timestamp": decision.get("timestamp", datetime.now().isoformat()),
        })
        
        return {
            "event_id": event_id,
            "is_correct": is_correct,
            "ground_truth": is_attack,
            "ids_decision": ids_decision,
            "error_type": error_type,
        }
