# Validation & Metrics Tracking

## Overview

This module provides **training-only** validation and metrics tracking for IDS co-evolutionary training.

**Purpose:**
- Measure IDS accuracy during training (FP/FN rates)
- Auto-correct database when IDS makes mistakes
- Guide co-evolution by providing quality metrics
- Minimize false positives and false negatives

**Ground Truth Source:**
- Attacker provides ground truth (is_attack: true/false)
- Validator checks if IDS decision was correct
- Auto-corrector learns from mistakes

During training, the system tracks:
- **True Positives (TP)**: Attacks correctly detected
- **True Negatives (TN)**: Benign traffic correctly allowed
- **False Positives (FP)**: Benign traffic incorrectly blocked/alerted
- **False Negatives (FN)**: Attacks incorrectly ignored/logged

## Key Metrics

- **Accuracy**: (TP + TN) / Total
- **Precision**: TP / (TP + FP) - How many alerts are real attacks?
- **Recall**: TP / (TP + FN) - How many attacks are detected?
- **F1 Score**: Harmonic mean of precision and recall
- **FPR (False Positive Rate)**: FP / (FP + TN) - Rate of false alarms
- **FNR (False Negative Rate)**: FN / (FN + TP) - Rate of missed attacks

## Usage

### Basic Metrics Tracking

```python
from validation.metrics_tracker import MetricsTracker

tracker = MetricsTracker(output_dir="validation")

# Log events
tracker.log_event({
    "is_attack": True,           # Ground truth
    "decision": "Block",         # IDS decision
    "attack_class": "DoS/DDoS",
    "confidence": 0.95,
})

# Get metrics
metrics = tracker.get_metrics()
print(f"Accuracy: {metrics['accuracy']:.2%}")
print(f"FPR: {metrics['fpr']:.2%}")
print(f"FNR: {metrics['fnr']:.2%}")

# Save report
tracker.save_report()
tracker.print_summary()
```

### Validation Authenticator

```python
from validation.metrics_tracker import ValidationAuthenticator, MetricsTracker

tracker = MetricsTracker()
auth = ValidationAuthenticator(tracker)

# Register ground truth
auth.register_ground_truth("evt_001", is_attack=True, attack_class="DoS/DDoS")
auth.register_ground_truth("evt_002", is_attack=False, attack_class="benign")

# Authenticate IDS decisions
result = auth.authenticate_decision("evt_001", {
    "decision": "Block",
    "confidence": 0.95,
})

# result = {
#     "event_id": "evt_001",
#     "is_correct": True,
#     "ground_truth": True,
#     "ids_decision": "Block",
#     "error_type": None,
# }
```

### Integration with Training Pipeline

```python
from validation.training_validator import integrate_validator

# In run.py main():
validator = integrate_validator(bus, output_dir="validation")

# ... training runs ...
# Validator automatically tracks metrics from decoder_output events

# At end of training:
validator.print_final_report()
validator.save_report()
```

## Output Files

- `validation/validation_report.json` - Final metrics report
- `validation/metrics_timeline.jsonl` - Per-event timeline (one JSON per line)

## Example Report

```json
{
  "session_start": "2026-04-20T10:29:14.393639",
  "total_events": 1000,
  "true_positives": 450,
  "true_negatives": 480,
  "false_positives": 35,
  "false_negatives": 35,
  "accuracy": 0.93,
  "precision": 0.928,
  "recall": 0.928,
  "f1_score": 0.928,
  "fpr": 0.068,
  "fnr": 0.072,
  "by_class": {
    "DoS/DDoS": {"tp": 120, "tn": 0, "fp": 5, "fn": 3},
    "PortScan": {"tp": 85, "tn": 0, "fp": 2, "fn": 8},
    "benign": {"tp": 0, "tn": 480, "fp": 28, "fn": 0}
  }
}
```

## Interpreting Results

### Good Model
- Accuracy > 95%
- Precision > 90% (few false alarms)
- Recall > 90% (catches most attacks)
- FPR < 5% (acceptable false alarm rate)
- FNR < 5% (acceptable miss rate)

### Needs Improvement
- FPR > 10% (too many false alarms)
- FNR > 10% (missing too many attacks)
- Precision < 80% (too many false positives)
- Recall < 80% (missing attacks)

## Testing

Run the validation test suite:

```bash
python tests/test_validation_metrics.py
```

This demonstrates:
1. Basic metrics tracking
2. Validation authenticator
3. Report generation
