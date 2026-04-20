"""
Capture Real Metrics from Actual Training Session

This script runs the actual IDS pipeline (like run.py does) and captures
real validation metrics from a live attack session.

It shows the REAL performance of the IDS against actual attacks.
"""
import sys
import os
import io
import time
import threading
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Fix Windows console encoding issues
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from event_bus import EventBus
from cnn.cnn_engine import CNNEngine
from rnn.rnn_engine import RNNEngine
from decoder.decoder_engine import HybridDecoder
from decoder.mutation_predictor import MutationAwareDecoder
from database.db_engine import DatabaseEngine
from validation.training_validator import TrainingValidator
from attacker.attack_engine import AttackEngine
from network.decision_feedback_server import DecisionFeedbackServer
from datetime import datetime
import json


def run_with_validation(duration_seconds=60):
    """Run the IDS pipeline with validation for specified duration."""
    
    print("\n" + "="*70)
    print("REAL IDS PIPELINE WITH VALIDATION")
    print("="*70)
    
    # Initialize
    bus = EventBus()
    db = DatabaseEngine(bus)
    cnn = CNNEngine(bus)
    rnn = RNNEngine(bus)
    base_decoder = HybridDecoder(bus)
    decoder = MutationAwareDecoder(base_decoder, db)
    validator = TrainingValidator(bus, db=db)
    
    print(f"\n[init] IDS Pipeline initialized")
    print(f"  - CNN Engine: ready")
    print(f"  - RNN Engine: ready")
    print(f"  - Decoder: ready (mutation-aware)")
    print(f"  - Database: {db.memory.total_size()} records loaded")
    print(f"  - Validator: ready")
    
    # Setup pipeline
    _counter = [0]
    
    def on_network_event(ev):
        _counter[0] += 1
        ev["frame_id"] = _counter[0]
        
        fid = ev.get("frame_id", 0)
        meta = ev.get("metadata", {})
        
        # Process through pipeline
        cnn_out = cnn.process_event(ev)
        rnn_out = rnn.process_features(cnn_out)
        db_mem = db.retrieve_memory(
            embedding=cnn_out["feature_vector"],
            source=ev.get("source", ""),
            destination=ev.get("destination", ""),
            port_dst=cnn_out.get("port_dst", 0),
            frame_id=fid,
        )
        
        # Decode
        dec_out = decoder.decode_with_mutation_awareness(
            cnn_out, rnn_out, db_mem["retrieved"], metadata=meta
        )
        dec_out["feature_vector"] = cnn_out["feature_vector"]
        dec_out["entropy"] = cnn_out.get("entropy", 0.0)
        dec_out["rate_hz"] = cnn_out.get("rate_hz", 0.0)
        dec_out["port_dst"] = cnn_out.get("port_dst", 0)
        dec_out["protocol"] = cnn_out.get("protocol", 0)
        dec_out["flags"] = cnn_out.get("flags", 0)
        
        # Log prediction
        db.log_prediction(dec_out)
        
        # VALIDATE: Check if decision is correct
        if validator and meta.get("is_attack") is not None:
            validator.validate_and_correct({
                "is_attack": meta.get("is_attack", False),
                "decision": dec_out["decision"],
                "attack_class": meta.get("attack_class", "unknown"),
                "confidence": dec_out["confidence"],
                "feature_vector": cnn_out["feature_vector"],
                "source": ev.get("source", ""),
                "destination": ev.get("destination", ""),
                "port_dst": cnn_out.get("port_dst", 0),
                "protocol": cnn_out.get("protocol", 0),
                "flags": cnn_out.get("flags", 0),
                "rate_hz": cnn_out.get("rate_hz", 0.0),
                "timestamp": dec_out.get("timestamp", ""),
            })
    
    bus.subscribe("network_event", on_network_event)
    
    # Start feedback server
    feedback_server = DecisionFeedbackServer(bus, port=9878)
    feedback_server.start()
    print(f"[feedback-server] Started on port 9878")
    
    # Start attacker
    attacker = AttackEngine(
        bus,
        synthetic_targets=True,
        rate_limit=0.05,
        evolve_interval=50,
        on_status=lambda m: print(f"[attacker] {m}")
    )
    attacker.start()
    print(f"[attacker] Attack engine started")
    
    # Run for specified duration
    print(f"\n[test] Running for {duration_seconds} seconds...")
    start_time = time.time()
    last_report = 0
    
    while time.time() - start_time < duration_seconds:
        elapsed = time.time() - start_time
        
        # Report every 15 seconds
        if elapsed - last_report >= 15:
            last_report = elapsed
            metrics = validator.get_metrics()
            stats = attacker.stats
            
            print(f"\n[{elapsed:.0f}s] REAL-TIME METRICS:")
            print(f"  Attacks Sent: {stats.get('total_sent', 0)}")
            print(f"  Events Validated: {metrics['total_events']}")
            
            if metrics['total_events'] > 0:
                print(f"  TP: {metrics['true_positives']} | "
                      f"TN: {metrics['true_negatives']} | "
                      f"FP: {metrics['false_positives']} | "
                      f"FN: {metrics['false_negatives']}")
                print(f"  Accuracy: {metrics['accuracy']:.2%} | "
                      f"Recall: {metrics['recall']:.2%} | "
                      f"Precision: {metrics['precision']:.2%}")
                print(f"  FNR: {metrics['fnr']:.2%} | FPR: {metrics['fpr']:.2%}")
                print(f"  Corrections: {validator.corrections_made}")
        
        time.sleep(1)
    
    # Stop
    attacker.stop()
    feedback_server.stop()
    
    # Final report
    print(f"\n" + "="*70)
    print("FINAL VALIDATION REPORT")
    print("="*70)
    
    metrics = validator.get_metrics()
    stats = attacker.stats
    
    print(f"\nAttack Session:")
    print(f"  Total Attacks Sent: {stats.get('total_sent', 0)}")
    print(f"  Blocked: {stats.get('total_blocked', 0)}")
    print(f"  Evaded: {stats.get('total_evaded', 0)}")
    print(f"  Alerted: {stats.get('total_alerted', 0)}")
    print(f"  Generations: {stats.get('generation', 0)}")
    
    total_sent = stats.get('total_sent', 1)
    evaded = stats.get('total_evaded', 0)
    evasion_rate = (evaded / total_sent * 100) if total_sent > 0 else 0
    
    print(f"\nEvasion Analysis:")
    print(f"  Evasion Rate: {evasion_rate:.1f}%")
    print(f"  Detection Rate: {100 - evasion_rate:.1f}%")
    
    if metrics['total_events'] > 0:
        print(f"\nValidation Metrics:")
        print(f"  Total Events: {metrics['total_events']}")
        print(f"  TP: {metrics['true_positives']}")
        print(f"  TN: {metrics['true_negatives']}")
        print(f"  FP: {metrics['false_positives']}")
        print(f"  FN: {metrics['false_negatives']}")
        
        print(f"\nPerformance:")
        print(f"  Accuracy: {metrics['accuracy']:.2%}")
        print(f"  Precision: {metrics['precision']:.2%}")
        print(f"  Recall: {metrics['recall']:.2%}")
        print(f"  F1 Score: {metrics['f1_score']:.4f}")
        
        print(f"\nError Rates:")
        print(f"  FPR: {metrics['fpr']:.2%}")
        print(f"  FNR: {metrics['fnr']:.2%}")
        
        print(f"\nCorrections:")
        print(f"  Total: {validator.corrections_made}")
        print(f"  FN: {validator.fn_corrections}")
        print(f"  FP: {validator.fp_corrections}")
    else:
        print(f"\n⚠️  No events validated (decoder_output not being emitted)")
    
    print(f"\nDatabase:")
    print(f"  Total Records: {db.memory.total_size()}")
    
    print(f"\n" + "="*70)
    
    # Save results
    results = {
        "timestamp": datetime.now().isoformat(),
        "duration": duration_seconds,
        "attacker_stats": stats,
        "validation_metrics": metrics if metrics['total_events'] > 0 else None,
        "corrections": {
            "total": validator.corrections_made,
            "fn": validator.fn_corrections,
            "fp": validator.fp_corrections,
        }
    }
    
    with open("validation/real_metrics_capture.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n[results] Saved to validation/real_metrics_capture.json")
    
    return metrics['total_events'] > 0


if __name__ == "__main__":
    try:
        success = run_with_validation(duration_seconds=60)
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
