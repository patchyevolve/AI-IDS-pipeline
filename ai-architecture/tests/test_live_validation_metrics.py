"""
Live Validation Metrics Test

Runs the actual IDS pipeline with real attacker data and captures
real validation metrics showing how the IDS performs against actual attacks.

This test:
1. Starts the full IDS pipeline (CNN, RNN, Decoder)
2. Runs the attack engine with real attack profiles
3. Captures real IDS decisions
4. Validates against ground truth from attacker
5. Reports real metrics
"""
import sys
import os
import time
import threading
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from event_bus import EventBus
from cnn.cnn_engine import CNNEngine
from rnn.rnn_engine import RNNEngine
from decoder.decoder_engine import HybridDecoder
from decoder.mutation_predictor import MutationAwareDecoder
from database.db_engine import DatabaseEngine
from validation.training_validator import TrainingValidator
from attacker.attack_engine import AttackEngine
from datetime import datetime


class LiveValidationTest:
    """Run live validation with real attacker data."""
    
    def __init__(self, duration_seconds: int = 30):
        self.duration = duration_seconds
        self.bus = EventBus()
        self.db = DatabaseEngine(self.bus)
        self.cnn = CNNEngine(self.bus)
        self.rnn = RNNEngine(self.bus)
        base_decoder = HybridDecoder(self.db)
        self.decoder = MutationAwareDecoder(base_decoder, self.db)
        self.validator = TrainingValidator(self.bus, db=self.db)
        self.attacker = None
        self.running = False
        self.events_processed = 0
        self.start_time = None
    
    def setup_pipeline(self):
        """Setup the IDS pipeline."""
        print("\n" + "="*70)
        print("SETTING UP IDS PIPELINE")
        print("="*70)
        
        # Background task: export signatures and update dashboard
        def _bg_tasks():
            while self.running:
                time.sleep(5.0)
                try:
                    count = self.db.export_ids_signatures()
                    stats = self.db.get_stats()
                    print(f"[bg_tasks] Exported {count} signatures, "
                          f"DB size: {self.db.memory.total_size()}")
                except Exception as e:
                    if "cannot schedule new futures" not in str(e):
                        print(f"[bg_tasks] {e}")
        
        threading.Thread(target=_bg_tasks, daemon=True, name="bg-tasks").start()
        
        # Main event handler
        def on_network_event(ev):
            self.events_processed += 1
            fid = ev.get("frame_id", 0)
            meta = ev.get("metadata", {})
            
            # Process through pipeline
            cnn_out = self.cnn.process_event(ev)
            rnn_out = self.rnn.process_features(cnn_out)
            db_mem = self.db.retrieve_memory(
                embedding=cnn_out["feature_vector"],
                source=ev.get("source", ""),
                destination=ev.get("destination", ""),
                port_dst=cnn_out.get("port_dst", 0),
                frame_id=fid,
            )
            
            # Decode with mutation awareness
            dec_out = self.decoder.decode_with_mutation_awareness(
                cnn_out, rnn_out, db_mem["retrieved"], metadata=meta
            )
            dec_out["feature_vector"] = cnn_out["feature_vector"]
            dec_out["entropy"] = cnn_out.get("entropy", 0.0)
            dec_out["rate_hz"] = cnn_out.get("rate_hz", 0.0)
            dec_out["port_dst"] = cnn_out.get("port_dst", 0)
            dec_out["protocol"] = cnn_out.get("protocol", 0)
            dec_out["flags"] = cnn_out.get("flags", 0)
            
            # Log prediction
            self.db.log_prediction(dec_out)
            
            # VALIDATE: Check if decision is correct
            if self.validator and meta.get("is_attack") is not None:
                self.validator.validate_and_correct({
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
        
        # Frame counter
        _counter = [0]
        def on_network_event_counted(ev):
            _counter[0] += 1
            ev["frame_id"] = _counter[0]
            on_network_event(ev)
        
        self.bus.subscribe("network_event", on_network_event_counted)
        print("[pipeline] Event handler registered")
    
    def start_attacker(self):
        """Start the attack engine."""
        print("\n" + "="*70)
        print("STARTING ATTACK ENGINE")
        print("="*70)
        
        self.attacker = AttackEngine(
            self.bus,
            synthetic_targets=True,
            rate_limit=0.1,  # 10 attacks per second
            evolve_interval=50,
            on_status=lambda m: print(f"[attacker] {m}")
        )
        self.attacker.start()
        print("[attacker] Attack engine started")
    
    def run_test(self):
        """Run the live validation test."""
        print("\n" + "="*70)
        print(f"RUNNING LIVE VALIDATION TEST ({self.duration}s)")
        print("="*70)
        
        self.running = True
        self.start_time = time.time()
        
        # Run for specified duration
        while time.time() - self.start_time < self.duration:
            elapsed = time.time() - self.start_time
            metrics = self.validator.get_metrics()
            
            if self.events_processed > 0 and self.events_processed % 50 == 0:
                print(f"\n[{elapsed:.1f}s] Events: {self.events_processed} | "
                      f"TP: {metrics['true_positives']} | "
                      f"FN: {metrics['false_negatives']} | "
                      f"FP: {metrics['false_positives']} | "
                      f"Accuracy: {metrics['accuracy']:.2%}")
            
            time.sleep(0.5)
        
        self.running = False
        print(f"\n[test] Test completed after {time.time() - self.start_time:.1f}s")
    
    def stop_attacker(self):
        """Stop the attack engine."""
        if self.attacker:
            self.attacker.stop()
            print("[attacker] Attack engine stopped")
    
    def print_results(self):
        """Print final validation results."""
        print("\n" + "="*70)
        print("LIVE VALIDATION RESULTS")
        print("="*70)
        
        metrics = self.validator.get_metrics()
        attacker_stats = self.attacker.stats if self.attacker else {}
        
        print(f"\nAttack Session Statistics:")
        print(f"  Total Attacks Sent: {attacker_stats.get('total_sent', 0)}")
        print(f"  Attacks Blocked: {attacker_stats.get('total_blocked', 0)}")
        print(f"  Attacks Evaded: {attacker_stats.get('total_evaded', 0)}")
        print(f"  Attacks Alerted: {attacker_stats.get('total_alerted', 0)}")
        print(f"  Generations: {attacker_stats.get('generation', 0)}")
        
        print(f"\nValidation Metrics:")
        print(f"  Total Events Validated: {metrics['total_events']}")
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
        
        print(f"\nDatabase Corrections:")
        print(f"  Total Corrections: {self.validator.corrections_made}")
        print(f"  FN Corrections: {self.validator.fn_corrections}")
        print(f"  FP Corrections: {self.validator.fp_corrections}")
        
        print(f"\nDatabase State:")
        print(f"  Total Records: {self.db.memory.total_size()}")
        
        # Calculate evasion rate
        total_sent = attacker_stats.get('total_sent', 1)
        evaded = attacker_stats.get('total_evaded', 0)
        evasion_rate = (evaded / total_sent * 100) if total_sent > 0 else 0
        
        print(f"\nEvasion Analysis:")
        print(f"  Evasion Rate: {evasion_rate:.1f}%")
        print(f"  Detection Rate: {100 - evasion_rate:.1f}%")
        
        # Correlation analysis
        print(f"\nCorrelation Analysis:")
        print(f"  Attacks Sent: {total_sent}")
        print(f"  Events Validated: {metrics['total_events']}")
        print(f"  Validation Coverage: {metrics['total_events'] / max(total_sent, 1) * 100:.1f}%")
        
        print(f"\n" + "="*70)
        
        return metrics
    
    def save_results(self):
        """Save results to file."""
        metrics = self.validator.get_metrics()
        attacker_stats = self.attacker.stats if self.attacker else {}
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": self.duration,
            "attacker_stats": attacker_stats,
            "validation_metrics": metrics,
            "corrections": {
                "total": self.validator.corrections_made,
                "fn_corrections": self.validator.fn_corrections,
                "fp_corrections": self.validator.fp_corrections,
            },
            "database": {
                "total_records": self.db.memory.total_size(),
            }
        }
        
        output_file = "validation/live_validation_results.json"
        os.makedirs("validation", exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[results] Saved to {output_file}")
        return output_file


def main():
    """Run the live validation test."""
    
    # Create test instance
    test = LiveValidationTest(duration_seconds=60)  # Run for 60 seconds
    
    try:
        # Setup pipeline
        test.setup_pipeline()
        
        # Start attacker
        test.start_attacker()
        
        # Run test
        test.run_test()
        
        # Stop attacker
        test.stop_attacker()
        
        # Print results
        metrics = test.print_results()
        
        # Save results
        test.save_results()
        
        # Exit with success
        return 0 if metrics['total_events'] > 0 else 1
    
    except KeyboardInterrupt:
        print("\n[test] Interrupted by user")
        test.stop_attacker()
        test.print_results()
        test.save_results()
        return 0
    
    except Exception as e:
        print(f"\n[ERROR] Live validation test failed: {e}")
        import traceback
        traceback.print_exc()
        test.stop_attacker()
        return 1


if __name__ == "__main__":
    sys.exit(main())
