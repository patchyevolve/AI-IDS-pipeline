#!/usr/bin/env python3
"""
Test co-evolution system for 5 minutes.
Runs with validation enabled to verify:
1. Validator detects FN/FP
2. Database is corrected in real-time
3. Decoder reloads patterns immediately
4. FNR/FPR metrics improve
5. Attacker receives feedback and evolves
"""
import sys
import os
import time
import json
import threading
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from event_bus import EventBus
from cnn.cnn_engine import CNNEngine
from rnn.rnn_engine import RNNEngine
from decoder.decoder_engine import HybridDecoder
from decoder.mutation_predictor import MutationAwareDecoder
from database.db_engine import DatabaseEngine
from network.ids_bridge import IDSBridge
from validation.training_validator import TrainingValidator
from attacker.attack_engine import AttackEngine
from visualizer.dashboard import state, lock

# Test configuration
TEST_DURATION_S = 300  # 5 minutes
REPORT_INTERVAL_S = 60  # Report every 60 seconds

class CoEvoTester:
    def __init__(self):
        self.start_time = time.time()
        self.reports = []
        self.running = True
        
    def run(self):
        print("\n" + "="*70)
        print("CO-EVOLUTION SYSTEM TEST - 5 MINUTES")
        print("="*70)
        print(f"Start time: {datetime.now().isoformat()}")
        print(f"Duration: {TEST_DURATION_S} seconds")
        print(f"Report interval: {REPORT_INTERVAL_S} seconds")
        print("="*70 + "\n")
        
        # Initialize system
        bus = EventBus()
        cnn = CNNEngine(bus)
        rnn = RNNEngine(bus)
        db = DatabaseEngine(bus)
        base_decoder = HybridDecoder(bus)
        decoder = MutationAwareDecoder(base_decoder, db)
        
        bridge = IDSBridge(
            event_bus=bus,
            interface="",
            scapy_name="",
            bpf_filter="",
            mode="synthetic",
            on_status=lambda msg: print(f"[bridge] {msg}"),
        )
        
        # Enable validation
        validator = TrainingValidator(bus, db=db, output_dir="validation")
        print("[test] Validation enabled - tracking FN/FP and auto-correcting database\n")
        
        # Start attacker
        attacker = AttackEngine(
            event_bus=bus,
            synthetic_targets=True,
            rate_limit=0.4,
            on_status=lambda msg: print(f"[attacker] {msg}"),
        )
        attacker.start()
        print("[test] Attack engine started\n")
        
        # Start bridge
        bridge.start()
        print("[test] IDS bridge started\n")
        
        # Pipeline
        def on_network_event(ev):
            fid = ev.get("frame_id", 0)
            meta = ev.get("metadata", {})
            
            cnn_out = cnn.process_event(ev)
            rnn_out = rnn.process_features(cnn_out)
            db_mem = db.retrieve_memory(
                embedding=cnn_out["feature_vector"],
                source=ev.get("source", ""),
                destination=ev.get("destination", ""),
                port_dst=cnn_out.get("port_dst", 0),
                frame_id=fid,
            )
            
            # Use mutation-aware decoder
            if isinstance(decoder, MutationAwareDecoder):
                dec_out = decoder.decode_with_mutation_awareness(cnn_out, rnn_out, db_mem["retrieved"], metadata=meta)
            else:
                dec_out = decoder.decode(cnn_out, rnn_out, db_mem["retrieved"], metadata=meta)
            
            dec_out["feature_vector"] = cnn_out["feature_vector"]
            dec_out["entropy"] = cnn_out.get("entropy", 0.0)
            dec_out["rate_hz"] = cnn_out.get("rate_hz", 0.0)
            dec_out["port_dst"] = cnn_out.get("port_dst", 0)
            dec_out["protocol"] = cnn_out.get("protocol", 0)
            dec_out["flags"] = cnn_out.get("flags", 0)
            
            db.log_prediction(dec_out)
            
            # Validate
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
            
            # Send decision to attacker
            predicted = False
            if "mutation_prediction" in dec_out:
                predicted = dec_out["mutation_prediction"]["mutation_scores"]["predicted_mutation_detected"]
            
            bridge.send_decision({
                "source": dec_out.get("source", ""),
                "decision": dec_out["decision"],
                "confidence": dec_out["confidence"],
                "attack_class": dec_out["attack_class"],
                "explanation": dec_out["explanation"],
                "timestamp": dec_out["timestamp"],
                "predicted": predicted,
            })
        
        _counter = [0]
        def on_network_event_counted(ev):
            _counter[0] += 1
            ev["frame_id"] = _counter[0]
            on_network_event(ev)
        
        bus.subscribe("network_event", on_network_event_counted)
        
        # Reporting thread
        def report_loop():
            last_report = time.time()
            while self.running:
                now = time.time()
                if now - last_report >= REPORT_INTERVAL_S:
                    elapsed = now - self.start_time
                    metrics = validator.get_metrics()
                    attacker_stats = attacker.stats
                    db_stats = db.get_stats()
                    
                    report = {
                        "elapsed_s": int(elapsed),
                        "timestamp": datetime.now().isoformat(),
                        "validation": {
                            "total_events": metrics.get("total_events", 0),
                            "accuracy": metrics.get("accuracy", 0),
                            "precision": metrics.get("precision", 0),
                            "recall": metrics.get("recall", 0),
                            "f1_score": metrics.get("f1_score", 0),
                            "fpr": metrics.get("fpr", 0),
                            "fnr": metrics.get("fnr", 0),
                            "true_positives": metrics.get("true_positives", 0),
                            "true_negatives": metrics.get("true_negatives", 0),
                            "false_positives": metrics.get("false_positives", 0),
                            "false_negatives": metrics.get("false_negatives", 0),
                        },
                        "attacker": {
                            "total_sent": attacker_stats.get("total_sent", 0),
                            "total_blocked": attacker_stats.get("total_blocked", 0),
                            "total_evaded": attacker_stats.get("total_evaded", 0),
                            "total_alerted": attacker_stats.get("total_alerted", 0),
                            "generation": attacker_stats.get("generation", 0),
                        },
                        "database": {
                            "total_size": db_stats.get("total", 0),
                            "avg_confidence": db_stats.get("avg_confidence", 0),
                            "threat_count": db_stats.get("threat_count", 0),
                        },
                    }
                    
                    self.reports.append(report)
                    
                    # Print report
                    print(f"\n[REPORT @ {int(elapsed)}s]")
                    print(f"  Validation: {metrics.get('total_events', 0)} events | "
                          f"Accuracy: {metrics.get('accuracy', 0):.2%} | "
                          f"FPR: {metrics.get('fpr', 0):.2%} | "
                          f"FNR: {metrics.get('fnr', 0):.2%}")
                    print(f"  Attacker: sent={attacker_stats.get('total_sent', 0)} | "
                          f"blocked={attacker_stats.get('total_blocked', 0)} | "
                          f"evaded={attacker_stats.get('total_evaded', 0)} | "
                          f"gen={attacker_stats.get('generation', 0)}")
                    print(f"  Database: size={db_stats.get('total', 0)} | "
                          f"avg_conf={db_stats.get('avg_confidence', 0):.3f}")
                    
                    last_report = now
                
                time.sleep(1)
        
        report_thread = threading.Thread(target=report_loop, daemon=True)
        report_thread.start()
        
        # Run for TEST_DURATION_S
        try:
            while time.time() - self.start_time < TEST_DURATION_S:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[test] Interrupted by user")
        
        self.running = False
        
        # Stop everything
        attacker.stop()
        bridge.stop()
        
        # Final report
        print("\n" + "="*70)
        print("FINAL REPORT")
        print("="*70)
        
        final_metrics = validator.get_metrics()
        final_attacker = attacker.stats
        final_db = db.get_stats()
        
        print(f"\nValidation Metrics:")
        print(f"  Total events: {final_metrics.get('total_events', 0)}")
        print(f"  Accuracy: {final_metrics.get('accuracy', 0):.2%}")
        print(f"  Precision: {final_metrics.get('precision', 0):.2%}")
        print(f"  Recall: {final_metrics.get('recall', 0):.2%}")
        print(f"  F1 Score: {final_metrics.get('f1_score', 0):.4f}")
        print(f"  FPR: {final_metrics.get('fpr', 0):.2%}")
        print(f"  FNR: {final_metrics.get('fnr', 0):.2%}")
        print(f"  TP: {final_metrics.get('true_positives', 0)} | "
              f"TN: {final_metrics.get('true_negatives', 0)} | "
              f"FP: {final_metrics.get('false_positives', 0)} | "
              f"FN: {final_metrics.get('false_negatives', 0)}")
        
        print(f"\nAttacker Stats:")
        print(f"  Total sent: {final_attacker.get('total_sent', 0)}")
        print(f"  Blocked: {final_attacker.get('total_blocked', 0)}")
        print(f"  Evaded: {final_attacker.get('total_evaded', 0)}")
        print(f"  Alerted: {final_attacker.get('total_alerted', 0)}")
        print(f"  Generations: {final_attacker.get('generation', 0)}")
        
        print(f"\nDatabase Stats:")
        print(f"  Total size: {final_db.get('total', 0)}")
        print(f"  Avg confidence: {final_db.get('avg_confidence', 0):.3f}")
        print(f"  Threat count: {final_db.get('threat_count', 0)}")
        
        # Save reports
        report_file = "coevo_test_report.json"
        with open(report_file, "w") as f:
            json.dump({
                "test_duration_s": TEST_DURATION_S,
                "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
                "end_time": datetime.now().isoformat(),
                "reports": self.reports,
                "final_metrics": {
                    "validation": final_metrics,
                    "attacker": final_attacker,
                    "database": final_db,
                },
            }, f, indent=2)
        
        print(f"\nReport saved to: {report_file}")
        print("="*70 + "\n")
        
        return self.reports

if __name__ == "__main__":
    tester = CoEvoTester()
    tester.run()
