"""
Real Attacker Metrics Test

Captures real validation metrics from actual attacker data
by running the attack engine and validating decisions.

This test shows the REAL performance of the IDS against actual attacks.
"""
import sys
import os
import time
import threading
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from event_bus import EventBus
from database.db_engine import DatabaseEngine
from validation.training_validator import TrainingValidator
from attacker.attack_engine import AttackEngine
from datetime import datetime


class RealAttackerMetricsTest:
    """Capture real metrics from actual attacker."""
    
    def __init__(self, duration_seconds: int = 60):
        self.duration = duration_seconds
        self.bus = EventBus()
        self.db = DatabaseEngine(self.bus)
        self.validator = TrainingValidator(self.bus, db=self.db)
        self.attacker = None
        self.running = False
        self.start_time = None
        self.last_metrics_print = 0
    
    def setup_validation_hook(self):
        """Setup validation to capture real attacker decisions."""
        print("\n" + "="*70)
        print("SETTING UP VALIDATION HOOK")
        print("="*70)
        
        # Subscribe to decoder output to validate decisions
        def on_decoder_output(data):
            # Get metadata with ground truth
            metadata = data.get("metadata", {})
            
            # Only validate if we have ground truth (from attacker)
            if metadata.get("is_attack") is not None:
                self.validator.validate_and_correct({
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
                    "timestamp": data.get("timestamp", ""),
                })
        
        self.bus.subscribe("decoder_output", on_decoder_output)
        print("[validation] Validation hook registered on decoder_output")
    
    def start_attacker(self):
        """Start the attack engine."""
        print("\n" + "="*70)
        print("STARTING ATTACK ENGINE")
        print("="*70)
        
        self.attacker = AttackEngine(
            self.bus,
            synthetic_targets=True,
            rate_limit=0.05,  # 20 attacks per second
            evolve_interval=50,
            on_status=lambda m: print(f"[attacker] {m}")
        )
        self.attacker.start()
        print("[attacker] Attack engine started")
    
    def run_test(self):
        """Run the test."""
        print("\n" + "="*70)
        print(f"RUNNING REAL ATTACKER METRICS TEST ({self.duration}s)")
        print("="*70)
        
        self.running = True
        self.start_time = time.time()
        
        # Run for specified duration
        while time.time() - self.start_time < self.duration:
            elapsed = time.time() - self.start_time
            
            # Print metrics every 10 seconds
            if elapsed - self.last_metrics_print >= 10:
                self.last_metrics_print = elapsed
                metrics = self.validator.get_metrics()
                attacker_stats = self.attacker.stats if self.attacker else {}
                
                if metrics['total_events'] > 0:
                    print(f"\n[{elapsed:.1f}s] REAL-TIME METRICS:")
                    print(f"  Attacks Sent: {attacker_stats.get('total_sent', 0)}")
                    print(f"  Events Validated: {metrics['total_events']}")
                    print(f"  TP: {metrics['true_positives']} | "
                          f"TN: {metrics['true_negatives']} | "
                          f"FP: {metrics['false_positives']} | "
                          f"FN: {metrics['false_negatives']}")
                    print(f"  Accuracy: {metrics['accuracy']:.2%} | "
                          f"Recall: {metrics['recall']:.2%} | "
                          f"Precision: {metrics['precision']:.2%}")
                    print(f"  FNR: {metrics['fnr']:.2%} | FPR: {metrics['fpr']:.2%}")
                    print(f"  Corrections: {self.validator.corrections_made} "
                          f"(FN: {self.validator.fn_corrections}, "
                          f"FP: {self.validator.fp_corrections})")
            
            time.sleep(1)
        
        self.running = False
        print(f"\n[test] Test completed after {time.time() - self.start_time:.1f}s")
    
    def stop_attacker(self):
        """Stop the attack engine."""
        if self.attacker:
            self.attacker.stop()
            print("[attacker] Attack engine stopped")
    
    def print_final_report(self):
        """Print final validation report."""
        print("\n" + "="*70)
        print("REAL ATTACKER VALIDATION REPORT")
        print("="*70)
        
        metrics = self.validator.get_metrics()
        attacker_stats = self.attacker.stats if self.attacker else {}
        
        print(f"\n{'ATTACK SESSION STATISTICS':^70}")
        print("-" * 70)
        print(f"Total Attacks Sent:     {attacker_stats.get('total_sent', 0):>6}")
        print(f"Attacks Blocked:        {attacker_stats.get('total_blocked', 0):>6}")
        print(f"Attacks Evaded:         {attacker_stats.get('total_evaded', 0):>6}")
        print(f"Attacks Alerted:        {attacker_stats.get('total_alerted', 0):>6}")
        print(f"Generations Evolved:    {attacker_stats.get('generation', 0):>6}")
        
        total_sent = attacker_stats.get('total_sent', 1)
        evaded = attacker_stats.get('total_evaded', 0)
        blocked = attacker_stats.get('total_blocked', 0)
        evasion_rate = (evaded / total_sent * 100) if total_sent > 0 else 0
        detection_rate = 100 - evasion_rate
        
        print(f"\nEvasion Rate:           {evasion_rate:>6.1f}%")
        print(f"Detection Rate:         {detection_rate:>6.1f}%")
        
        print(f"\n{'VALIDATION METRICS':^70}")
        print("-" * 70)
        print(f"Total Events Validated: {metrics['total_events']:>6}")
        print(f"True Positives (TP):    {metrics['true_positives']:>6}")
        print(f"True Negatives (TN):    {metrics['true_negatives']:>6}")
        print(f"False Positives (FP):   {metrics['false_positives']:>6}")
        print(f"False Negatives (FN):   {metrics['false_negatives']:>6}")
        
        print(f"\n{'PERFORMANCE METRICS':^70}")
        print("-" * 70)
        print(f"Accuracy:               {metrics['accuracy']:>6.2%}")
        print(f"Precision:              {metrics['precision']:>6.2%}")
        print(f"Recall (Sensitivity):   {metrics['recall']:>6.2%}")
        print(f"F1 Score:               {metrics['f1_score']:>6.4f}")
        
        print(f"\n{'ERROR RATES':^70}")
        print("-" * 70)
        print(f"False Positive Rate:    {metrics['fpr']:>6.2%}")
        print(f"False Negative Rate:    {metrics['fnr']:>6.2%}")
        
        print(f"\n{'DATABASE CORRECTIONS':^70}")
        print("-" * 70)
        print(f"Total Corrections:      {self.validator.corrections_made:>6}")
        print(f"FN Corrections:         {self.validator.fn_corrections:>6}")
        print(f"FP Corrections:         {self.validator.fp_corrections:>6}")
        
        print(f"\n{'DATABASE STATE':^70}")
        print("-" * 70)
        print(f"Total Records:          {self.db.memory.total_size():>6}")
        
        # Analysis
        print(f"\n{'ANALYSIS':^70}")
        print("-" * 70)
        
        if metrics['total_events'] > 0:
            coverage = metrics['total_events'] / max(total_sent, 1) * 100
            print(f"Validation Coverage:    {coverage:>6.1f}%")
            
            if metrics['false_negatives'] > 0:
                print(f"\n⚠️  {metrics['false_negatives']} attacks were MISSED (FN)")
                print(f"   These have been added to the database for learning")
            
            if metrics['false_positives'] > 0:
                print(f"\n⚠️  {metrics['false_positives']} benign events were BLOCKED (FP)")
                print(f"   These have been added to the database for learning")
            
            if metrics['accuracy'] >= 0.9:
                print(f"\n✅ EXCELLENT: {metrics['accuracy']:.1%} accuracy")
            elif metrics['accuracy'] >= 0.8:
                print(f"\n✅ GOOD: {metrics['accuracy']:.1%} accuracy")
            elif metrics['accuracy'] >= 0.7:
                print(f"\n⚠️  FAIR: {metrics['accuracy']:.1%} accuracy")
            else:
                print(f"\n❌ POOR: {metrics['accuracy']:.1%} accuracy")
        
        print("\n" + "="*70)
        
        return metrics


def main():
    """Run the real attacker metrics test."""
    
    test = RealAttackerMetricsTest(duration_seconds=60)
    
    try:
        # Setup validation
        test.setup_validation_hook()
        
        # Start attacker
        test.start_attacker()
        
        # Run test
        test.run_test()
        
        # Stop attacker
        test.stop_attacker()
        
        # Print final report
        metrics = test.print_final_report()
        
        return 0 if metrics['total_events'] > 0 else 1
    
    except KeyboardInterrupt:
        print("\n[test] Interrupted by user")
        test.stop_attacker()
        test.print_final_report()
        return 0
    
    except Exception as e:
        print(f"\n[ERROR] Real attacker metrics test failed: {e}")
        import traceback
        traceback.print_exc()
        test.stop_attacker()
        return 1


if __name__ == "__main__":
    sys.exit(main())
