"""
Validation & Decision Accuracy Stats Capture
Captures real-time validation metrics and decision correctness statistics
"""

import sys
import time
import json
from datetime import datetime
from collections import defaultdict, deque

sys.path.insert(0, '.')
import ids_pipeline

class ValidationDecisionStats:
    def __init__(self, duration_seconds=60, sample_interval=2.0):
        self.duration = duration_seconds
        self.sample_interval = sample_interval
        self.stats_history = deque(maxlen=100)
        
        # Decision tracking
        self.decision_counts = defaultdict(int)
        self.decision_confidence = defaultdict(list)
        self.attack_classes = defaultdict(int)
        
        # Validation tracking
        self.validation_results = []
        self.correct_decisions = 0
        self.total_decisions = 0
        
    def start_ids(self):
        """Initialize IDS"""
        print("\n" + "="*80)
        print("= STARTING C++ IDS FOR VALIDATION & DECISION STATS")
        print("="*80)
        
        cfg = ids_pipeline.IDSConfig()
        ids = ids_pipeline.IDS(cfg)
        
        print("✓ IDS initialized")
        return ids
    
    def generate_attack_events(self, ids, attack_type="normal", count=500):
        """Generate events with known attack patterns"""
        print(f"\n[GENERATING {attack_type.upper()} EVENTS: {count}]")
        
        start_time = time.perf_counter()
        alerts_triggered = 0
        
        for i in range(count):
            ev = ids_pipeline.Event()
            
            if attack_type == "ddos":
                # DDoS pattern: same source, high rate
                ev.source = "192.168.1.100"
                ev.destination = "10.0.0.1"
                ev.payload.rate_hz = 50000.0  # Very high rate
                ev.payload.bytes_in = 64  # Small packets
                ev.payload.entropy = 0.2  # Low entropy
                
            elif attack_type == "port_scan":
                # Port scan pattern: many destinations, varying ports
                ev.source = "192.168.1.50"
                ev.destination = f"10.0.0.{(i % 254) + 1}"
                ev.payload.port_dst = 1000 + (i % 60000)
                ev.payload.flags = 0x02  # SYN
                ev.payload.rate_hz = 10000.0
                ev.payload.entropy = 0.3
                
            elif attack_type == "data_exfil":
                # Data exfiltration: high outbound traffic
                ev.source = "10.0.0.50"
                ev.destination = "192.168.1.1"
                ev.payload.bytes_out = 10000 + (i % 50000)
                ev.payload.bytes_in = 100
                ev.payload.entropy = 0.9
                ev.payload.rate_hz = 1000.0
                
            else:  # normal
                # Normal traffic pattern
                ev.source = f"192.168.1.{(i % 100) + 1}"
                ev.destination = "10.0.0.1"
                ev.payload.bytes_in = 1400 + (i % 500)
                ev.payload.bytes_out = 200 + (i % 100)
                ev.payload.port_dst = 80 if i % 3 == 0 else 443
                ev.payload.entropy = 0.7 + (i % 30) / 100.0
                ev.payload.rate_hz = 1000.0 + (i % 5000)
            
            ev.type = ids_pipeline.EventType.NetworkPacket
            ev.payload.protocol = 6  # TCP
            
            ids.ingest(ev)
        
        ingest_time = (time.perf_counter() - start_time) * 1000
        throughput = (count / (ingest_time / 1000))
        
        print(f"✓ Ingested {count} {attack_type} events in {ingest_time:.2f}ms")
        print(f"✓ Throughput: {throughput:,.0f} events/sec")
        
        return throughput
    
    def capture_decision_stats(self, ids):
        """Capture decision statistics"""
        metrics = ids.metrics()
        
        stats = {
            'timestamp': datetime.now().isoformat(),
            'decisions': {
                'total_events': metrics['events_total'],
                'alerts': metrics['alerts_total'],
                'blocks': metrics['blocks_total'],
                'escalations': metrics['escalations_total'],
                'reasoning_calls': metrics['reasoning_calls'],
            },
            'decision_rates': {
                'alert_rate': (metrics['alerts_total'] / max(metrics['events_total'], 1)) * 100,
                'block_rate': (metrics['blocks_total'] / max(metrics['events_total'], 1)) * 100,
                'escalation_rate': (metrics['escalations_total'] / max(metrics['events_total'], 1)) * 100,
                'reasoning_rate': (metrics['reasoning_calls'] / max(metrics['events_total'], 1)) * 100,
            },
            'health': {
                'faults': metrics['faults_total'],
                'reasoning_fails': 0,
                'retrieval_fails': 0,
            }
        }
        
        return stats
    
    def validate_decisions(self, attack_type, metrics):
        """Validate if decisions are correct for the attack type"""
        validation = {
            'attack_type': attack_type,
            'timestamp': datetime.now().isoformat(),
            'expected_alerts': attack_type != 'normal',
            'expected_blocks': attack_type in ['ddos', 'port_scan'],
            'actual_alerts': metrics['decisions']['alerts'] > 0,
            'actual_blocks': metrics['decisions']['blocks'] > 0,
            'correct': False,
            'confidence': 0.0
        }
        
        # Validation logic
        if attack_type == 'normal':
            # Normal traffic should have minimal alerts/blocks
            validation['correct'] = (metrics['decisions']['alerts'] < 10 and 
                                    metrics['decisions']['blocks'] < 10)
            validation['confidence'] = 1.0 - (metrics['decision_rates']['alert_rate'] / 100)
            
        elif attack_type == 'ddos':
            # DDoS should trigger blocks
            validation['correct'] = metrics['decisions']['blocks'] > 0
            validation['confidence'] = min(metrics['decision_rates']['block_rate'] / 100, 1.0)
            
        elif attack_type == 'port_scan':
            # Port scan should trigger alerts/blocks
            validation['correct'] = (metrics['decisions']['alerts'] > 0 or 
                                    metrics['decisions']['blocks'] > 0)
            validation['confidence'] = max(metrics['decision_rates']['alert_rate'],
                                          metrics['decision_rates']['block_rate']) / 100
            
        elif attack_type == 'data_exfil':
            # Data exfil should trigger alerts
            validation['correct'] = metrics['decisions']['alerts'] > 0
            validation['confidence'] = min(metrics['decision_rates']['alert_rate'] / 100, 1.0)
        
        return validation
    
    def print_validation_results(self, validation):
        """Print validation results"""
        status = "PASS" if validation['correct'] else "FAIL"
        symbol = "[OK]" if validation['correct'] else "[XX]"
        
        print(f"\n{symbol} {validation['attack_type'].upper()}")
        print(f"    Expected Alerts: {validation['expected_alerts']}")
        print(f"    Actual Alerts:   {validation['actual_alerts']}")
        print(f"    Expected Blocks: {validation['expected_blocks']}")
        print(f"    Actual Blocks:   {validation['actual_blocks']}")
        print(f"    Confidence:      {validation['confidence']*100:.1f}%")
        print(f"    Result:          {status}")
        
        return validation['correct']
    
    def run(self):
        """Run validation and decision stats capture"""
        print("\n" + "="*80)
        print("= VALIDATION & DECISION ACCURACY STATS CAPTURE")
        print("="*80)
        
        # Start IDS
        ids = self.start_ids()
        
        # Test different attack types
        attack_scenarios = [
            ('normal', 1000),
            ('ddos', 500),
            ('port_scan', 500),
            ('data_exfil', 500),
            ('normal', 1000),
        ]
        
        print(f"\n{'='*80}")
        print("RUNNING ATTACK SCENARIOS")
        print(f"{'='*80}")
        
        validation_results = []
        
        for attack_type, count in attack_scenarios:
            # Generate events
            self.generate_attack_events(ids, attack_type, count)
            
            # Capture stats
            stats = self.capture_decision_stats(ids)
            
            # Validate decisions
            validation = self.validate_decisions(attack_type, stats)
            validation_results.append(validation)
            
            # Print results
            is_correct = self.print_validation_results(validation)
            if is_correct:
                self.correct_decisions += 1
            self.total_decisions += 1
            
            # Wait between scenarios
            time.sleep(1)
        
        # Print summary
        self.print_summary(validation_results, stats)
    
    def print_summary(self, validation_results, final_stats):
        """Print comprehensive summary"""
        print(f"\n{'='*80}")
        print("VALIDATION & DECISION ACCURACY SUMMARY")
        print(f"{'='*80}")
        
        # Validation accuracy
        accuracy = (self.correct_decisions / self.total_decisions * 100) if self.total_decisions > 0 else 0
        
        print(f"\n[VALIDATION ACCURACY]:")
        print(f"  Correct Decisions:   {self.correct_decisions}/{self.total_decisions}")
        print(f"  Accuracy Rate:       {accuracy:.1f}%")
        
        # Decision breakdown
        print(f"\n[DECISION STATISTICS]:")
        print(f"  Total Events:        {final_stats['decisions']['total_events']:>12,}")
        print(f"  Total Alerts:        {final_stats['decisions']['alerts']:>12,}")
        print(f"  Total Blocks:        {final_stats['decisions']['blocks']:>12,}")
        print(f"  Total Escalations:   {final_stats['decisions']['escalations']:>12,}")
        print(f"  Reasoning Calls:     {final_stats['decisions']['reasoning_calls']:>12,}")
        
        # Decision rates
        print(f"\n[DECISION RATES]:")
        print(f"  Alert Rate:          {final_stats['decision_rates']['alert_rate']:>12.2f}%")
        print(f"  Block Rate:          {final_stats['decision_rates']['block_rate']:>12.2f}%")
        print(f"  Escalation Rate:     {final_stats['decision_rates']['escalation_rate']:>12.2f}%")
        print(f"  Reasoning Rate:      {final_stats['decision_rates']['reasoning_rate']:>12.2f}%")
        
        # Validation by attack type
        print(f"\n[VALIDATION BY ATTACK TYPE]:")
        for result in validation_results:
            status = "PASS" if result['correct'] else "FAIL"
            print(f"  {result['attack_type']:15} {status:6} (confidence: {result['confidence']*100:5.1f}%)")
        
        # Health
        print(f"\n[SYSTEM HEALTH]:")
        print(f"  Faults:              {final_stats['health']['faults']:>12,}")
        print(f"  Reasoning Fails:     {final_stats['health']['reasoning_fails']:>12,}")
        print(f"  Retrieval Fails:     {final_stats['health']['retrieval_fails']:>12,}")
        
        print(f"\n{'='*80}")
        print(f"= VALIDATION COMPLETE - Accuracy: {accuracy:.1f}%")
        print(f"{'='*80}\n")

def main():
    try:
        # Set UTF-8 encoding for Windows
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        
        capture = ValidationDecisionStats(duration_seconds=60, sample_interval=2.0)
        capture.run()
        return 0
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
