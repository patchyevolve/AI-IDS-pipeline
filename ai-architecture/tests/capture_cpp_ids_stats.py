"""
Real-time C++ IDS Stats Capture
Starts the C++ IDS pipeline and captures live performance metrics
"""

import sys
import time
import json
from datetime import datetime
from collections import deque

sys.path.insert(0, '.')
import ids_pipeline

class RealTimeStatsCapture:
    def __init__(self, duration_seconds=30, sample_interval=1.0):
        self.duration = duration_seconds
        self.sample_interval = sample_interval
        self.stats_history = deque(maxlen=100)
        self.latency_history = deque(maxlen=100)
        
    def start_ids(self):
        """Initialize and start the C++ IDS"""
        print("\n" + "="*80)
        print("STARTING C++ IDS PIPELINE")
        print("="*80)
        
        cfg = ids_pipeline.IDSConfig()
        ids = ids_pipeline.IDS(cfg)
        
        print("✓ IDS initialized")
        print(f"  Config thresholds: {cfg.thresholds.alert_threshold}")
        
        return ids
    
    def generate_test_events(self, ids, count=1000):
        """Generate and ingest test events"""
        print(f"\n{'='*80}")
        print(f"INGESTING {count} TEST EVENTS")
        print(f"{'='*80}")
        
        start_time = time.perf_counter()
        
        for i in range(count):
            ev = ids_pipeline.Event()
            ev.source = f"192.168.1.{(i % 254) + 1}"
            ev.destination = "10.0.0.1"
            ev.type = ids_pipeline.EventType.NetworkPacket
            
            # Vary payload to create realistic patterns
            ev.payload.bytes_in = 1400 + (i % 500)
            ev.payload.bytes_out = 200 + (i % 100)
            ev.payload.port_src = 5000 + (i % 10000)
            ev.payload.port_dst = 80 if i % 3 == 0 else 443
            ev.payload.protocol = 6  # TCP
            ev.payload.flags = 0x02 if i % 5 == 0 else 0x18
            ev.payload.entropy = 0.7 + (i % 30) / 100.0
            ev.payload.rate_hz = 1000.0 + (i % 5000)
            
            ids.ingest(ev)
        
        ingest_time = (time.perf_counter() - start_time) * 1000
        throughput = (count / (ingest_time / 1000))
        
        print(f"✓ Ingested {count} events in {ingest_time:.2f}ms")
        print(f"✓ Throughput: {throughput:,.0f} events/sec")
        
        return throughput
    
    def capture_stats(self, ids):
        """Capture current IDS statistics"""
        metrics = ids.metrics()
        latency = ids.latency_stats()
        health = ids.health()
        
        stats = {
            'timestamp': datetime.now().isoformat(),
            'metrics': {
                'events_total': metrics['events_total'],
                'alerts_total': metrics['alerts_total'],
                'blocks_total': metrics['blocks_total'],
                'escalations_total': metrics['escalations_total'],
                'reasoning_calls': metrics['reasoning_calls'],
                'memory_writes': metrics['memory_writes'],
                'faults_total': metrics['faults_total'],
            },
            'latency_us': {
                'l0_avg': latency['l0_avg_us'],
                'l1_avg': latency['l1_avg_us'],
                'l2_avg': latency['l2_avg_us'],
                'retrieval_avg': latency['retrieval_avg_us'],
                'reasoning_avg': latency['reasoning_avg_us'],
                'total_avg': latency['total_avg_us'],
                'total_p99': latency['total_p99_us'],
            },
            'health': {
                'panic_mode': health['panic_mode'],
                'numeric_faults': health['numeric_faults'],
                'reasoning_fails': health['reasoning_fails'],
                'retrieval_fails': health['retrieval_fails'],
            }
        }
        
        return stats
    
    def print_stats(self, stats, iteration):
        """Pretty print statistics"""
        m = stats['metrics']
        l = stats['latency_us']
        h = stats['health']
        
        print(f"\n{'─'*80}")
        print(f"ITERATION {iteration} - {stats['timestamp']}")
        print(f"{'─'*80}")
        
        print(f"\n[METRICS]:")
        print(f"  Events Processed:    {m['events_total']:>12,}")
        print(f"  Alerts Generated:    {m['alerts_total']:>12,}")
        print(f"  Blocks Triggered:    {m['blocks_total']:>12,}")
        print(f"  Escalations:         {m['escalations_total']:>12,}")
        print(f"  Reasoning Calls:     {m['reasoning_calls']:>12,}")
        print(f"  Memory Writes:       {m['memory_writes']:>12,}")
        print(f"  Faults:              {m['faults_total']:>12,}")
        
        print(f"\n[LATENCY (microseconds)]:")
        print(f"  L0 (Local):          {l['l0_avg']:>12.2f} us")
        print(f"  L1 (Segment):        {l['l1_avg']:>12.2f} us")
        print(f"  L2 (Global):         {l['l2_avg']:>12.2f} us")
        print(f"  Retrieval:           {l['retrieval_avg']:>12.2f} us")
        print(f"  Reasoning:           {l['reasoning_avg']:>12.2f} us")
        print(f"  Total Avg:           {l['total_avg']:>12.2f} us")
        print(f"  Total P99:           {l['total_p99']:>12.2f} us")
        
        print(f"\n[HEALTH]:")
        print(f"  Panic Mode:          {str(h['panic_mode']):>12}")
        print(f"  Numeric Faults:      {h['numeric_faults']:>12,}")
        print(f"  Reasoning Fails:     {h['reasoning_fails']:>12,}")
        print(f"  Retrieval Fails:     {h['retrieval_fails']:>12,}")
        
        # Calculate throughput
        if len(self.stats_history) >= 2:
            prev_events = self.stats_history[-2]['metrics']['events_total']
            curr_events = m['events_total']
            events_delta = curr_events - prev_events
            throughput = events_delta / self.sample_interval
            print(f"\n[THROUGHPUT]:")
            print(f"  Events/sec:          {throughput:>12,.0f}")
        
        self.stats_history.append(stats)
    
    def run(self):
        """Run the real-time stats capture"""
        print("\n" + "="*80)
        print("= C++ IDS REAL-TIME STATS CAPTURE")
        print("="*80)
        
        # Start IDS
        ids = self.start_ids()
        
        # Initial event ingestion
        throughput = self.generate_test_events(ids, count=5000)
        
        # Capture initial stats
        print(f"\n{'='*80}")
        print("CAPTURING REAL-TIME STATISTICS")
        print(f"{'='*80}")
        print(f"Duration: {self.duration} seconds")
        print(f"Sample interval: {self.sample_interval} seconds")
        
        start_time = time.time()
        iteration = 0
        
        while time.time() - start_time < self.duration:
            iteration += 1
            
            # Ingest more events
            self.generate_test_events(ids, count=1000)
            
            # Capture stats
            stats = self.capture_stats(ids)
            self.print_stats(stats, iteration)
            
            # Wait for next sample
            time.sleep(self.sample_interval)
        
        # Final summary
        self.print_summary()
    
    def print_summary(self):
        """Print summary statistics"""
        if not self.stats_history:
            return
        
        print(f"\n{'='*80}")
        print("FINAL SUMMARY")
        print(f"{'='*80}")
        
        first_stats = self.stats_history[0]['metrics']
        last_stats = self.stats_history[-1]['metrics']
        
        total_events = last_stats['events_total'] - first_stats['events_total']
        total_alerts = last_stats['alerts_total'] - first_stats['alerts_total']
        total_blocks = last_stats['blocks_total'] - first_stats['blocks_total']
        
        elapsed = len(self.stats_history) * self.sample_interval
        avg_throughput = total_events / elapsed if elapsed > 0 else 0
        
        print(f"\n[AGGREGATE STATISTICS]:")
        print(f"  Total Events:        {total_events:>12,}")
        print(f"  Total Alerts:        {total_alerts:>12,}")
        print(f"  Total Blocks:        {total_blocks:>12,}")
        print(f"  Avg Throughput:      {avg_throughput:>12,.0f} events/sec")
        print(f"  Alert Rate:          {(total_alerts/total_events*100):>12.2f}%")
        print(f"  Block Rate:          {(total_blocks/total_events*100):>12.2f}%")
        
        # Latency stats
        latencies = [s['latency_us']['total_avg'] for s in self.stats_history]
        if latencies:
            print(f"\n[LATENCY STATISTICS]:")
            print(f"  Min:                 {min(latencies):>12.2f} us")
            print(f"  Max:                 {max(latencies):>12.2f} us")
            print(f"  Avg:                 {sum(latencies)/len(latencies):>12.2f} us")
        
        print(f"\n{'='*80}")
        print(f"= C++ IDS STATS CAPTURE COMPLETE")
        print(f"= Samples collected: {len(self.stats_history)}")
        print(f"{'='*80}")

def main():
    try:
        # Set UTF-8 encoding for Windows
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        
        # Run for 30 seconds with 2-second sample interval
        capture = RealTimeStatsCapture(duration_seconds=30, sample_interval=2.0)
        capture.run()
        return 0
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
