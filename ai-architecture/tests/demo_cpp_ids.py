#!/usr/bin/env python3
"""
C++ IDS Demo - Shows the system detecting attacks
"""

import sys
sys.path.insert(0, '.')

import ids_pipeline as cpp
import time

print("=" * 60)
print("C++ IDS - Attack Detection Demo")
print("=" * 60)

# Create IDS instance
cfg = cpp.IDSConfig()
cfg.thresholds.alert_threshold = 0.60
cfg.thresholds.block_threshold = 0.85

ids = cpp.IDS(cfg)

# Track alerts
alerts = []

def on_alert(alert):
    alerts.append(alert)
    print(f"\n🚨 ALERT DETECTED!")
    print(f"   Source: {alert.source}")
    print(f"   Destination: {alert.destination}")
    print(f"   Attack Class: {alert.attack_class}")
    print(f"   Confidence: {alert.confidence:.2%}")
    print(f"   Decision: {cpp.decision_name(alert.decision)}")

ids.on_alert(on_alert)

print("\n[*] Simulating normal traffic...")
for i in range(5):
    ev = cpp.Event()
    ev.source = f"192.168.1.{100 + i}"
    ev.destination = "10.0.0.1"
    ev.type = cpp.EventType.NetworkPacket
    ev.payload.bytes_in = 1000
    ev.payload.bytes_out = 500
    ev.payload.port_dst = 80
    ev.payload.protocol = 6
    ev.payload.entropy = 0.3
    ev.payload.rate_hz = 100.0
    
    state = ids.ingest(ev)
    print(f"    Event {i+1}: anomaly={state.local.anomaly_score:.3f}")

print("\n[*] Simulating DoS attack...")
for i in range(10):
    ev = cpp.Event()
    ev.source = "192.168.1.200"
    ev.destination = "10.0.0.1"
    ev.type = cpp.EventType.NetworkPacket
    ev.payload.bytes_in = 10000 + i * 1000
    ev.payload.bytes_out = 100
    ev.payload.port_dst = 80
    ev.payload.protocol = 6
    ev.payload.entropy = 0.95
    ev.payload.rate_hz = 50000.0 + i * 5000
    
    state = ids.ingest(ev)
    print(f"    Event {i+1}: anomaly={state.local.anomaly_score:.3f}, drift={state.global_.drift_score:.3f}")

print("\n[*] Simulating port scan...")
for i in range(8):
    ev = cpp.Event()
    ev.source = "192.168.1.150"
    ev.destination = "10.0.0.1"
    ev.type = cpp.EventType.NetworkPacket
    ev.payload.bytes_in = 100
    ev.payload.bytes_out = 50
    ev.payload.port_dst = 1000 + i * 100
    ev.payload.protocol = 6
    ev.payload.entropy = 0.8
    ev.payload.rate_hz = 1000.0
    
    state = ids.ingest(ev)
    print(f"    Event {i+1}: anomaly={state.local.anomaly_score:.3f}")

# Show results
print("\n" + "=" * 60)
print("Results")
print("=" * 60)

metrics = ids.metrics()
print(f"\nMetrics:")
print(f"  Total events: {metrics['events_total']}")
print(f"  Alerts: {metrics['alerts_total']}")
print(f"  Blocks: {metrics['blocks_total']}")
print(f"  Reasoning calls: {metrics['reasoning_calls']}")

latency = ids.latency_stats()
print(f"\nLatency:")
print(f"  Average: {latency['total_avg_us']:.1f} µs")
print(f"  P99: {latency['total_p99_us']:.1f} µs")

health = ids.health()
print(f"\nHealth:")
print(f"  Panic mode: {health['panic_mode']}")
print(f"  Faults: {health['numeric_faults']}")

print(f"\nDetected {len(alerts)} attacks")
for i, alert in enumerate(alerts, 1):
    print(f"  {i}. {alert.source} → {alert.destination} ({alert.attack_class})")

print("\n✅ Demo complete!")
