#!/usr/bin/env python3
"""
Quick-start test for C++ IDS pipeline.

Tests:
1. Import and basic initialization
2. Event ingestion
3. Callback firing
4. Metrics collection
5. State persistence
6. Config hot-reload
"""

import sys
import os
import json
import time

# Add ai-architecture to path
sys.path.insert(0, os.path.dirname(__file__))

try:
    import ids_pipeline as cpp
    print("[✓] Successfully imported ids_pipeline (C++ IDS)")
except ImportError as e:
    print(f"[✗] Failed to import ids_pipeline: {e}")
    print("\nPlease build the C++ extension first:")
    print("  cd ai-architecture/cpp")
    print("  python build.py")
    sys.exit(1)

def test_basic_initialization():
    """Test 1: Basic initialization"""
    print("\n[Test 1] Basic Initialization")
    try:
        cfg = cpp.IDSConfig()
        ids = cpp.IDS(cfg)
        print("  [✓] Created IDS instance")
        return ids
    except Exception as e:
        print(f"  [✗] Failed: {e}")
        return None

def test_event_ingestion(ids):
    """Test 2: Event ingestion"""
    print("\n[Test 2] Event Ingestion")
    try:
        # Create event
        ev = cpp.Event()
        ev.source = "192.168.1.100"
        ev.destination = "10.0.0.1"
        ev.type = cpp.EventType.NetworkPacket
        ev.payload.bytes_in = 1400
        ev.payload.bytes_out = 200
        ev.payload.port_dst = 80
        ev.payload.protocol = 6
        ev.payload.entropy = 0.85
        ev.payload.rate_hz = 5000.0
        
        # Ingest
        state = ids.ingest(ev)
        print(f"  [✓] Ingested event")
        print(f"      Anomaly score: {state.local.anomaly_score:.3f}")
        print(f"      Entropy: {state.local.entropy:.3f}")
        print(f"      Drift: {state.global_.drift_score:.3f}")
        return True
    except Exception as e:
        print(f"  [✗] Failed: {e}")
        return False

def test_callbacks(ids):
    """Test 3: Callback firing"""
    print("\n[Test 3] Callback System")
    
    alerts_received = []
    blocks_received = []
    escalations_received = []
    
    def on_alert(alert):
        alerts_received.append(alert)
        print(f"  [→] Alert: {alert.attack_class} ({alert.confidence:.2f})")
    
    def on_block(source):
        blocks_received.append(source)
        print(f"  [→] Block: {source}")
    
    def on_escalate(alert):
        escalations_received.append(alert)
        print(f"  [→] Escalate: {alert.source}")
    
    try:
        ids.on_alert(on_alert)
        ids.on_block(on_block)
        ids.on_escalate(on_escalate)
        print("  [✓] Registered callbacks")
        
        # Generate high-anomaly event to trigger alert
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
            ids.ingest(ev)
        
        print(f"  [✓] Callbacks working (alerts: {len(alerts_received)})")
        return True
    except Exception as e:
        print(f"  [✗] Failed: {e}")
        return False

def test_metrics(ids):
    """Test 4: Metrics collection"""
    print("\n[Test 4] Metrics Collection")
    try:
        metrics = ids.metrics()
        print(f"  [✓] Metrics retrieved:")
        print(f"      Events: {metrics['events_total']}")
        print(f"      Alerts: {metrics['alerts_total']}")
        print(f"      Blocks: {metrics['blocks_total']}")
        print(f"      Reasoning calls: {metrics['reasoning_calls']}")
        print(f"      Faults: {metrics['faults_total']}")
        
        latency = ids.latency_stats()
        print(f"  [✓] Latency stats:")
        print(f"      L0: {latency['l0_avg_us']:.1f} µs")
        print(f"      L1: {latency['l1_avg_us']:.1f} µs")
        print(f"      L2: {latency['l2_avg_us']:.1f} µs")
        print(f"      Total: {latency['total_avg_us']:.1f} µs")
        print(f"      P99: {latency['total_p99_us']:.1f} µs")
        
        health = ids.health()
        print(f"  [✓] Health stats:")
        print(f"      Panic mode: {health['panic_mode']}")
        print(f"      Numeric faults: {health['numeric_faults']}")
        
        return True
    except Exception as e:
        print(f"  [✗] Failed: {e}")
        return False

def test_state_persistence(ids):
    """Test 5: State persistence"""
    print("\n[Test 5] State Persistence")
    try:
        # Save state
        ids.save_state("test_ids_state.bin")
        print("  [✓] Saved state to test_ids_state.bin")
        
        ids.save_config("test_ids_config.json")
        print("  [✓] Saved config to test_ids_config.json")
        
        # Verify files exist
        if os.path.exists("test_ids_state.bin"):
            size = os.path.getsize("test_ids_state.bin")
            print(f"      State file size: {size} bytes")
        
        if os.path.exists("test_ids_config.json"):
            with open("test_ids_config.json") as f:
                cfg = json.load(f)
                print(f"      Config: {cfg}")
        
        # Load state
        ids.load_state("test_ids_state.bin")
        print("  [✓] Loaded state from test_ids_state.bin")
        
        # Cleanup
        os.remove("test_ids_state.bin")
        os.remove("test_ids_config.json")
        
        return True
    except Exception as e:
        print(f"  [✗] Failed: {e}")
        return False

def test_config_hotreload(ids):
    """Test 6: Config hot-reload"""
    print("\n[Test 6] Config Hot-Reload")
    try:
        # Create new config
        new_cfg = cpp.IDSConfig()
        new_cfg.thresholds.alert_threshold = 0.55
        new_cfg.thresholds.block_threshold = 0.80
        
        # Apply
        success = ids.hot_reload_config(new_cfg)
        if success:
            print("  [✓] Config hot-reloaded successfully")
        else:
            print("  [✗] Config validation failed")
            return False
        
        # Verify by ingesting event
        ev = cpp.Event()
        ev.source = "192.168.1.100"
        ev.destination = "10.0.0.1"
        ev.type = cpp.EventType.NetworkPacket
        ev.payload.rate_hz = 1000.0
        ev.payload.entropy = 0.5
        
        state = ids.ingest(ev)
        print(f"  [✓] Event processed with new config")
        
        return True
    except Exception as e:
        print(f"  [✗] Failed: {e}")
        return False

def test_batch_processing(ids):
    """Test 7: Batch processing"""
    print("\n[Test 7] Batch Processing")
    try:
        # Create batch
        events = []
        for i in range(100):
            ev = cpp.Event()
            ev.source = f"192.168.1.{i % 256}"
            ev.destination = "10.0.0.1"
            ev.type = cpp.EventType.NetworkPacket
            ev.payload.bytes_in = 1000 + i
            ev.payload.rate_hz = 1000.0 + i
            ev.payload.entropy = 0.5 + (i % 50) / 100.0
            events.append(ev)
        
        # Process batch
        start = time.time()
        ids.ingest_batch(events)
        elapsed = time.time() - start
        
        throughput = len(events) / elapsed
        print(f"  [✓] Processed {len(events)} events in {elapsed:.3f}s")
        print(f"      Throughput: {throughput:.0f} events/sec")
        
        return True
    except Exception as e:
        print(f"  [✗] Failed: {e}")
        return False

def main():
    """Run all tests"""
    print("=" * 60)
    print("C++ IDS Pipeline - Quick Start Test")
    print("=" * 60)
    
    results = []
    
    # Test 1: Initialization
    ids = test_basic_initialization()
    if not ids:
        print("\n[✗] Cannot continue without IDS instance")
        return 1
    results.append(("Initialization", True))
    
    # Test 2: Event ingestion
    results.append(("Event Ingestion", test_event_ingestion(ids)))
    
    # Test 3: Callbacks
    results.append(("Callbacks", test_callbacks(ids)))
    
    # Test 4: Metrics
    results.append(("Metrics", test_metrics(ids)))
    
    # Test 5: State persistence
    results.append(("State Persistence", test_state_persistence(ids)))
    
    # Test 6: Config hot-reload
    results.append(("Config Hot-Reload", test_config_hotreload(ids)))
    
    # Test 7: Batch processing
    results.append(("Batch Processing", test_batch_processing(ids)))
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n[✓] All tests passed! C++ IDS is ready to use.")
        return 0
    else:
        print(f"\n[✗] {total - passed} test(s) failed.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
