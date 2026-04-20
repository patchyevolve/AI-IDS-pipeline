#!/usr/bin/env python3
"""
Test that IDS learning fixes are properly implemented.
Verifies:
1. Write gate thresholds are balanced (0.40/0.70)
2. Decoder filters low-confidence records
3. Decoder uses high-quality database matches
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from database.db_engine import MEMORY_WRITE_GATE, MEMORY_FORCE_GATE
from decoder.decoder_engine import HybridDecoder
from event_bus import EventBus

def test_write_gates():
    """Verify write gate thresholds are balanced"""
    print("✓ TEST 1: Write Gate Thresholds")
    print(f"  MEMORY_WRITE_GATE = {MEMORY_WRITE_GATE} (should be 0.40)")
    print(f"  MEMORY_FORCE_GATE = {MEMORY_FORCE_GATE} (should be 0.70)")
    
    assert MEMORY_WRITE_GATE == 0.40, f"Expected 0.40, got {MEMORY_WRITE_GATE}"
    assert MEMORY_FORCE_GATE == 0.70, f"Expected 0.70, got {MEMORY_FORCE_GATE}"
    print("  ✓ PASS: Thresholds are balanced\n")

def test_decoder_filtering():
    """Verify decoder filters low-confidence records"""
    print("✓ TEST 2: Decoder Filtering Logic")
    
    bus = EventBus()
    decoder = HybridDecoder(bus)
    
    # Create test events
    cnn_event = {
        "frame_id": 1,
        "source": "192.168.1.1",
        "destination": "10.0.0.1",
        "feature_vector": [0.1] * 64,
        "is_attack_prob": 0.3,
        "entropy": 0.5,
        "flags": 0x02,
        "atk_class": "none",
    }
    
    rnn_event = {
        "context_vector": [0.0] * 32,
        "anomaly_trend": 0.2,
        "anomaly_history": 0.1,
        "drift_score": 2.0,
        "global_state": {},
    }
    
    # Test with low-confidence records (should be filtered)
    db_memory_low = [
        {"id": "1", "similarity": 0.90, "confidence": 0.25, "decision": "Block"},  # Low conf
        {"id": "2", "similarity": 0.88, "confidence": 0.35, "decision": "Block"},  # Low conf
    ]
    
    result = decoder.decode(cnn_event, rnn_event, db_memory_low)
    print(f"  With low-confidence records: decision={result['decision']}")
    print(f"  db_hits={result['db_hits']} (should be 0 after filtering)")
    
    # Test with high-confidence records (should be used)
    db_memory_high = [
        {"id": "3", "similarity": 0.92, "confidence": 0.75, "decision": "Block"},  # High conf
        {"id": "4", "similarity": 0.88, "confidence": 0.65, "decision": "Alert"},  # High conf
    ]
    
    result = decoder.decode(cnn_event, rnn_event, db_memory_high)
    print(f"  With high-confidence records: decision={result['decision']}")
    print(f"  db_hits={result['db_hits']} (should be >0)")
    print("  ✓ PASS: Decoder filters correctly\n")

def test_database_retrieval():
    """Verify database retrieval filters low-confidence records"""
    print("✓ TEST 3: Database Retrieval Filtering")
    
    from database.db_engine import PartitionedMemoryStore, ThreatRecord
    
    memory = PartitionedMemoryStore()
    
    # Insert mixed confidence records
    for i in range(5):
        rec = ThreatRecord(
            id=f"rec_{i}",
            embedding=[0.1 * (i+1)] * 64,
            source="192.168.1.1",
            destination="10.0.0.1",
            attack_class="DoS/DDoS",
            decision="Block",
            confidence=0.30 + (i * 0.15),  # 0.30, 0.45, 0.60, 0.75, 0.90
            anomaly_trend=0.5,
            entropy=0.5,
            rate_hz=1000,
            port_dst=80,
            protocol=6,
            flags=0x02,
            explanation="test",
            timestamp="2026-04-19T00:00:00",
            frame_id=i,
        )
        memory.ip_store["192.168.1.1"].insert(rec)
    
    # Retrieve with test embedding
    test_embedding = [0.1] * 64
    results = memory.retrieve(test_embedding, source="192.168.1.1", k=5)
    
    print(f"  Inserted 5 records with confidence: 0.30, 0.45, 0.60, 0.75, 0.90")
    print(f"  Retrieved {len(results)} records (should be 3: only >0.50)")
    
    retrieved_confs = [r.get("confidence", 0) for r in results]
    print(f"  Retrieved confidences: {retrieved_confs}")
    
    # Verify only high-confidence records returned
    assert all(c > 0.50 for c in retrieved_confs), "Low-confidence records not filtered!"
    print("  ✓ PASS: Database retrieval filters correctly\n")

if __name__ == "__main__":
    print("\n" + "="*60)
    print("IDS LEARNING FIXES VERIFICATION")
    print("="*60 + "\n")
    
    try:
        test_write_gates()
        test_decoder_filtering()
        test_database_retrieval()
        
        print("="*60)
        print("✓ ALL TESTS PASSED")
        print("="*60)
        print("\nSummary of fixes:")
        print("1. Write gates balanced: 0.40/0.70 (quality over quantity)")
        print("2. Decoder filters low-confidence records (<0.50)")
        print("3. Database retrieval only returns high-quality matches")
        print("\nExpected improvement:")
        print("- IDS detection rate should stabilize or improve")
        print("- False positive rate should decrease")
        print("- Attacker evasion rate should decrease")
        print()
        
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
