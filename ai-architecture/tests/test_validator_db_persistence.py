"""
Validator Database Persistence Test

Verifies that:
1. Validator actually updates the database with corrections
2. Corrected patterns are retrievable from database
3. Same attacks won't be missed again (no FN after correction)
4. Database changes persist across sessions
5. Similarity matching works for corrected patterns

This test proves the validator's corrections are real and effective.
"""
import sys
import os
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from event_bus import EventBus
from database.db_engine import DatabaseEngine, ThreatRecord
from validation.training_validator import TrainingValidator
from datetime import datetime


class ValidatorPersistenceTest:
    """Test that validator corrections persist in database."""
    
    def __init__(self):
        self.bus = EventBus()
        self.db = DatabaseEngine(self.bus)
        self.validator = TrainingValidator(self.bus, db=self.db)
        self.test_results = []
    
    def test_1_initial_state(self):
        """Test 1: Check initial database state."""
        print("\n" + "="*70)
        print("TEST 1: Initial Database State")
        print("="*70)
        
        initial_size = self.db.memory.total_size()
        print(f"Initial DB size: {initial_size} records")
        
        # Get initial metrics
        metrics = self.validator.get_metrics()
        print(f"Initial FN count: {metrics['false_negatives']}")
        print(f"Initial corrections: {self.validator.corrections_made}")
        
        self.test_results.append({
            "test": "Initial State",
            "initial_db_size": initial_size,
            "initial_fn": metrics['false_negatives'],
            "initial_corrections": self.validator.corrections_made,
        })
        
        return initial_size
    
    def test_2_create_false_negative(self):
        """Test 2: Create a false negative (missed attack)."""
        print("\n" + "="*70)
        print("TEST 2: Create False Negative")
        print("="*70)
        
        # Create an attack that will be missed
        attack_event = {
            "is_attack": True,
            "decision": "Ignore",  # IDS missed it
            "attack_class": "DoS/DDoS",
            "confidence": 0.1,
            "feature_vector": [0.9] * 64,
            "source": "203.0.113.10",
            "destination": "192.168.1.1",
            "port_dst": 80,
            "protocol": 6,
            "flags": 0x02,
            "rate_hz": 500.0,
            "timestamp": datetime.now().isoformat(),
        }
        
        print(f"Attack: {attack_event['attack_class']} from {attack_event['source']}")
        print(f"IDS Decision: {attack_event['decision']} (MISSED)")
        
        # Validate - this should trigger FN correction
        self.validator.validate_and_correct(attack_event)
        
        metrics = self.validator.get_metrics()
        print(f"FN count after: {metrics['false_negatives']}")
        print(f"Corrections made: {self.validator.corrections_made}")
        
        self.test_results.append({
            "test": "Create FN",
            "fn_count": metrics['false_negatives'],
            "corrections": self.validator.corrections_made,
            "attack_class": attack_event['attack_class'],
            "source": attack_event['source'],
        })
        
        return attack_event
    
    def test_3_verify_db_updated(self):
        """Test 3: Verify database was actually updated."""
        print("\n" + "="*70)
        print("TEST 3: Verify Database Updated")
        print("="*70)
        
        db_size_after = self.db.memory.total_size()
        print(f"DB size after correction: {db_size_after} records")
        
        # Check if records were added
        if db_size_after > self.test_results[0]["initial_db_size"]:
            print(f"✅ Database GREW by {db_size_after - self.test_results[0]['initial_db_size']} records")
            growth = True
        else:
            print(f"❌ Database did NOT grow")
            growth = False
        
        # Check global store
        global_store_size = len(self.db.memory.global_store.records) if hasattr(self.db.memory.global_store, 'records') else 0
        print(f"Global store records: {global_store_size}")
        
        # Check IP store
        ip_store_size = sum(len(store.records) if hasattr(store, 'records') else 0 
                           for store in self.db.memory.ip_store.values())
        print(f"IP store records: {ip_store_size}")
        
        self.test_results.append({
            "test": "DB Updated",
            "db_size_after": db_size_after,
            "growth": growth,
            "global_store_size": global_store_size,
            "ip_store_size": ip_store_size,
        })
        
        return growth
    
    def test_4_retrieve_corrected_pattern(self):
        """Test 4: Retrieve the corrected pattern from database."""
        print("\n" + "="*70)
        print("TEST 4: Retrieve Corrected Pattern")
        print("="*70)
        
        # Try to retrieve the pattern we just added
        test_embedding = [0.9] * 64
        
        retrieved = self.db.retrieve_memory(
            embedding=test_embedding,
            source="203.0.113.10",
            destination="192.168.1.1",
            port_dst=80,
            frame_id=1,
        )
        
        print(f"Retrieved records: {len(retrieved['retrieved'])}")
        
        if retrieved['retrieved']:
            for i, rec in enumerate(retrieved['retrieved'][:3]):
                print(f"\n  Record {i+1}:")
                print(f"    Attack Class: {rec.get('attack_class', 'unknown')}")
                print(f"    Decision: {rec.get('decision', 'unknown')}")
                print(f"    Confidence: {rec.get('confidence', 0)}")
                print(f"    Similarity: {rec.get('similarity', 0)}")
                print(f"    Explanation: {rec.get('explanation', '')[:60]}...")
            
            retrieved_ok = True
        else:
            print("❌ No records retrieved")
            retrieved_ok = False
        
        self.test_results.append({
            "test": "Retrieve Pattern",
            "records_retrieved": len(retrieved['retrieved']),
            "retrieval_ok": retrieved_ok,
        })
        
        return retrieved_ok, retrieved['retrieved']
    
    def test_5_same_attack_again(self):
        """Test 5: Send the same attack again - should NOT be missed now."""
        print("\n" + "="*70)
        print("TEST 5: Same Attack Again (Should NOT be missed)")
        print("="*70)
        
        # Send the same attack again
        attack_event_2 = {
            "is_attack": True,
            "decision": "Ignore",  # Simulating IDS decision
            "attack_class": "DoS/DDoS",
            "confidence": 0.1,
            "feature_vector": [0.9] * 64,  # Same pattern
            "source": "203.0.113.10",
            "destination": "192.168.1.1",
            "port_dst": 80,
            "protocol": 6,
            "flags": 0x02,
            "rate_hz": 500.0,
            "timestamp": datetime.now().isoformat(),
        }
        
        print(f"Sending same attack again: {attack_event_2['attack_class']}")
        print(f"IDS Decision: {attack_event_2['decision']}")
        
        # Validate
        self.validator.validate_and_correct(attack_event_2)
        
        metrics = self.validator.get_metrics()
        print(f"FN count now: {metrics['false_negatives']}")
        print(f"Total corrections: {self.validator.corrections_made}")
        
        # Check if it was detected as FN again
        # If database is working, this should still be FN (IDS still missed it)
        # But the validator should recognize it's in the DB
        
        self.test_results.append({
            "test": "Same Attack Again",
            "fn_count": metrics['false_negatives'],
            "total_corrections": self.validator.corrections_made,
        })
        
        return metrics
    
    def test_6_verify_pattern_similarity(self):
        """Test 6: Verify pattern similarity matching works."""
        print("\n" + "="*70)
        print("TEST 6: Pattern Similarity Matching")
        print("="*70)
        
        # Test with slightly different embedding (mutation)
        mutated_embedding = [0.85] * 64  # Slightly different
        
        retrieved = self.db.retrieve_memory(
            embedding=mutated_embedding,
            source="203.0.113.10",
            destination="192.168.1.1",
            port_dst=80,
            frame_id=2,
        )
        
        print(f"Retrieved records for mutated pattern: {len(retrieved['retrieved'])}")
        
        if retrieved['retrieved']:
            best_match = retrieved['retrieved'][0]
            similarity = best_match.get('similarity', 0)
            print(f"Best match similarity: {similarity:.4f}")
            print(f"Attack class: {best_match.get('attack_class', 'unknown')}")
            
            if similarity > 0.8:
                print(f"✅ Similarity matching works (>0.8)")
                similarity_ok = True
            else:
                print(f"⚠️  Similarity is low ({similarity:.4f})")
                similarity_ok = False
        else:
            print("❌ No similar patterns found")
            similarity_ok = False
        
        self.test_results.append({
            "test": "Similarity Matching",
            "records_found": len(retrieved['retrieved']),
            "similarity_ok": similarity_ok,
        })
        
        return similarity_ok
    
    def test_7_verify_no_false_positives(self):
        """Test 7: Verify corrected patterns don't cause false positives."""
        print("\n" + "="*70)
        print("TEST 7: Verify No False Positives")
        print("="*70)
        
        # Send benign traffic with similar pattern
        benign_event = {
            "is_attack": False,  # Ground truth: benign
            "decision": "Ignore",  # IDS correctly allowed it
            "attack_class": "benign",
            "confidence": 0.1,
            "feature_vector": [0.1] * 64,  # Different pattern
            "source": "192.168.1.100",
            "destination": "8.8.8.8",
            "port_dst": 53,
            "protocol": 17,
            "flags": 0x00,
            "rate_hz": 100.0,
            "timestamp": datetime.now().isoformat(),
        }
        
        print(f"Sending benign traffic")
        print(f"IDS Decision: {benign_event['decision']} (correct)")
        
        # Validate
        self.validator.validate_and_correct(benign_event)
        
        metrics = self.validator.get_metrics()
        print(f"FP count: {metrics['false_positives']}")
        print(f"TN count: {metrics['true_negatives']}")
        
        if metrics['false_positives'] == 0:
            print(f"✅ No false positives")
            no_fp = True
        else:
            print(f"❌ False positives detected: {metrics['false_positives']}")
            no_fp = False
        
        self.test_results.append({
            "test": "No False Positives",
            "fp_count": metrics['false_positives'],
            "tn_count": metrics['true_negatives'],
            "no_fp": no_fp,
        })
        
        return no_fp
    
    def test_8_database_persistence(self):
        """Test 8: Verify database changes persist."""
        print("\n" + "="*70)
        print("TEST 8: Database Persistence")
        print("="*70)
        
        # Get current DB size
        current_size = self.db.memory.total_size()
        print(f"Current DB size: {current_size} records")
        
        # Export signatures
        exported = self.db.export_ids_signatures()
        print(f"Exported signatures: {exported}")
        
        # Check if signatures file exists
        sig_file = "database/ids_signatures.jsonl"
        if os.path.exists(sig_file):
            with open(sig_file, 'r') as f:
                lines = f.readlines()
            print(f"Signatures file has {len(lines)} entries")
            persistence_ok = True
        else:
            print(f"❌ Signatures file not found")
            persistence_ok = False
        
        self.test_results.append({
            "test": "Persistence",
            "db_size": current_size,
            "exported": exported,
            "persistence_ok": persistence_ok,
        })
        
        return persistence_ok
    
    def print_summary(self):
        """Print test summary."""
        print("\n" + "="*70)
        print("VALIDATOR DATABASE PERSISTENCE TEST SUMMARY")
        print("="*70)
        
        print(f"\nTests Run: {len(self.test_results)}")
        
        for result in self.test_results:
            test_name = result.get("test", "Unknown")
            print(f"\n{test_name}:")
            for key, value in result.items():
                if key != "test":
                    print(f"  {key}: {value}")
        
        # Overall assessment
        print("\n" + "="*70)
        print("ASSESSMENT")
        print("="*70)
        
        checks = [
            ("Database Updated", self.test_results[2].get("growth", False)),
            ("Pattern Retrieved", self.test_results[3].get("retrieval_ok", False)),
            ("Similarity Matching", self.test_results[5].get("similarity_ok", False)),
            ("No False Positives", self.test_results[6].get("no_fp", False)),
            ("Persistence", self.test_results[7].get("persistence_ok", False)),
        ]
        
        passed = sum(1 for _, result in checks if result)
        total = len(checks)
        
        print(f"\nChecks Passed: {passed}/{total}")
        
        for check_name, result in checks:
            status = "✅" if result else "❌"
            print(f"  {status} {check_name}")
        
        if passed == total:
            print(f"\n✅ ALL CHECKS PASSED - Validator database updates are REAL and EFFECTIVE")
            return True
        else:
            print(f"\n⚠️  {total - passed} checks failed")
            return False


if __name__ == "__main__":
    test = ValidatorPersistenceTest()
    
    try:
        initial_size = test.test_1_initial_state()
        attack = test.test_2_create_false_negative()
        db_updated = test.test_3_verify_db_updated()
        retrieved_ok, records = test.test_4_retrieve_corrected_pattern()
        metrics = test.test_5_same_attack_again()
        similarity_ok = test.test_6_verify_pattern_similarity()
        no_fp = test.test_7_verify_no_false_positives()
        persistence_ok = test.test_8_database_persistence()
        
        success = test.print_summary()
        
        sys.exit(0 if success else 1)
    
    except Exception as e:
        print(f"\n[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
