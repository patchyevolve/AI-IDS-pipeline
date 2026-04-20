#!/usr/bin/env python3
"""
Test script to verify the feedback loop is working correctly.
Run this to diagnose why attacker isn't receiving feedback.
"""
import sys
import os
import json
import time
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

def test_feedback_server_metadata():
    """Test that DecisionFeedbackServer includes metadata with atk_tag"""
    print("\n" + "="*60)
    print("TEST: DecisionFeedbackServer Metadata")
    print("="*60)
    
    feedback_py = Path(_HERE) / "network" / "decision_feedback_server.py"
    with open(feedback_py) as f:
        content = f.read()
    
    checks = [
        ("metadata in JSON", '"metadata":    data.get("metadata"' in content),
        ("atk_tag forwarding", 'Include metadata with atk_tag' in content),
    ]
    
    all_pass = True
    for check_name, result in checks:
        status = "✓" if result else "❌"
        print(f"{status} {check_name}")
        all_pass = all_pass and result
    
    if all_pass:
        print("✓ PASS: Metadata properly forwarded")
    else:
        print("❌ FAIL: Metadata not forwarded")
    
    return all_pass


def test_attack_engine_feedback():
    """Test that AttackEngine properly handles feedback with atk_tag"""
    print("\n" + "="*60)
    print("TEST: AttackEngine Feedback Handling")
    print("="*60)
    
    attack_py = Path(_HERE) / "attacker" / "attack_engine.py"
    with open(attack_py) as f:
        content = f.read()
    
    checks = [
        ("atk_tag extraction", 'atk_tag = (data.get("metadata") or {}).get("atk_tag")' in content),
        ("pending dict lookup", 'profile_name = self._pending.pop(atk_tag, None)' in content),
        ("outcome recording", 'self.mutator.record_outcome(profile_name, decision)' in content),
    ]
    
    all_pass = True
    for check_name, result in checks:
        status = "✓" if result else "❌"
        print(f"{status} {check_name}")
        all_pass = all_pass and result
    
    if all_pass:
        print("✓ PASS: Feedback handling correct")
    else:
        print("❌ FAIL: Feedback handling broken")
    
    return all_pass


def test_attack_log():
    """Check if attack_log.jsonl has decisions"""
    print("\n" + "="*60)
    print("TEST: Attack Log Decisions")
    print("="*60)
    
    attack_log = Path(_HERE) / "attacker" / "attack_log.jsonl"
    
    if not attack_log.exists():
        print("❌ attack_log.jsonl NOT FOUND")
        return False
    
    attack_count = 0
    decisions_count = 0
    
    try:
        with open(attack_log) as f:
            for line in f:
                attack_count += 1
                try:
                    rec = json.loads(line)
                    if "decision" in rec:
                        decisions_count += 1
                except:
                    pass
    except Exception as e:
        print(f"❌ Error reading attack_log.jsonl: {e}")
        return False
    
    print(f"✓ Total attacks: {attack_count}")
    print(f"✓ Attacks with decisions: {decisions_count}")
    
    if decisions_count == 0:
        print("❌ FAIL: No decisions in attack log")
        print("   → Feedback loop not working")
        return False
    
    decision_rate = 100 * decisions_count / attack_count if attack_count > 0 else 0
    print(f"✓ Decision rate: {decision_rate:.1f}%")
    
    if decision_rate < 50:
        print("⚠️  WARNING: Low decision rate")
        print("   → Feedback loop may be intermittent")
        return False
    
    print("✓ PASS: Feedback loop working")
    return True


def test_session_report():
    """Check if session report shows evolution"""
    print("\n" + "="*60)
    print("TEST: Session Report Evolution")
    print("="*60)
    
    session_report = Path(_HERE) / "attacker" / "session_report.json"
    
    if not session_report.exists():
        print("❌ session_report.json NOT FOUND")
        return False
    
    try:
        with open(session_report) as f:
            report = json.load(f)
        
        session = report.get("session", {})
        total_sent = session.get("total_sent", 0)
        total_blocked = session.get("total_blocked", 0)
        total_evaded = session.get("total_evaded", 0)
        generations = session.get("generations", 0)
        
        print(f"✓ Total sent: {total_sent}")
        print(f"✓ Total blocked: {total_blocked}")
        print(f"✓ Total evaded: {total_evaded}")
        print(f"✓ Generations: {generations}")
        
        if total_blocked == 0 and total_evaded == 0:
            print("❌ FAIL: No blocked or evaded attacks")
            print("   → Feedback not being recorded")
            return False
        
        if generations == 0:
            print("⚠️  WARNING: No evolution happening")
            print("   → Population not evolving")
            return False
        
        print("✓ PASS: Evolution working")
        return True
    
    except Exception as e:
        print(f"❌ Error reading session_report.json: {e}")
        return False


def test_database_records():
    """Check if database has records"""
    print("\n" + "="*60)
    print("TEST: Database Records")
    print("="*60)
    
    db_dir = Path(_HERE) / "database"
    refined_file = db_dir / "refined_threats.jsonl"
    
    if not refined_file.exists():
        print("❌ refined_threats.jsonl NOT FOUND")
        return False
    
    record_count = 0
    try:
        with open(refined_file) as f:
            record_count = sum(1 for _ in f)
    except Exception as e:
        print(f"❌ Error reading refined_threats.jsonl: {e}")
        return False
    
    print(f"✓ Database records: {record_count}")
    
    if record_count == 0:
        print("❌ FAIL: No records in database")
        print("   → IDS not logging predictions")
        return False
    
    print("✓ PASS: Database has records")
    return True


def main():
    print("\n" + "="*60)
    print("FEEDBACK LOOP DIAGNOSTIC")
    print("="*60)
    
    results = {
        "Metadata forwarding": test_feedback_server_metadata(),
        "Feedback handling": test_attack_engine_feedback(),
        "Attack log decisions": test_attack_log(),
        "Session evolution": test_session_report(),
        "Database records": test_database_records(),
    }
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    
    for test_name, result in results.items():
        status = "✓ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    all_pass = all(results.values())
    
    print("\n" + "="*60)
    if all_pass:
        print("✓ FEEDBACK LOOP WORKING CORRECTLY")
        print("="*60)
        print("\nExpected behavior:")
        print("- Attacker sends attacks")
        print("- IDS processes and makes decisions")
        print("- Feedback server broadcasts decisions")
        print("- Attacker receives decisions and updates fitness")
        print("- Population evolves based on fitness")
        return 0
    else:
        print("❌ FEEDBACK LOOP HAS ISSUES")
        print("="*60)
        print("\nTroubleshooting:")
        print("1. Verify DecisionFeedbackServer is running on IDS")
        print("2. Check port 9878 is open and listening")
        print("3. Verify metadata is being forwarded")
        print("4. Check attack_log.jsonl for decisions")
        print("5. Review session_report.json for evolution")
        return 1


if __name__ == "__main__":
    sys.exit(main())
