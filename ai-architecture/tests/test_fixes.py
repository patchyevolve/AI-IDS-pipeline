#!/usr/bin/env python3
"""
Test script to verify all 6 fixes are working correctly.
Run this after implementing the fixes to validate the system.
"""
import sys
import os
import json
import time
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

def test_fix_1_write_gate():
    """Test Fix 1: Lower database write gate threshold"""
    print("\n" + "="*60)
    print("TEST FIX 1: Database Write Gate Threshold")
    print("="*60)
    
    from database.db_engine import MEMORY_WRITE_GATE, MEMORY_FORCE_GATE
    
    print(f"MEMORY_WRITE_GATE: {MEMORY_WRITE_GATE}")
    print(f"MEMORY_FORCE_GATE: {MEMORY_FORCE_GATE}")
    
    if MEMORY_WRITE_GATE == 0.30 and MEMORY_FORCE_GATE == 0.60:
        print("✓ PASS: Write gate thresholds lowered correctly")
        return True
    else:
        print("❌ FAIL: Write gate thresholds not updated")
        print(f"  Expected: MEMORY_WRITE_GATE=0.30, MEMORY_FORCE_GATE=0.60")
        print(f"  Got: MEMORY_WRITE_GATE={MEMORY_WRITE_GATE}, MEMORY_FORCE_GATE={MEMORY_FORCE_GATE}")
        return False


def test_fix_2_feedback_server():
    """Test Fix 2: DecisionFeedbackServer in run.py"""
    print("\n" + "="*60)
    print("TEST FIX 2: DecisionFeedbackServer")
    print("="*60)
    
    run_py = Path(_HERE) / "run.py"
    with open(run_py) as f:
        content = f.read()
    
    checks = [
        ("DecisionFeedbackServer import", "from network.decision_feedback_server import DecisionFeedbackServer" in content),
        ("feedback_server instantiation", "feedback_server = DecisionFeedbackServer" in content),
        ("feedback_server.start()", "feedback_server.start()" in content),
        ("Port 9878", "port=9878" in content),
    ]
    
    all_pass = True
    for check_name, result in checks:
        status = "✓" if result else "❌"
        print(f"{status} {check_name}")
        all_pass = all_pass and result
    
    if all_pass:
        print("✓ PASS: DecisionFeedbackServer properly added")
    else:
        print("❌ FAIL: DecisionFeedbackServer not properly added")
    
    return all_pass


def test_fix_3_decoder_calibration():
    """Test Fix 3: Decoder uses database context"""
    print("\n" + "="*60)
    print("TEST FIX 3: Decoder Calibration")
    print("="*60)
    
    decoder_py = Path(_HERE) / "decoder" / "decoder_engine.py"
    with open(decoder_py) as f:
        content = f.read()
    
    checks = [
        ("db_boost variable", "db_boost = 0.0" in content),
        ("db_decision_override", "db_decision_override = None" in content),
        ("high_sims check", "high_sims = [r for r in db_memory" in content),
        ("db_boost in fused", "retrieval_boost + rule_boost + meta_fused + db_boost" in content),
        ("decision override", "if db_decision_override and db_decision_override in DECISIONS:" in content),
    ]
    
    all_pass = True
    for check_name, result in checks:
        status = "✓" if result else "❌"
        print(f"{status} {check_name}")
        all_pass = all_pass and result
    
    if all_pass:
        print("✓ PASS: Decoder calibration properly implemented")
    else:
        print("❌ FAIL: Decoder calibration not properly implemented")
    
    return all_pass


def test_fix_4_api_key():
    """Test Fix 4: API key moved to environment variable"""
    print("\n" + "="*60)
    print("TEST FIX 4: API Key Environment Variable")
    print("="*60)
    
    db_py = Path(_HERE) / "database" / "db_engine.py"
    with open(db_py) as f:
        content = f.read()
    
    checks = [
        ("os.getenv usage", 'os.getenv("PINECONE_API_KEY"' in content),
        ("Environment variable fallback", 'os.getenv(\n            "PINECONE_API_KEY"' in content or 'os.getenv("PINECONE_API_KEY"' in content),
    ]
    
    all_pass = True
    for check_name, result in checks:
        status = "✓" if result else "❌"
        print(f"{status} {check_name}")
        all_pass = all_pass and result
    
    if all_pass:
        print("✓ PASS: API key moved to environment variable")
    else:
        print("❌ FAIL: API key not properly moved")
    
    return all_pass


def test_fix_5_attack_logging():
    """Test Fix 5: Logging in attack engine"""
    print("\n" + "="*60)
    print("TEST FIX 5: Attack Engine Logging")
    print("="*60)
    
    attack_py = Path(_HERE) / "attacker" / "attack_engine.py"
    with open(attack_py) as f:
        content = f.read()
    
    checks = [
        ("Missing atk_tag log", 'received decision without atk_tag' in content),
        ("Unknown tag log", 'received decision for unknown atk_tag' in content),
        ("Feedback reception log", 'feedback:' in content and '[attacker]' in content),
        ("Fitness update log", 'fitness:' in content and '[attacker]' in content),
    ]
    
    all_pass = True
    for check_name, result in checks:
        status = "✓" if result else "❌"
        print(f"{status} {check_name}")
        all_pass = all_pass and result
    
    if all_pass:
        print("✓ PASS: Attack engine logging properly added")
    else:
        print("❌ FAIL: Attack engine logging not properly added")
    
    return all_pass


def test_fix_6_db_logging():
    """Test Fix 6: Logging in database engine"""
    print("\n" + "="*60)
    print("TEST FIX 6: Database Engine Logging")
    print("="*60)
    
    db_py = Path(_HERE) / "database" / "db_engine.py"
    with open(db_py) as f:
        content = f.read()
    
    checks = [
        ("Write success log", 'print(f"[db] wrote record:' in content),
        ("Drop reason log", 'print(f"[db] dropped record:' in content),
        ("Anomaly gate check", 'if anomaly_score < MEMORY_WRITE_GATE:' in content),
    ]
    
    all_pass = True
    for check_name, result in checks:
        status = "✓" if result else "❌"
        print(f"{status} {check_name}")
        all_pass = all_pass and result
    
    if all_pass:
        print("✓ PASS: Database engine logging properly added")
    else:
        print("❌ FAIL: Database engine logging not properly added")
    
    return all_pass


def main():
    print("\n" + "="*60)
    print("CNNFOLE TRAINING SYSTEM - FIX VERIFICATION")
    print("="*60)
    
    results = {
        "Fix 1: Write Gate": test_fix_1_write_gate(),
        "Fix 2: Feedback Server": test_fix_2_feedback_server(),
        "Fix 3: Decoder Calibration": test_fix_3_decoder_calibration(),
        "Fix 4: API Key": test_fix_4_api_key(),
        "Fix 5: Attack Logging": test_fix_5_attack_logging(),
        "Fix 6: DB Logging": test_fix_6_db_logging(),
    }
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    
    for fix_name, result in results.items():
        status = "✓ PASS" if result else "❌ FAIL"
        print(f"{status}: {fix_name}")
    
    all_pass = all(results.values())
    
    print("\n" + "="*60)
    if all_pass:
        print("✓ ALL FIXES VERIFIED SUCCESSFULLY")
        print("="*60)
        print("\nNext steps:")
        print("1. Set environment variable:")
        print('   export PINECONE_API_KEY="pcsk_..."')
        print("\n2. Start IDS:")
        print("   python run.py --synthetic")
        print("\n3. Start attacker (in another terminal):")
        print("   python attacker/run_attacker.py --remote 127.0.0.1 --duration 60")
        print("\n4. Monitor:")
        print("   python diagnose_system.py")
        return 0
    else:
        print("❌ SOME FIXES FAILED VERIFICATION")
        print("="*60)
        print("\nPlease review the failures above and re-apply fixes.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
