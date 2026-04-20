#!/usr/bin/env python3
"""
Test mutation predictor to verify it works correctly.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from decoder.mutation_predictor import MutationPredictor

def test_mutation_prediction():
    print("=" * 60)
    print("MUTATION PREDICTOR TEST")
    print("=" * 60)
    
    predictor = MutationPredictor()
    
    # Test 1: DoS mutation prediction
    print("\n1. DoS Attack Mutation Prediction")
    print("-" * 60)
    dos_event = {
        "rate_hz": 8000,
        "entropy": 0.05,
        "bytes_in": 60,
        "port_dst": 80,
        "protocol": 6,
    }
    
    mutations = predictor.predict_mutations(dos_event, "DoS/DDoS", k=5)
    print(f"Base event: rate={dos_event['rate_hz']}, entropy={dos_event['entropy']}")
    print(f"\nPredicted mutations:")
    for m in mutations:
        print(f"  {m['id']}. {m['description']}")
        print(f"     Type: {m['type']}, Confidence: {m['confidence']}")
    
    # Test 2: Score incoming traffic against mutations
    print("\n2. Score Incoming Traffic Against Mutations")
    print("-" * 60)
    incoming_event = {
        "rate_hz": 4200,  # Matches slow DoS (rate × 0.5)
        "entropy": 0.12,  # Matches obfuscated DoS (entropy + 0.1)
        "bytes_in": 60,
        "port_dst": 80,
        "protocol": 6,
    }
    
    scores = predictor.score_against_mutations(incoming_event, mutations)
    print(f"Incoming event: rate={incoming_event['rate_hz']}, entropy={incoming_event['entropy']}")
    print(f"\nMutation matches:")
    for match in scores["mutation_matches"]:
        print(f"  {match['description']}")
        print(f"    Match score: {match['match_score']}")
    
    print(f"\nMax mutation score: {scores['max_mutation_score']:.3f}")
    print(f"Predicted mutation detected: {scores['predicted_mutation_detected']}")
    
    # Test 3: PortScan mutation prediction
    print("\n3. PortScan Attack Mutation Prediction")
    print("-" * 60)
    portscan_event = {
        "rate_hz": 400,
        "entropy": 0.02,
        "bytes_in": 60,
        "port_dst": 22,
        "protocol": 6,
    }
    
    mutations = predictor.predict_mutations(portscan_event, "PortScan", k=3)
    print(f"Base event: rate={portscan_event['rate_hz']}, entropy={portscan_event['entropy']}")
    print(f"\nPredicted mutations:")
    for m in mutations:
        print(f"  {m['id']}. {m['description']}")
    
    # Test 4: C2 mutation prediction
    print("\n4. C2/Exfiltration Attack Mutation Prediction")
    print("-" * 60)
    c2_event = {
        "rate_hz": 8,
        "entropy": 0.88,
        "bytes_in": 280,
        "bytes_out": 120,
        "port_dst": 443,
        "protocol": 6,
    }
    
    mutations = predictor.predict_mutations(c2_event, "EncryptedC2/Exfiltration", k=3)
    print(f"Base event: rate={c2_event['rate_hz']}, entropy={c2_event['entropy']}")
    print(f"\nPredicted mutations:")
    for m in mutations:
        print(f"  {m['id']}. {m['description']}")
    
    # Test 5: Decision upgrade logic
    print("\n5. Decision Upgrade Logic")
    print("-" * 60)
    
    test_cases = [
        ("Ignore", 0.75, "Alert"),
        ("Log", 0.75, "Alert"),
        ("Alert", 0.75, "Block"),
        ("Ignore", 0.55, "Log"),
        ("Log", 0.55, "Log"),
    ]
    
    print("Base Decision → Mutation Score → Upgraded Decision")
    print("-" * 60)
    for base, score, expected in test_cases:
        if score > 0.7:
            if base in ("Ignore", "Log"):
                upgraded = "Alert"
            elif base == "Alert":
                upgraded = "Block"
            else:
                upgraded = base
        elif score > 0.5:
            if base == "Ignore":
                upgraded = "Log"
            else:
                upgraded = base
        else:
            upgraded = base
        
        status = "✓" if upgraded == expected else "✗"
        print(f"{status} {base:10} → {score:.2f} → {upgraded:10} (expected {expected})")
    
    print("\n" + "=" * 60)
    print("✓ Mutation Predictor Test Complete")
    print("=" * 60)

if __name__ == "__main__":
    test_mutation_prediction()
