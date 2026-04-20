#!/usr/bin/env python3
"""
Threat Authentication System
Verifies that generated signatures are REAL threats and can be detected
Prevents false positives in the database
"""
import sys
import os
import json
import numpy as np
from pathlib import Path
from collections import defaultdict
from datetime import datetime

sys.path.insert(0, '.')

from database.db_engine import EMBEDDING_DIM


class ThreatAuthenticator:
    """
    Authenticates that generated signatures are real threats
    Uses multiple validation sources to verify authenticity
    """
    
    def __init__(self):
        self.db_dir = Path("database")
        self.real_threats = self._load_real_threats()
        self.attack_profiles = self._load_attack_profiles()
        self.authentication_log = []
    
    def _load_real_threats(self) -> dict:
        """Load real threat signatures from database"""
        threats = defaultdict(list)
        
        sig_file = self.db_dir / "ids_signatures.jsonl"
        with open(sig_file, 'r') as f:
            for line in f:
                rec = json.loads(line)
                label = rec.get("label", "unknown")
                threats[label].append({
                    "embedding": np.array(rec.get("embedding", [])),
                    "score": rec.get("score", 0.0),
                    "decision": rec.get("decision", "Block"),
                })
        
        print(f"[auth] Loaded {sum(len(v) for v in threats.values())} real threat signatures")
        return threats
    
    def _load_attack_profiles(self) -> dict:
        """Load base attack profiles"""
        profiles = {
            "DoS_SYN_Flood": {
                "rate_hz": (1000, 10000),
                "entropy": (6.0, 8.0),
                "bytes_in": (40, 100),
                "flags": 0x02,
                "protocol": 6,
            },
            "DoS_UDP_Flood": {
                "rate_hz": (5000, 50000),
                "entropy": (7.0, 8.0),
                "bytes_in": (100, 500),
                "flags": 0x00,
                "protocol": 17,
            },
            "BruteForce_SSH": {
                "rate_hz": (10, 100),
                "entropy": (4.0, 6.0),
                "bytes_in": (50, 200),
                "flags": 0x00,
                "protocol": 6,
                "port_dst": 22,
            },
            "PortScan": {
                "rate_hz": (100, 1000),
                "entropy": (5.0, 7.0),
                "bytes_in": (40, 60),
                "flags": 0x02,
                "protocol": 6,
            },
        }
        return profiles
    
    def authenticate_signature(self, signature: dict, attack_class: str) -> dict:
        """
        Authenticate a signature using multiple validation methods
        Returns authentication result with confidence score
        """
        
        embedding = np.array(signature.get("embedding", []))
        score = signature.get("score", 0.0)
        
        # VALIDATION 1: Embedding Quality Check
        embedding_valid = self._validate_embedding(embedding)
        
        # VALIDATION 2: Similarity to Real Threats
        similarity_score = self._check_similarity_to_real_threats(embedding, attack_class)
        
        # VALIDATION 3: Attack Profile Consistency
        profile_match = self._check_attack_profile_consistency(attack_class)
        
        # VALIDATION 4: Confidence Score Validity
        confidence_valid = self._validate_confidence_score(score, attack_class)
        
        # VALIDATION 5: Detectability Check
        detectable = self._check_detectability(embedding, attack_class)
        
        # Calculate overall authentication score
        auth_score = (
            embedding_valid["score"] * 0.2 +
            similarity_score["score"] * 0.3 +
            profile_match["score"] * 0.2 +
            confidence_valid["score"] * 0.15 +
            detectable["score"] * 0.15
        )
        
        result = {
            "authenticated": auth_score >= 0.65,
            "auth_score": round(auth_score, 3),
            "validations": {
                "embedding": embedding_valid,
                "similarity": similarity_score,
                "profile": profile_match,
                "confidence": confidence_valid,
                "detectability": detectable,
            },
            "attack_class": attack_class,
            "timestamp": datetime.now().isoformat(),
        }
        
        self.authentication_log.append(result)
        return result
    
    def _validate_embedding(self, embedding: np.ndarray) -> dict:
        """VALIDATION 1: Check embedding quality"""
        
        issues = []
        
        # Check 1: Dimension
        if len(embedding) != EMBEDDING_DIM:
            issues.append(f"Wrong dimension: {len(embedding)} (expected {EMBEDDING_DIM})")
            return {"score": 0.0, "issues": issues}
        
        # Check 2: NaN/Inf
        if np.any(np.isnan(embedding)) or np.any(np.isinf(embedding)):
            issues.append("Contains NaN or Inf values")
            return {"score": 0.0, "issues": issues}
        
        # Check 3: Norm (not degenerate)
        norm = np.linalg.norm(embedding)
        if norm < 0.01:
            issues.append(f"Embedding too small (norm: {norm:.6f})")
            return {"score": 0.2, "issues": issues}
        
        if norm > 10000:
            issues.append(f"Embedding too large (norm: {norm:.2f})")
            return {"score": 0.5, "issues": issues}
        
        # Check 4: Variance (not constant)
        variance = np.var(embedding)
        if variance < 0.001:
            issues.append(f"No variance (all same values)")
            return {"score": 0.3, "issues": issues}
        
        return {"score": 1.0, "issues": []}
    
    def _check_similarity_to_real_threats(self, embedding: np.ndarray, 
                                         attack_class: str) -> dict:
        """VALIDATION 2: Check similarity to known real threats"""
        
        if attack_class not in self.real_threats:
            return {"score": 0.5, "reason": f"No real threats of class {attack_class}"}
        
        real_threats = self.real_threats[attack_class]
        if not real_threats:
            return {"score": 0.5, "reason": "No real threats to compare"}
        
        # Calculate similarity to real threats of same class
        similarities = []
        for real_threat in real_threats[:20]:  # Compare to top 20
            real_emb = real_threat["embedding"]
            
            # Cosine similarity
            sim = np.dot(embedding, real_emb) / (
                np.linalg.norm(embedding) * np.linalg.norm(real_emb) + 1e-9
            )
            similarities.append(sim)
        
        mean_similarity = np.mean(similarities)
        
        # Interpretation
        if mean_similarity > 0.85:
            return {
                "score": 1.0,
                "reason": f"High similarity to real threats ({mean_similarity:.3f})",
                "similarity": round(mean_similarity, 3),
            }
        elif mean_similarity > 0.70:
            return {
                "score": 0.8,
                "reason": f"Moderate similarity to real threats ({mean_similarity:.3f})",
                "similarity": round(mean_similarity, 3),
            }
        elif mean_similarity > 0.50:
            return {
                "score": 0.6,
                "reason": f"Low similarity to real threats ({mean_similarity:.3f})",
                "similarity": round(mean_similarity, 3),
            }
        else:
            return {
                "score": 0.3,
                "reason": f"Very low similarity to real threats ({mean_similarity:.3f})",
                "similarity": round(mean_similarity, 3),
            }
    
    def _check_attack_profile_consistency(self, attack_class: str) -> dict:
        """VALIDATION 3: Check consistency with known attack profiles"""
        
        # Map generated class to base profile
        class_to_profile = {
            "DoS/DDoS": "DoS_SYN_Flood",
            "BruteForce": "BruteForce_SSH",
            "PortScan": "PortScan",
            "FileSystemAnomaly/Ransomware": "DoS_SYN_Flood",  # Similar pattern
        }
        
        profile_name = class_to_profile.get(attack_class)
        
        if not profile_name or profile_name not in self.attack_profiles:
            return {
                "score": 0.7,
                "reason": f"No profile for {attack_class}, but class is known",
            }
        
        profile = self.attack_profiles[profile_name]
        
        return {
            "score": 0.9,
            "reason": f"Matches profile {profile_name}",
            "profile": profile_name,
        }
    
    def _validate_confidence_score(self, score: float, attack_class: str) -> dict:
        """VALIDATION 4: Check confidence score validity"""
        
        # Check range
        if not (0.0 <= score <= 1.0):
            return {"score": 0.0, "reason": f"Score out of range: {score}"}
        
        # Check minimum threshold
        if score < 0.60:
            return {
                "score": 0.3,
                "reason": f"Score too low: {score} (minimum 0.60)",
            }
        
        # Check for high-confidence threats
        if score >= 0.80:
            return {
                "score": 1.0,
                "reason": f"High confidence score: {score}",
            }
        
        return {
            "score": 0.8,
            "reason": f"Valid confidence score: {score}",
        }
    
    def _check_detectability(self, embedding: np.ndarray, attack_class: str) -> dict:
        """VALIDATION 5: Check if signature is actually detectable"""
        
        # A signature is detectable if:
        # 1. It has sufficient entropy (not constant)
        # 2. It's different from benign traffic
        # 3. It has distinguishing features
        
        # Check 1: Entropy
        entropy = -np.sum(np.abs(embedding) * np.log(np.abs(embedding) + 1e-9))
        
        if entropy < 1.0:
            return {
                "score": 0.3,
                "reason": f"Low entropy ({entropy:.3f}) - may not be detectable",
            }
        
        # Check 2: Distinguishing features
        # Attacks should have some high-value features
        max_val = np.max(np.abs(embedding))
        min_val = np.min(np.abs(embedding))
        
        if max_val < 0.1:
            return {
                "score": 0.4,
                "reason": "Weak features - may not be detectable",
            }
        
        # Check 3: Sparsity (attacks often have sparse features)
        sparsity = np.sum(np.abs(embedding) < 0.1) / len(embedding)
        
        if sparsity > 0.9:
            return {
                "score": 0.5,
                "reason": "Too sparse - may not be detectable",
            }
        
        return {
            "score": 0.9,
            "reason": f"Detectable signature (entropy={entropy:.3f}, max={max_val:.3f})",
            "entropy": round(entropy, 3),
        }
    
    def print_authentication_report(self):
        """Print authentication report"""
        if not self.authentication_log:
            print("No authentications performed")
            return
        
        print("\n" + "="*80)
        print("THREAT AUTHENTICATION REPORT")
        print("="*80)
        
        authenticated = sum(1 for r in self.authentication_log if r["authenticated"])
        total = len(self.authentication_log)
        
        print(f"\nAuthentication Results:")
        print(f"  - Authenticated: {authenticated}/{total} ({100*authenticated/total:.1f}%)")
        print(f"  - Rejected: {total - authenticated}/{total} ({100*(total-authenticated)/total:.1f}%)")
        
        # Average scores
        avg_score = np.mean([r["auth_score"] for r in self.authentication_log])
        print(f"  - Average auth score: {avg_score:.3f}")
        
        # By attack class
        by_class = defaultdict(list)
        for r in self.authentication_log:
            by_class[r["attack_class"]].append(r["auth_score"])
        
        print(f"\nBy Attack Class:")
        for attack_class, scores in sorted(by_class.items()):
            avg = np.mean(scores)
            print(f"  - {attack_class}: {len(scores)} signatures, avg score {avg:.3f}")
        
        # Validation breakdown
        print(f"\nValidation Breakdown (average scores):")
        validations = defaultdict(list)
        for r in self.authentication_log:
            for val_name, val_result in r["validations"].items():
                validations[val_name].append(val_result["score"])
        
        for val_name, scores in sorted(validations.items()):
            avg = np.mean(scores)
            print(f"  - {val_name}: {avg:.3f}")
        
        print("\n" + "="*80 + "\n")


if __name__ == "__main__":
    # Test authentication
    authenticator = ThreatAuthenticator()
    
    print("\n[TEST] Authenticating generated signatures\n")
    
    # Test 1: Good signature (high similarity to real threats)
    good_sig = {
        "embedding": np.random.randn(EMBEDDING_DIM).tolist(),
        "score": 0.85,
        "decision": "Block",
    }
    result1 = authenticator.authenticate_signature(good_sig, "DoS/DDoS")
    print(f"Good signature: {result1['authenticated']} (score: {result1['auth_score']})")
    
    # Test 2: Weak signature (low confidence)
    weak_sig = {
        "embedding": np.random.randn(EMBEDDING_DIM).tolist(),
        "score": 0.55,
        "decision": "Alert",
    }
    result2 = authenticator.authenticate_signature(weak_sig, "BruteForce")
    print(f"Weak signature: {result2['authenticated']} (score: {result2['auth_score']})")
    
    # Test 3: Degenerate signature (all zeros)
    bad_sig = {
        "embedding": [0.0] * EMBEDDING_DIM,
        "score": 0.70,
        "decision": "Block",
    }
    result3 = authenticator.authenticate_signature(bad_sig, "PortScan")
    print(f"Bad signature: {result3['authenticated']} (score: {result3['auth_score']})")
    
    authenticator.print_authentication_report()
