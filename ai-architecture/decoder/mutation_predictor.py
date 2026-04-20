"""
Mutation Predictor — Anticipates attack mutations before they arrive.

Strategy:
  1. Analyze existing threats in database
  2. Learn mutation patterns (what changes when attacks evade)
  3. Generate predicted mutations of current attack
  4. Score incoming traffic against predicted mutations
  5. Block predicted mutations with high confidence

This allows IDS to think ahead: "If this is a DoS, what mutations might come next?"
"""
import math
import numpy as np
from collections import defaultdict


class MutationPredictor:
    """
    Learns mutation patterns from database and predicts likely variants.
    """
    
    # Mutation patterns observed in real attacks
    MUTATION_PATTERNS = {
        "DoS/DDoS": {
            "rate_reduction": [0.5, 0.3, 0.1],      # Slow down to evade rate-based detection
            "entropy_increase": [0.1, 0.2, 0.3],    # Add noise/randomization
            "port_rotation": [80, 443, 8080, 8443], # Try different ports
            "fragmentation": [0.5, 0.3],            # Fragment packets
            "burst_variation": [0.2, 0.5, 0.8],     # Vary burst patterns
        },
        "PortScan": {
            "rate_reduction": [0.5, 0.2, 0.1],
            "entropy_increase": [0.1, 0.15],
            "port_randomization": True,             # Randomize port order
            "protocol_switching": ["TCP", "UDP"],   # Try different protocols
        },
        "BruteForce/CredentialStuffing": {
            "rate_reduction": [0.5, 0.3, 0.1],
            "timing_variation": [0.1, 0.5, 1.0],    # Vary time between attempts
            "entropy_increase": [0.1, 0.2],
            "port_switching": [22, 3389, 445],      # Try different ports
        },
        "EncryptedC2/Exfiltration": {
            "rate_increase": [1.5, 2.0],            # Increase to exfiltrate faster
            "entropy_variation": [0.05, 0.1],       # Slight entropy changes
            "payload_fragmentation": [0.5, 0.3],    # Fragment large payloads
            "timing_jitter": [0.1, 0.2, 0.5],       # Add timing jitter
        },
        "DNSTunnel": {
            "query_size_variation": [0.5, 1.5, 2.0],
            "frequency_variation": [0.5, 0.3, 0.1],
            "entropy_increase": [0.05, 0.1],
        },
        "LateralMovement/Persistence": {
            "rate_reduction": [0.5, 0.3],
            "timing_increase": [1.5, 2.0],          # Slow down to avoid detection
            "entropy_variation": [0.05, 0.1],
        },
    }
    
    def __init__(self):
        self.threat_patterns = defaultdict(list)  # attack_class → [threat records]
        self.mutation_cache = {}                   # (attack_class, base_hash) → [mutations]
        
    def learn_from_database(self, db_records: list):
        """
        Analyze database records to learn mutation patterns.
        """
        for rec in db_records:
            attack_class = rec.get("attack_class", "none")
            if attack_class and attack_class != "none":
                self.threat_patterns[attack_class].append(rec)
    
    def predict_mutations(self, current_event: dict, attack_class: str, k: int = 5) -> list:
        """
        Given a current attack event and its class, predict likely mutations.
        
        Returns list of predicted mutations with scores.
        """
        if attack_class not in self.MUTATION_PATTERNS:
            return []
        
        patterns = self.MUTATION_PATTERNS[attack_class]
        mutations = []
        
        # Extract base features
        base_rate = current_event.get("rate_hz", 0.0)
        base_entropy = current_event.get("entropy", 0.0)
        base_bytes = current_event.get("bytes_in", 0.0)
        base_port = current_event.get("port_dst", 0)
        base_protocol = current_event.get("protocol", 0)
        
        # Generate mutations based on patterns
        mutation_id = 0
        
        # Mutation 1: Rate reduction (slow down to evade)
        if "rate_reduction" in patterns:
            for factor in patterns["rate_reduction"]:
                mutation_id += 1
                mutations.append({
                    "id": mutation_id,
                    "type": "rate_reduction",
                    "factor": factor,
                    "predicted_rate": base_rate * factor,
                    "confidence": 0.7,  # High confidence - common evasion
                    "description": f"Slow DoS attack (rate × {factor})",
                })
        
        # Mutation 2: Entropy increase (add noise)
        if "entropy_increase" in patterns:
            for delta in patterns["entropy_increase"]:
                mutation_id += 1
                new_entropy = min(base_entropy + delta, 1.0)
                mutations.append({
                    "id": mutation_id,
                    "type": "entropy_increase",
                    "delta": delta,
                    "predicted_entropy": new_entropy,
                    "confidence": 0.65,
                    "description": f"Obfuscated attack (entropy + {delta})",
                })
        
        # Mutation 3: Port rotation
        if "port_rotation" in patterns:
            for port in patterns["port_rotation"]:
                if port != base_port:
                    mutation_id += 1
                    mutations.append({
                        "id": mutation_id,
                        "type": "port_rotation",
                        "predicted_port": port,
                        "confidence": 0.6,
                        "description": f"Port-rotated attack (port {port})",
                    })
        
        # Mutation 4: Fragmentation (split into smaller packets)
        if "fragmentation" in patterns:
            for frag_factor in patterns["fragmentation"]:
                mutation_id += 1
                mutations.append({
                    "id": mutation_id,
                    "type": "fragmentation",
                    "factor": frag_factor,
                    "predicted_bytes": base_bytes * frag_factor,
                    "predicted_rate": base_rate / frag_factor,  # More packets, lower rate each
                    "confidence": 0.55,
                    "description": f"Fragmented attack ({frag_factor}x smaller packets)",
                })
        
        # Mutation 5: Timing variation (jitter)
        if "timing_jitter" in patterns:
            for jitter in patterns["timing_jitter"]:
                mutation_id += 1
                mutations.append({
                    "id": mutation_id,
                    "type": "timing_jitter",
                    "jitter": jitter,
                    "confidence": 0.5,
                    "description": f"Jittered attack (timing variance {jitter})",
                })
        
        # Sort by confidence and return top k
        mutations.sort(key=lambda x: -x["confidence"])
        return mutations[:k]
    
    def score_against_mutations(self, current_event: dict, predicted_mutations: list) -> dict:
        """
        Score incoming event against predicted mutations.
        Returns mutation match scores.
        """
        scores = {
            "mutation_matches": [],
            "max_mutation_score": 0.0,
            "predicted_mutation_detected": False,
        }
        
        current_rate = current_event.get("rate_hz", 0.0)
        current_entropy = current_event.get("entropy", 0.0)
        current_bytes = current_event.get("bytes_in", 0.0)
        current_port = current_event.get("port_dst", 0)
        
        for mutation in predicted_mutations:
            match_score = 0.0
            match_count = 0
            
            # Check rate match
            if "predicted_rate" in mutation:
                pred_rate = mutation["predicted_rate"]
                if pred_rate > 0:
                    # Allow 30% tolerance on rate matching
                    rate_diff = abs(current_rate - pred_rate) / (pred_rate + 1e-6)
                    if rate_diff <= 0.3:  # Within 30% tolerance
                        rate_match = 1.0 - (rate_diff / 0.3)  # Scale to [0, 1]
                        match_score += rate_match * 0.4
                        match_count += 1
            
            # Check entropy match
            if "predicted_entropy" in mutation:
                pred_entropy = mutation["predicted_entropy"]
                entropy_diff = abs(current_entropy - pred_entropy)
                if entropy_diff <= 0.15:  # Within 0.15 tolerance
                    entropy_match = 1.0 - (entropy_diff / 0.15)
                    match_score += entropy_match * 0.4
                    match_count += 1
            
            # Check port match
            if "predicted_port" in mutation:
                if current_port == mutation["predicted_port"]:
                    match_score += 0.5
                    match_count += 1
            
            # Check bytes match
            if "predicted_bytes" in mutation:
                pred_bytes = mutation["predicted_bytes"]
                if pred_bytes > 0:
                    bytes_diff = abs(current_bytes - pred_bytes) / (pred_bytes + 1e-6)
                    if bytes_diff <= 0.3:
                        bytes_match = 1.0 - (bytes_diff / 0.3)
                        match_score += bytes_match * 0.2
                        match_count += 1
            
            # Normalize by number of features checked
            if match_count > 0:
                match_score = match_score / match_count
            
            match_score = min(match_score, 1.0)
            
            if match_score > 0.25:  # Lower threshold for detection
                scores["mutation_matches"].append({
                    "mutation_id": mutation["id"],
                    "mutation_type": mutation["type"],
                    "match_score": round(match_score, 3),
                    "description": mutation["description"],
                })
                scores["max_mutation_score"] = max(scores["max_mutation_score"], match_score)
        
        if scores["mutation_matches"]:
            scores["predicted_mutation_detected"] = True
        
        return scores


class MutationAwareDecoder:
    """
    Wraps HybridDecoder to add mutation prediction.
    """
    
    def __init__(self, base_decoder, db_engine):
        self.base_decoder = base_decoder
        self.db_engine = db_engine
        self.predictor = MutationPredictor()
        self._last_db_sync = 0
        self._sync_interval = 300  # Sync every 5 minutes
        
    def decode_with_mutation_awareness(self, cnn_event: dict, rnn_event: dict, 
                                       db_memory: list = None, metadata: dict = None) -> dict:
        """
        Enhanced decode that predicts and blocks mutations.
        """
        import time
        
        # Periodically sync database patterns
        now = time.time()
        if now - self._last_db_sync > self._sync_interval:
            self._sync_database_patterns()
            self._last_db_sync = now
        
        # Get base decision
        base_decision = self.base_decoder.decode(cnn_event, rnn_event, db_memory, metadata)
        
        # If already blocking, no need for mutation prediction
        if base_decision["decision"] in ("Block", "Escalate"):
            return base_decision
        
        # Get attack class
        attack_class = base_decision.get("attack_class", "none")
        if attack_class == "none":
            return base_decision
        
        # Predict mutations
        predicted_mutations = self.predictor.predict_mutations(cnn_event, attack_class, k=5)
        if not predicted_mutations:
            return base_decision
        
        # Score against mutations
        mutation_scores = self.predictor.score_against_mutations(cnn_event, predicted_mutations)
        
        # Add mutation info to decision
        base_decision["mutation_prediction"] = {
            "predicted_mutations": predicted_mutations,
            "mutation_scores": mutation_scores,
            "max_mutation_score": mutation_scores["max_mutation_score"],
        }
        
        # Upgrade decision if mutation detected with high confidence
        if mutation_scores["predicted_mutation_detected"]:
            max_score = mutation_scores["max_mutation_score"]
            
            # If mutation match is high, upgrade decision
            if max_score > 0.7:
                if base_decision["decision"] in ("Ignore", "Log"):
                    base_decision["decision"] = "Alert"
                    base_decision["explanation"] += f" [MUTATION PREDICTED: {max_score:.2f}]"
                elif base_decision["decision"] == "Alert":
                    base_decision["decision"] = "Block"
                    base_decision["explanation"] += f" [MUTATION PREDICTED: {max_score:.2f}]"
            elif max_score > 0.5:
                if base_decision["decision"] == "Ignore":
                    base_decision["decision"] = "Log"
                    base_decision["explanation"] += f" [MUTATION LIKELY: {max_score:.2f}]"
        
        return base_decision
    
    def _sync_database_patterns(self):
        """
        Sync threat patterns from database.
        """
        try:
            # Get all records from database
            all_records = []
            
            # Collect from all scopes
            for store in self.db_engine.memory.ip_store.values():
                all_records.extend([r.to_dict() for r in store.records])
            for store in self.db_engine.memory.session_store.values():
                all_records.extend([r.to_dict() for r in store.records])
            for store in self.db_engine.memory.host_store.values():
                all_records.extend([r.to_dict() for r in store.records])
            
            all_records.extend([r.to_dict() for r in self.db_engine.memory.global_store.records])
            
            # Learn patterns
            self.predictor.learn_from_database(all_records)
            
            if all_records:
                print(f"[mutation-predictor] Synced {len(all_records)} patterns from database")
        except Exception as e:
            print(f"[mutation-predictor] Sync error: {e}")
