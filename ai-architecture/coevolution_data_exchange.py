#!/usr/bin/env python3
"""
Co-Evolution Data Exchange System
Tracks data flow between Attacker, IDS, and Database during co-evolution
Shows exactly what data is exchanged and how database is updated
"""
import sys
import os
import json
import time
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, '.')


class CoEvolutionDataExchange:
    """
    Tracks and logs all data exchanges during co-evolution
    Shows the complete feedback loop
    """
    
    def __init__(self):
        self.exchanges = []
        self.generation = 0
        self.stats = {
            "total_attacks": 0,
            "total_detections": 0,
            "total_evasions": 0,
            "database_updates": 0,
            "signatures_added": 0,
        }
    
    def log_attack_generation(self, attack_profile: dict, generation: int):
        """STEP 1: Attacker generates attack"""
        self.generation = generation
        
        exchange = {
            "step": 1,
            "phase": "ATTACK_GENERATION",
            "timestamp": datetime.now().isoformat(),
            "generation": generation,
            "data": {
                "source": "ATTACKER",
                "action": "Generate attack variant",
                "attack_profile": attack_profile.get("name", "unknown"),
                "parameters": {
                    "rate_hz": attack_profile.get("rate_hz", 0),
                    "entropy": attack_profile.get("entropy", 0),
                    "bytes_in": attack_profile.get("bytes_in", 0),
                    "port_dst": attack_profile.get("port_dst", 0),
                },
                "fitness_history": attack_profile.get("fitness", 0),
            },
        }
        
        self.exchanges.append(exchange)
        self.stats["total_attacks"] += 1
        
        print(f"\n[GEN {generation}] STEP 1: ATTACK GENERATION")
        print(f"  Attacker creates: {attack_profile.get('name', 'unknown')}")
        print(f"  Parameters: rate={attack_profile.get('rate_hz', 0)}, "
              f"entropy={attack_profile.get('entropy', 0)}")
    
    def log_ids_detection(self, decision: str, confidence: float, 
                         attack_class: str, explanation: str):
        """STEP 2: IDS processes attack and makes decision"""
        
        exchange = {
            "step": 2,
            "phase": "IDS_DETECTION",
            "timestamp": datetime.now().isoformat(),
            "generation": self.generation,
            "data": {
                "source": "IDS",
                "action": "Process attack and decide",
                "decision": decision,
                "confidence": confidence,
                "attack_class": attack_class,
                "explanation": explanation,
                "components": {
                    "CNN": "Extracted features",
                    "RNN": "Detected temporal anomaly",
                    "Decoder": "Made decision",
                    "TI": "Enriched with threat intelligence",
                },
            },
        }
        
        self.exchanges.append(exchange)
        self.stats["total_detections"] += 1
        
        print(f"\n[GEN {self.generation}] STEP 2: IDS DETECTION")
        print(f"  Decision: {decision}")
        print(f"  Confidence: {confidence:.3f}")
        print(f"  Attack Class: {attack_class}")
    
    def log_fitness_scoring(self, decision: str, fitness_score: float,
                           evasion_type: str):
        """STEP 3: Fitness scoring based on decision"""
        
        # Map decision to fitness
        fitness_map = {
            "Ignore": 1.0,      # True evasion
            "Log": 0.4,         # Weak evasion
            "Alert": 0.2,       # Partial evasion
            "Block": 0.0,       # Failure
            "Escalate": 0.0,    # Failure
        }
        
        actual_fitness = fitness_map.get(decision, 0.0)
        
        exchange = {
            "step": 3,
            "phase": "FITNESS_SCORING",
            "timestamp": datetime.now().isoformat(),
            "generation": self.generation,
            "data": {
                "source": "MUTATOR",
                "action": "Score attack fitness",
                "decision": decision,
                "fitness_score": actual_fitness,
                "evasion_type": evasion_type,
                "scoring_logic": {
                    "Ignore": "1.0 - True evasion (not detected)",
                    "Log": "0.4 - Weak evasion (detected but not acted)",
                    "Alert": "0.2 - Partial evasion (detected but not blocked)",
                    "Block": "0.0 - Failure (detected and blocked)",
                },
            },
        }
        
        self.exchanges.append(exchange)
        
        if actual_fitness > 0:
            self.stats["total_evasions"] += 1
        
        print(f"\n[GEN {self.generation}] STEP 3: FITNESS SCORING")
        print(f"  Decision: {decision} -> Fitness: {actual_fitness}")
        print(f"  Evasion Type: {evasion_type}")
    
    def log_database_update(self, attack_data: dict, decision: str, 
                           confidence: float, added_to_db: bool):
        """STEP 4: Database update with attack outcome"""
        
        exchange = {
            "step": 4,
            "phase": "DATABASE_UPDATE",
            "timestamp": datetime.now().isoformat(),
            "generation": self.generation,
            "data": {
                "source": "DATABASE",
                "action": "Store attack outcome",
                "added_to_database": added_to_db,
                "record": {
                    "attack_class": attack_data.get("attack_class", "unknown"),
                    "decision": decision,
                    "confidence": confidence,
                    "embedding": f"[{len(attack_data.get('embedding', []))} dims]",
                    "source_ip": attack_data.get("source", ""),
                    "destination_ip": attack_data.get("destination", ""),
                },
                "write_gate_check": {
                    "confidence": confidence,
                    "write_gate": 0.35,
                    "force_gate": 0.65,
                    "passes_write_gate": confidence >= 0.35,
                    "passes_force_gate": confidence >= 0.65,
                },
            },
        }
        
        self.exchanges.append(exchange)
        
        if added_to_db:
            self.stats["database_updates"] += 1
            self.stats["signatures_added"] += 1
        
        print(f"\n[GEN {self.generation}] STEP 4: DATABASE UPDATE")
        print(f"  Added to DB: {added_to_db}")
        print(f"  Confidence: {confidence:.3f}")
        print(f"  Write Gate (0.35): {'PASS' if confidence >= 0.35 else 'FAIL'}")
        print(f"  Force Gate (0.65): {'PASS' if confidence >= 0.65 else 'FAIL'}")
    
    def log_decoder_learning(self, similar_records: int, 
                            threshold_adjustment: float):
        """STEP 5: Decoder learns from database"""
        
        exchange = {
            "step": 5,
            "phase": "DECODER_LEARNING",
            "timestamp": datetime.now().isoformat(),
            "generation": self.generation,
            "data": {
                "source": "DECODER",
                "action": "Learn from database records",
                "similar_records_retrieved": similar_records,
                "learning_mechanism": {
                    "vector_similarity_search": "Find similar attacks in database",
                    "threshold_adjustment": threshold_adjustment,
                    "adaptive_learning": "Per-IP thresholds updated",
                },
                "impact": {
                    "next_similar_attack": "Will be detected with higher confidence",
                    "false_negative_prevention": "Learned evasion pattern",
                },
            },
        }
        
        self.exchanges.append(exchange)
        
        print(f"\n[GEN {self.generation}] STEP 5: DECODER LEARNING")
        print(f"  Similar records retrieved: {similar_records}")
        print(f"  Threshold adjustment: {threshold_adjustment:.3f}")
        print(f"  Impact: Next similar attack will be detected")
    
    def log_population_evolution(self, elite_count: int, 
                                new_variants: int, avg_fitness: float):
        """STEP 6: Population evolution for next generation"""
        
        exchange = {
            "step": 6,
            "phase": "POPULATION_EVOLUTION",
            "timestamp": datetime.now().isoformat(),
            "generation": self.generation,
            "data": {
                "source": "MUTATOR",
                "action": "Evolve population for next generation",
                "elite_attacks": elite_count,
                "new_variants": new_variants,
                "average_fitness": avg_fitness,
                "evolution_strategy": {
                    "elite_keep": "Top 4 attacks always survive",
                    "crossover": "Combine two successful attacks",
                    "mutation": "Vary parameters of winners",
                    "selection": "Fitness-weighted tournament selection",
                },
                "result": {
                    "next_generation": f"Gen {self.generation + 1}",
                    "expected_fitness": f"{avg_fitness * 1.1:.3f} (10% improvement)",
                },
            },
        }
        
        self.exchanges.append(exchange)
        
        print(f"\n[GEN {self.generation}] STEP 6: POPULATION EVOLUTION")
        print(f"  Elite attacks: {elite_count}")
        print(f"  New variants: {new_variants}")
        print(f"  Average fitness: {avg_fitness:.3f}")
        print(f"  Next generation expected fitness: {avg_fitness * 1.1:.3f}")
    
    def print_data_flow_diagram(self):
        """Print complete data flow diagram"""
        print("\n" + "="*80)
        print("CO-EVOLUTION DATA EXCHANGE FLOW")
        print("="*80)
        
        print("""
GENERATION N:
=============

[STEP 1: ATTACK GENERATION (ATTACKER)]
Input:  Base attack profile + mutation parameters
Output: Attack variant with mutated parameters
Data:   rate_hz, entropy, bytes_in, port_dst, flags, protocol
                                    |
[STEP 2: IDS DETECTION (CNN + RNN + DECODER + TI)]
Input:  Attack packets
Process:
  - CNN: Extract features -> is_attack_prob
  - RNN: Detect temporal anomaly -> anomaly_trend
  - Decoder: Fuse scores -> confidence
  - TI: Enrich with threat intelligence
Output: Decision (Block/Alert/Log/Ignore) + Confidence
Data:   decision, confidence, attack_class, explanation
                                    |
[STEP 3: FITNESS SCORING (MUTATOR)]
Input:  IDS Decision
Scoring:
  - Ignore -> 1.0 (true evasion)
  - Log -> 0.4 (weak evasion)
  - Alert -> 0.2 (partial evasion)
  - Block -> 0.0 (failure)
Output: Fitness score (0.0 - 1.0)
Data:   fitness_score, evasion_type
                                    |
[STEP 4: DATABASE UPDATE (DATABASE ENGINE)]
Input:  Attack outcome (decision, confidence, embedding)
Write Gates:
  - confidence >= 0.35 -> Write to memory store
  - confidence >= 0.65 -> Write to global store
Output: Record stored in database
Data:   embedding, decision, confidence, attack_class, source, dest
Files Updated:
  - refined_threats.jsonl (all outcomes)
  - ids_signatures.jsonl (high-confidence only)
                                    |
[STEP 5: DECODER LEARNING (HYBRID DECODER)]
Input:  New database record
Process:
  - Vector similarity search: Find similar attacks
  - Retrieve top K similar records
  - Update adaptive thresholds (per-IP)
  - Adjust decision boundaries
Output: Updated decoder state
Data:   similar_records, threshold_adjustments, new_boundaries
Impact: Next similar attack will be detected with higher confidence
                                    |
[STEP 6: POPULATION EVOLUTION (MUTATOR)]
Input:  Fitness scores of all attacks in population
Evolution:
  - Elite Keep: Top 4 attacks always survive
  - Crossover: Combine two successful attacks
  - Mutation: Vary parameters of winners
  - Selection: Fitness-weighted tournament
Output: New population for next generation
Data:   new_attack_profiles, mutation_parameters
Result: Population evolves toward higher evasion
                                    |
                        GENERATION N+1 STARTS
                        (Repeat cycle)

KEY DATA EXCHANGES:
===================

Attacker -> IDS:
  - Attack packets with mutated parameters
  - Embedding features

IDS -> Database:
  - Decision (Block/Alert/Log/Ignore)
  - Confidence score
  - Attack class
  - Embedding vector
  - Source/destination IPs

Database -> Decoder:
  - Similar attack records
  - Historical decisions
  - Confidence trends

Decoder -> Attacker (via Fitness):
  - Fitness score (0.0 - 1.0)
  - Evasion success indicator

Mutator -> Population:
  - Evolved attack profiles
  - New mutation parameters
        """)
    
    def print_exchange_summary(self):
        """Print summary of all exchanges"""
        print("\n" + "="*80)
        print("CO-EVOLUTION EXCHANGE SUMMARY")
        print("="*80)
        
        print(f"\nGeneration: {self.generation}")
        print(f"\nStatistics:")
        print(f"  - Total attacks generated: {self.stats['total_attacks']}")
        print(f"  - Total detections: {self.stats['total_detections']}")
        print(f"  - Total evasions: {self.stats['total_evasions']}")
        print(f"  - Database updates: {self.stats['database_updates']}")
        print(f"  - Signatures added: {self.stats['signatures_added']}")
        
        if self.stats['total_attacks'] > 0:
            evasion_rate = self.stats['total_evasions'] / self.stats['total_attacks']
            print(f"  - Evasion rate: {evasion_rate:.1%}")
        
        print(f"\nData Exchanges: {len(self.exchanges)}")
        
        # Group by phase
        by_phase = defaultdict(int)
        for ex in self.exchanges:
            by_phase[ex["phase"]] += 1
        
        print(f"\nExchanges by phase:")
        for phase, count in sorted(by_phase.items()):
            print(f"  - {phase}: {count}")
        
        print("\n" + "="*80 + "\n")


if __name__ == "__main__":
    # Simulate co-evolution exchanges
    exchange = CoEvolutionDataExchange()
    
    print("\n[SIMULATION] Co-Evolution Data Exchange\n")
    
    # Generation 1
    attack = {
        "name": "DoS_SYN_Flood",
        "rate_hz": 1000,
        "entropy": 7.0,
        "bytes_in": 50,
        "port_dst": 80,
        "fitness": 0.0,
    }
    
    exchange.log_attack_generation(attack, generation=1)
    exchange.log_ids_detection("Block", 0.85, "DoS/DDoS", "High rate SYN flood detected")
    exchange.log_fitness_scoring("Block", 0.0, "failure")
    exchange.log_database_update(
        {"attack_class": "DoS/DDoS", "source": "192.168.1.100", 
         "destination": "10.0.0.50", "embedding": [0.8] * 64},
        "Block", 0.85, True
    )
    exchange.log_decoder_learning(5, 0.05)
    exchange.log_population_evolution(4, 16, 0.15)
    
    # Generation 2
    attack2 = {
        "name": "DoS_SYN_Flood_v2",
        "rate_hz": 500,
        "entropy": 6.5,
        "bytes_in": 40,
        "port_dst": 443,
        "fitness": 0.4,
    }
    
    exchange.log_attack_generation(attack2, generation=2)
    exchange.log_ids_detection("Log", 0.45, "DoS/DDoS", "Slower SYN flood detected but not blocked")
    exchange.log_fitness_scoring("Log", 0.4, "weak_evasion")
    exchange.log_database_update(
        {"attack_class": "DoS/DDoS", "source": "192.168.1.101", 
         "destination": "10.0.0.51", "embedding": [0.7] * 64},
        "Log", 0.45, True
    )
    exchange.log_decoder_learning(8, 0.08)
    exchange.log_population_evolution(4, 16, 0.35)
    
    exchange.print_data_flow_diagram()
    exchange.print_exchange_summary()
