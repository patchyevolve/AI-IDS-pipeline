"""
Mutation Engine — learns from DB feedback which attacks got through (evaded)
and which were blocked, then evolves new variants.

Strategy:
  - BLOCKED record  → the profile was detected. Mutate away from it:
      lower rate_hz, add entropy noise, randomize ports, fragment bytes
  - EVADED record   → the profile worked. Reinforce it:
      keep core params, slightly amplify rate/entropy
  - New variant     → crossover two evaded profiles + random perturbation
"""
import random
import math
import copy
from .attack_profiles import BASE_PROFILES


# Fitness record
class ProfileFitness:
    def __init__(self, name: str, params: dict):
        self.name        = name
        self.params      = copy.deepcopy(params)
        self.sent        = 0
        self.blocked     = 0
        self.evaded      = 0
        self.alerted     = 0
        self.generation  = 0
        self.metadata    = {}  # Track predicted evasions

    @property
    def evasion_rate(self) -> float:
        """
        True evasion rate (not blocked and not alerted).
        """
        if self.sent == 0:
            return 0.5
        true_evasions = self.sent - self.blocked - self.alerted
        return true_evasions / self.sent

    @property
    def fitness(self) -> float:
        """
        Fitness scoring with EVASION-FIRST strategy.
        
        Hierarchy:
        - Ignore = 1.0 (true evasion - not detected)
        - Log = 0.4 (weak evasion - detected but not acted)
        - Alert = 0.2 (partial evasion - detected but not blocked)
        - Block/Escalate = 0.0 (failure - detected and blocked)
        
        SPECIAL: If evasion was PREDICTED by IDS, fitness = 0.0 (failure)
        This prevents population from converging to predicted patterns.
        """
        if self.sent < 3:
            return 0.5  # unknown
        
        if self.sent == 0:
            return 0.5
        
        # Check if this profile's evasions were predicted
        if self.metadata.get("predicted_evasion"):
            # Predicted evasion = failure (fitness 0.0)
            # Attacker must find NEW evasion technique
            return 0.0
        
        # Normal fitness calculation
        true_evasions = self.evaded  # Only "Ignore" decisions
        weak_evasions = self.alerted  # "Alert" decisions
        blocks = self.blocked  # "Block" + "Escalate"
        
        weighted_score = (true_evasions * 1.0 + weak_evasions * 0.2 - blocks * 1.0) / self.sent
        return max(0.0, min(1.0, weighted_score))

    def record_outcome(self, decision: str):
        self.sent += 1
        if decision in ("Block", "Escalate"):
            self.blocked += 1
        elif decision == "Ignore":
            self.evaded += 1
        elif decision in ("Alert", "Log"):
            self.alerted += 1
        else:
            # Unknown decision - treat as neutral
            pass

    def to_dict(self) -> dict:
        return {
            "name":       self.name,
            "generation": self.generation,
            "sent":       self.sent,
            "blocked":    self.blocked,
            "evaded":     self.evaded,
            "evasion_rate": round(self.evasion_rate, 3),
            "params":     self.params,
        }


class MutationEngine:
    """
    Maintains a population of attack profiles.
    Reads DB records to score fitness, mutates/breeds new variants.
    """
    POPULATION_SIZE = 20
    ELITE_KEEP      = 4     # top N always survive
    MUTATION_RATE   = 0.30  # probability of mutating each param
    CROSSOVER_RATE  = 0.50

    def __init__(self):
        # Seed population from base profiles
        self.population: list[ProfileFitness] = [
            ProfileFitness(name, copy.deepcopy(params))
            for name, params in BASE_PROFILES.items()
        ]
        self._gen = 0

    # Feed DB outcome back into fitness
    def record_outcome(self, profile_name: str, decision: str, predicted: bool = False):
        """
        Record attack outcome.
        If predicted=True, attacker's evasion was predicted by IDS (fitness = 0.0).
        """
        for pf in self.population:
            if pf.name == profile_name:
                pf.record_outcome(decision)
                
                # If IDS predicted this evasion, mark it as "predicted"
                if predicted and decision == "Escalate":
                    # Predicted evasion = failure (fitness 0.0)
                    # Attacker must find NEW evasion technique
                    pf.metadata = pf.metadata or {}
                    pf.metadata["predicted_evasion"] = True
                    print(f"[mutator] {profile_name}: Evasion was PREDICTED by IDS - must evolve differently")
                
                return

    # Evolve population
    def evolve(self):
        """
        Called periodically. Sorts by fitness, keeps elites,
        breeds/mutates the rest.
        """
        self._gen += 1
        self.population.sort(key=lambda p: -p.fitness)

        elites   = self.population[:self.ELITE_KEEP]
        new_pop  = list(elites)

        while len(new_pop) < self.POPULATION_SIZE:
            # Tournament selection
            parent_a = self._tournament()
            if random.random() < self.CROSSOVER_RATE:
                parent_b = self._tournament()
                child_params = self._crossover(parent_a.params, parent_b.params)
                child_name   = f"{parent_a.name[:8]}x{parent_b.name[:8]}_g{self._gen}"
            else:
                child_params = copy.deepcopy(parent_a.params)
                child_name   = f"{parent_a.name}_g{self._gen}"

            child_params = self._mutate(child_params, parent_a.blocked > parent_a.evaded)
            child = ProfileFitness(child_name, child_params)
            child.generation = self._gen
            new_pop.append(child)

        self.population = new_pop

    def _tournament(self, k: int = 3) -> ProfileFitness:
        contestants = random.sample(self.population, min(k, len(self.population)))
        return max(contestants, key=lambda p: p.fitness)

    def _crossover(self, a: dict, b: dict) -> dict:
        """Uniform crossover of numeric params."""
        child = {}
        for key in a:
            child[key] = a[key] if random.random() < 0.5 else b.get(key, a[key])
        return child

    def _mutate(self, params: dict, was_blocked: bool) -> dict:
        """
        If was_blocked: mutate to evade — reduce rate, add entropy noise,
        randomize port, fragment bytes.
        Else: amplify slightly.
        """
        p = copy.deepcopy(params)

        def _perturb(v, scale):
            return max(0, v * (1 + random.uniform(-scale, scale)))

        if random.random() < self.MUTATION_RATE:
            if was_blocked:
                # Evasion mutations
                p["rate_hz"]  = _perturb(p["rate_hz"],  0.40)   # vary rate
                p["entropy"]  = min(1.0, _perturb(p["entropy"], 0.20))
                p["bytes_in"] = int(_perturb(p["bytes_in"], 0.30))
                # Randomize port to avoid port-based rules
                if random.random() < 0.4:
                    p["port_dst"] = random.choice([80, 443, 8080, 8443, 53, -1])
                # Fragment: lower bytes, higher rate
                if random.random() < 0.3:
                    p["bytes_in"] = max(40, p["bytes_in"] // 3)
                    p["rate_hz"]  = p["rate_hz"] * 0.5
                # Slow down to avoid burst detection
                if random.random() < 0.3:
                    p["rate_hz"]  = max(1, p["rate_hz"] * 0.1)
                    p["burst_prob"] = max(0.0, p.get("burst_prob", 0.1) - 0.2)
            else:
                # Amplify what's working
                p["rate_hz"]  = min(10000, _perturb(p["rate_hz"],  0.15))
                p["entropy"]  = min(1.0,   _perturb(p["entropy"],  0.10))
                p["bytes_in"] = int(_perturb(p["bytes_in"], 0.10))

        p["jitter"] = max(0.05, min(0.5, p.get("jitter", 0.2)))
        return p

    # Select a profile to use for next attack
    def select_profile(self) -> ProfileFitness:
        """
        Weighted random selection — higher fitness = more likely chosen.
        Occasionally picks a low-fitness one to explore.
        """
        if random.random() < 0.15:
            # Exploration: pick random
            return random.choice(self.population)
        weights = [max(0.01, p.fitness) for p in self.population]
        total   = sum(weights)
        r       = random.uniform(0, total)
        cumul   = 0.0
        for pf, w in zip(self.population, weights):
            cumul += w
            if r <= cumul:
                return pf
        return self.population[0]

    def stats(self) -> list:
        return [p.to_dict() for p in sorted(self.population, key=lambda p: -p.fitness)]
