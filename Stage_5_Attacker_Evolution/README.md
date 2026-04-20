# Stage 5: Attacker Evolution - Genetic Algorithm-Based Attack Generation

## Overview

The Attacker Engine generates evolved attack patterns using genetic algorithms to find IDS evasion techniques.

**Purpose**: Evolve attack profiles to discover IDS weaknesses and drive co-evolutionary improvement.

**Standalone**: Yes - can be used independently for attack generation and evolution.

**Dependencies**: Optional - can work with or without IDS feedback.

## What It Does

### Input
IDS decisions (feedback):
```python
{
    "decision": "Block",           # IDS decision
    "confidence": 0.95,            # IDS confidence
    "attack_class": "DoS/DDoS",    # Detected class
    "timestamp": "2026-04-20T10:30:00",
}
```

### Processing
1. **Profile Selection**: Choose attack profile
2. **Mutation**: Apply genetic algorithm mutations
3. **Attack Generation**: Create attack packets
4. **Feedback Integration**: Learn from IDS decisions
5. **Evolution**: Select best-performing mutations

### Output
Evolved attack patterns:
```python
{
    "profile": "DoS_v5_gen42",
    "attack_class": "DoS/DDoS",
    "packets": [
        {"source": "192.168.1.100", "destination": "10.0.0.1", ...},
        {"source": "192.168.1.101", "destination": "10.0.0.1", ...},
        ...
    ],
    "evasion_rate": 0.35,          # % of packets evaded
    "generation": 42,
    "fitness": 0.72,               # Fitness score
}
```

## Architecture

```
Base Attack Profiles
    ├─ DoS/DDoS
    ├─ PortScan
    ├─ BruteForce
    ├─ C2/Exfiltration
    └─ DNS Tunnel
    ↓
[Genetic Algorithm]
    ├─ Selection: Choose best profiles
    ├─ Crossover: Mix profiles
    ├─ Mutation: Modify parameters
    └─ Evaluation: Test against IDS
    ↓
[Mutation Operators]
    ├─ Rate mutation (packet rate)
    ├─ Payload mutation (data content)
    ├─ Timing mutation (inter-packet timing)
    ├─ Port mutation (destination ports)
    └─ Flag mutation (TCP flags)
    ↓
[Attack Generation]
    ├─ Create packets
    ├─ Send to IDS
    └─ Collect feedback
    ↓
[Feedback Integration]
    ├─ Blocked: Reduce fitness
    ├─ Alerted: Reduce fitness
    ├─ Logged: Increase fitness
    └─ Ignored: Maximize fitness
    ↓
[Evolution]
    ├─ Calculate fitness
    ├─ Select survivors
    ├─ Generate next generation
    └─ Repeat
    ↓
Evolved Attack Profiles
```

## Attack Profiles

### 1. DoS/DDoS
- **Characteristics**: High packet rate, low entropy, repetitive
- **Mutations**: Rate, payload size, flag patterns
- **Evasion**: Vary timing, randomize payloads
- **Example**: SYN flood with randomized source IPs

### 2. PortScan
- **Characteristics**: Sequential ports, low payload, varied destinations
- **Mutations**: Port sequence, scan speed, destination range
- **Evasion**: Randomize port order, vary scan rate
- **Example**: Slow port scan with random intervals

### 3. BruteForce
- **Characteristics**: Repeated attempts, similar features, high rate
- **Mutations**: Attempt rate, credential variations, timing
- **Evasion**: Vary timing between attempts, randomize credentials
- **Example**: SSH brute force with random delays

### 4. C2/Exfiltration
- **Characteristics**: Periodic beacons, encrypted, consistent timing
- **Mutations**: Beacon interval, payload size, encryption
- **Evasion**: Vary beacon timing, randomize payload
- **Example**: DNS tunnel with variable query intervals

### 5. DNS Tunnel
- **Characteristics**: DNS queries with data, high entropy
- **Mutations**: Query frequency, domain names, data encoding
- **Evasion**: Vary query patterns, randomize domains
- **Example**: DNS exfiltration with random subdomains

## Genetic Algorithm

### Population
- **Size**: 20-50 profiles
- **Diversity**: Mix of all attack types
- **Fitness**: Based on evasion rate

### Selection
- **Method**: Tournament selection
- **Tournament Size**: 3-5 profiles
- **Pressure**: Higher fitness = higher selection probability

### Crossover
- **Method**: Uniform crossover
- **Rate**: 70% of offspring
- **Result**: Mix of parent profiles

### Mutation
- **Rate**: 20-30% of offspring
- **Operators**: 5 mutation types
- **Intensity**: Varies by generation

### Fitness Function
```python
fitness = (
    0.4 * evasion_rate +           # How many packets evaded?
    0.3 * (1 - detection_rate) +   # How many not detected?
    0.2 * (1 - alert_rate) +       # How many not alerted?
    0.1 * diversity_score          # How different from others?
)
```

## Standalone Usage

### Basic Example
```python
from attacker.attack_engine import AttackEngine
from event_bus import EventBus

# Initialize
bus = EventBus()
attacker = AttackEngine(
    event_bus=bus,
    synthetic_targets=True,
    rate_limit=0.4,
)

# Start attacking
attacker.start()

# Let it run for a while
import time
time.sleep(60)

# Get statistics
stats = attacker.stats
print(f"Total sent: {stats['total_sent']}")
print(f"Total evaded: {stats['total_evaded']}")
print(f"Evasion rate: {stats['total_evaded'] / stats['total_sent']:.2%}")
print(f"Generations: {stats['generation']}")

# Stop
attacker.stop()
```

### Custom Profile
```python
# Lock to specific profile
attacker = AttackEngine(
    event_bus=bus,
    locked_profile="DoS/DDoS",  # Only DoS attacks
)

attacker.start()
time.sleep(60)
attacker.stop()
```

### Feedback Integration
```python
# Attacker learns from IDS decisions
def on_ids_decision(decision):
    # Attacker receives feedback
    attacker.process_feedback(decision)

bus.subscribe("decoder_output", on_ids_decision)

attacker.start()
# Attacker evolves based on feedback
```

### Population Analysis
```python
# Analyze population
pop_stats = attacker.population_stats()
print(f"Population size: {pop_stats['size']}")
print(f"Average fitness: {pop_stats['avg_fitness']:.2f}")
print(f"Best fitness: {pop_stats['best_fitness']:.2f}")
print(f"Diversity: {pop_stats['diversity']:.2f}")

# Get best profiles
best = attacker.get_best_profiles(top_n=5)
for profile in best:
    print(f"{profile['name']}: fitness={profile['fitness']:.2f}")
```

## Performance

| Metric | Value |
|--------|-------|
| **Attack Rate** | 0.1-1.0 attacks/sec |
| **Packet Rate** | 100-10,000 packets/sec |
| **Generation Time** | 30-60 seconds |
| **Population Size** | 20-50 profiles |
| **Evasion Rate** | 10-50% (improves over time) |
| **Evolution Speed** | 1-5 generations/minute |

## Integration Points

### From Stage 3: IDS Decisions
```python
# Attacker receives IDS feedback
bus.subscribe("decoder_output", attacker.process_feedback)
```

### To Stage 6: Validation
```python
# Validator tracks attacker's evasion success
validator.validate_and_correct({
    "is_attack": True,
    "decision": ids_decision,
    "attack_class": attacker_profile,
})
```

### To Stage 8: Co-Evolution
```python
# Full co-evolutionary loop
# IDS learns from attacker
# Attacker evolves against IDS
# Both improve together
```

## Testing

Run the attacker test:
```bash
python Stage_5_Attacker_Evolution/examples/test_attacker.py
```

Expected output:
```
Attacker Evolution Test
=======================
Initializing population...
✓ Created 30 profiles

Generation 1:
  Best fitness: 0.45
  Avg evasion: 15%
  Blocked: 85%

Generation 2:
  Best fitness: 0.52
  Avg evasion: 22%
  Blocked: 78%

Generation 3:
  Best fitness: 0.58
  Avg evasion: 28%
  Blocked: 72%

...

Generation 10:
  Best fitness: 0.72
  Avg evasion: 45%
  Blocked: 55%

Evolution complete!
Final evasion rate: 45%
```

## Troubleshooting

### Issue: Evasion rate not improving
**Solution**: Check IDS feedback
```python
# Verify attacker is receiving feedback
if not attacker.feedback_received:
    print("WARNING: No feedback from IDS")
    # Check event bus connections
```

### Issue: Population diversity decreasing
**Solution**: Increase mutation rate
```python
attacker.mutation_rate = 0.4  # Was 0.2
attacker.crossover_rate = 0.6  # Was 0.7
```

### Issue: Slow evolution
**Solution**: Increase population size
```python
attacker = AttackEngine(
    event_bus=bus,
    population_size=50,  # Was 30
)
```

## Advanced Usage

### Multi-Profile Evolution
```python
# Evolve multiple profiles simultaneously
profiles = ["DoS/DDoS", "PortScan", "BruteForce"]
for profile in profiles:
    attacker = AttackEngine(
        event_bus=bus,
        locked_profile=profile,
    )
    attacker.start()
    time.sleep(60)
    attacker.stop()
```

### Fitness Landscape Analysis
```python
# Analyze fitness landscape
fitness_history = attacker.get_fitness_history()

import matplotlib.pyplot as plt
plt.plot(fitness_history)
plt.xlabel('Generation')
plt.ylabel('Best Fitness')
plt.title('Fitness Evolution')
plt.show()
```

### Mutation Analysis
```python
# Analyze which mutations are most effective
mutation_stats = attacker.get_mutation_stats()
for mutation_type, effectiveness in mutation_stats.items():
    print(f"{mutation_type}: {effectiveness:.2%} effective")
```

### Evasion Techniques
```python
# Get evolved evasion techniques
techniques = attacker.get_evasion_techniques()
for technique in techniques:
    print(f"Technique: {technique['name']}")
    print(f"  Effectiveness: {technique['effectiveness']:.2%}")
    print(f"  Mutations: {technique['mutations']}")
```

## Mutation Operators

### 1. Rate Mutation
- **Parameter**: Packet rate (packets/sec)
- **Range**: 10-10,000 packets/sec
- **Effect**: Slower attacks evade better

### 2. Payload Mutation
- **Parameter**: Payload content and size
- **Range**: 0-65,535 bytes
- **Effect**: Randomized payloads evade pattern matching

### 3. Timing Mutation
- **Parameter**: Inter-packet timing
- **Range**: 0.001-10 seconds
- **Effect**: Variable timing evades rate-based detection

### 4. Port Mutation
- **Parameter**: Destination ports
- **Range**: 1-65,535
- **Effect**: Varied ports evade port-based rules

### 5. Flag Mutation
- **Parameter**: TCP flags
- **Range**: All valid flag combinations
- **Effect**: Unusual flags evade signature detection

## Statistics

### Per-Attack
```python
{
    "profile": "DoS_v5_gen42",
    "sent": 100,
    "blocked": 65,
    "alerted": 10,
    "logged": 15,
    "ignored": 10,
    "evasion_rate": 0.35,
}
```

### Per-Generation
```python
{
    "generation": 42,
    "population_size": 30,
    "best_fitness": 0.72,
    "avg_fitness": 0.58,
    "diversity": 0.65,
    "total_sent": 3000,
    "total_evaded": 1050,
}
```

## Next Steps

1. **Understand profiles**: Review attack types
2. **Test standalone**: Run examples
3. **Integrate with IDS**: Connect feedback loop
4. **Analyze evolution**: Track fitness over time
5. **Move to Stage 6**: Validation & Learning

## Files

- `attacker/attack_engine.py` - Main attacker implementation
- `attacker/mutator.py` - Genetic algorithm
- `attacker/attack_profiles.py` - Attack definitions
- `Stage_5_Attacker_Evolution/examples/test_attacker.py` - Test suite
- `Stage_5_Attacker_Evolution/examples/evolution_analysis.py` - Analysis tools

## References

- Genetic Algorithm: Population-based optimization
- Mutation Operators: Parameter variation strategies
- Fitness Function: Multi-objective optimization
- Co-Evolution: Arms race between attacker and defender

---

**Status**: Production Ready ✓
**Standalone**: Yes ✓
**Dependencies**: Optional (Stage 3 for feedback) ✓
**Next Stage**: Stage 6 - Validation & Learning
