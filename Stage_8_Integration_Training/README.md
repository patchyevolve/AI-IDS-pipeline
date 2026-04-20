# Stage 8: Integration & Training - Full System Co-Evolution

## Overview

Stage 8 integrates all previous stages into a complete co-evolutionary IDS system where the attacker and IDS improve together.

**Purpose**: Run the complete system with real-time co-evolution, validation, and learning.

**Standalone**: No - requires all previous stages (1-7).

**Dependencies**: All stages (CNN, RNN, Decoder, Database, Attacker, Validation, C++ Backend).

## What It Does

### Input
Network traffic (live or synthetic):
```python
{
    "source": "192.168.1.100",
    "destination": "10.0.0.1",
    "port_dst": 80,
    "protocol": 6,
    "flags": 0x02,
    "payload_size": 1024,
    "rate_hz": 100.0,
}
```

### Processing
1. **Attacker** generates evolved attack patterns
2. **IDS** processes packets through all stages
3. **Validator** checks correctness (FP/FN)
4. **Auto-Corrector** learns from mistakes
5. **Attacker** evolves based on feedback
6. **Loop repeats** → Both improve

### Output
Training results:
```python
{
    "session_duration": 3600,
    "total_events": 1000000,
    "accuracy": 0.93,
    "precision": 0.928,
    "recall": 0.928,
    "fpr": 0.068,
    "fnr": 0.072,
    "attacker_evasion_rate": 0.35,
    "database_size": 22385,
    "generations": 42,
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│           CO-EVOLUTIONARY TRAINING LOOP                 │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐         ┌──────────────┐             │
│  │   ATTACKER   │         │   IDS        │             │
│  │              │────────>│              │             │
│  │ • Generates  │ events  │ • CNN        │             │
│  │   mutations  │ with    │ • RNN        │             │
│  │ • Evolves    │ ground  │ • Decoder    │             │
│  │   profiles   │ truth   │ • Database   │             │
│  │              │         │              │             │
│  └──────────────┘         └──────┬───────┘             │
│         ^                        │                     │
│         │                        v                     │
│         │                 ┌──────────────┐             │
│         │                 │  VALIDATOR   │             │
│         │                 │              │             │
│         │                 │ • Detects    │             │
│         │                 │   FP/FN      │             │
│         │                 │ • Tracks     │             │
│         │                 │   metrics    │             │
│         │                 │              │             │
│         │                 └──────┬───────┘             │
│         │                        │                     │
│         │                        v                     │
│         │                 ┌──────────────┐             │
│         │                 │ AUTO-        │             │
│         │                 │ CORRECTOR    │             │
│         │                 │              │             │
│         │                 │ • Adds FN    │             │
│         │                 │   records    │             │
│         │                 │ • Adds FP    │             │
│         │                 │   records    │             │
│         │                 │              │             │
│         │                 └──────┬───────┘             │
│         │                        │                     │
│         │                        v                     │
│         │                 ┌──────────────┐             │
│         │                 │  DATABASE    │             │
│         │                 │              │             │
│         │                 │ • Grows with │             │
│         │                 │   learned    │             │
│         │                 │   patterns   │             │
│         │                 │              │             │
│         └─────────────────┤ • Feedback   │             │
│                           │   to         │             │
│                           │   attacker   │             │
│                           └──────────────┘             │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Training Flow

### Phase 1: Initialization
```
1. Load CNN, RNN, Decoder models
2. Initialize Database (24,000+ records)
3. Create Attacker population (30 profiles)
4. Initialize Validator
5. Start Event Bus
```

### Phase 2: Co-Evolution Loop
```
For each generation:
  1. Attacker generates attacks
  2. IDS processes packets
  3. Validator checks correctness
  4. Auto-corrector learns
  5. Attacker receives feedback
  6. Attacker evolves
  7. Repeat
```

### Phase 3: Monitoring
```
Every 5 minutes:
  1. Calculate metrics
  2. Update dashboard
  3. Log statistics
  4. Export signatures
```

### Phase 4: Completion
```
1. Stop attacker
2. Generate final report
3. Export database
4. Save metrics
5. Display results
```

## Running Full System

### Option 1: Python IDS with Validation
```bash
cd ai-architecture
python start_training_with_validation.bat
```

This will:
- Start IDS with `--validate` flag
- Start Attacker with `--remote` flag
- Track FP/FN in real-time
- Auto-correct database
- Generate validation report

### Option 2: C++ IDS with Validation
```bash
cd ai-architecture
python run.py --synthetic --validate --cpp
```

This will:
- Use C++ backend (247x faster)
- Enable validation
- Use synthetic targets
- Generate report

### Option 3: Extended Training (1 hour)
```bash
cd ai-architecture
python start_extended_training.bat
```

This will:
- Run for 3600 seconds
- Accumulate more data
- Better convergence

### Option 4: Custom Configuration
```python
import sys
sys.argv = [
    'run.py',
    '--synthetic',      # Use synthetic targets
    '--validate',       # Enable validation
    '--cpp',            # Use C++ backend
    '--duration', '3600',  # Run for 1 hour
]

from ai_architecture.run import main
main()
```

## Training Configuration

### Attacker Settings
```python
{
    "rate_limit": 0.4,              # Min seconds between attacks
    "evolve_interval": 30,          # Evolve every N attacks
    "population_size": 30,          # Number of profiles
    "mutation_rate": 0.2,           # Mutation probability
    "crossover_rate": 0.7,          # Crossover probability
}
```

### IDS Settings
```python
{
    "block_threshold": 0.85,        # Block if > 0.85 anomaly
    "alert_threshold": 0.75,        # Alert if > 0.75 anomaly
    "log_threshold": 0.60,          # Log if > 0.60 anomaly
    "db_similarity_threshold": 0.92, # Use DB if > 0.92 similarity
}
```

### Validation Settings
```python
{
    "track_metrics": True,          # Track FP/FN
    "auto_correct": True,           # Auto-correct database
    "report_interval": 300,         # Report every 5 minutes
    "output_dir": "validation",     # Report directory
}
```

## Monitoring

### Real-Time Dashboard
```bash
# View live metrics
python ai-architecture/visualizer/dashboard.py
```

Shows:
- IDS decisions (Block/Alert/Log/Ignore)
- Attacker evasion rate
- Database size
- Validation metrics
- Performance graphs

### Command Line Monitoring
```bash
# Monitor in terminal
python ai-architecture/visualizer/fast_cli.py
```

Shows:
- Events processed
- Decisions made
- Evasion rate
- Metrics

### Log Files
```
logs/
├── ids_training.log      # IDS output
├── attacker_training.log # Attacker output
└── validation_report.json # Final metrics
```

## Results

### After Training (1 hour)

**Database Growth**:
```
Initial:  1,685 signatures
Learned:  22,385 patterns
Total:    24,070 records
Growth:   1,330% increase
```

**IDS Performance**:
```
Accuracy:  93%+
Precision: 92%+
Recall:    92%+
FPR:       < 7%
FNR:       < 8%
```

**Attacker Evolution**:
```
Generations:    42
Evasion Rate:   35%
Best Fitness:   0.72
Population:     30 profiles
```

**Performance**:
```
Python:  100-500 events/sec
C++:     24,668 events/sec
Latency: 2-7 µs per event
```

## Integration Points

### Stage 1: CNN
```python
cnn_output = cnn.process_event(event)
```

### Stage 2: RNN
```python
rnn_output = rnn.process_features(cnn_output)
```

### Stage 3: Decoder
```python
decision = decoder.decode(cnn_output, rnn_output, db_matches)
```

### Stage 4: Database
```python
db_matches = db.retrieve_memory(embedding=cnn_output["feature_vector"])
```

### Stage 5: Attacker
```python
attacker.process_feedback(decision)
```

### Stage 6: Validation
```python
validator.validate_and_correct(event)
```

### Stage 7: C++ Backend
```python
if use_cpp:
    cpp_pipeline = CppPipeline(bus, db=db, bridge=bridge)
```

## Testing

### Integration Test
```bash
python tests/test_integration.py
```

### Full Training Test
```bash
python tests/test_full_training.py
```

### Performance Test
```bash
python tests/benchmark_full_system.py
```

## Troubleshooting

### Issue: Training not converging
**Solution**: Increase training duration
```bash
python start_extended_training.bat
# Edit DURATION variable to 7200 (2 hours)
```

### Issue: High FPR
**Solution**: Increase decision thresholds
```python
decoder.block_threshold = 0.90
decoder.alert_threshold = 0.85
```

### Issue: High FNR
**Solution**: Lower decision thresholds
```python
decoder.block_threshold = 0.80
decoder.alert_threshold = 0.75
```

### Issue: Slow performance
**Solution**: Use C++ backend
```bash
python run.py --synthetic --validate --cpp
```

## Advanced Usage

### Multi-Run Comparison
```python
# Run multiple training sessions
results = []
for i in range(3):
    result = run_training(duration=3600)
    results.append(result)

# Compare results
avg_accuracy = sum(r['accuracy'] for r in results) / len(results)
print(f"Average accuracy: {avg_accuracy:.2%}")
```

### Hyperparameter Tuning
```python
# Test different configurations
configs = [
    {"block_threshold": 0.80, "alert_threshold": 0.70},
    {"block_threshold": 0.85, "alert_threshold": 0.75},
    {"block_threshold": 0.90, "alert_threshold": 0.80},
]

for config in configs:
    result = run_training(config=config)
    print(f"Config {config}: Accuracy={result['accuracy']:.2%}")
```

### Ensemble Training
```python
# Train multiple IDS instances
ids_instances = [
    create_ids(seed=1),
    create_ids(seed=2),
    create_ids(seed=3),
]

# Combine decisions
for event in events:
    decisions = [ids.process(event) for ids in ids_instances]
    final_decision = ensemble_vote(decisions)
```

## Deployment

### Production Deployment
```bash
# 1. Train system
python start_training_with_validation.bat

# 2. Export trained database
cp ai-architecture/database/refined_threats.jsonl /opt/ids/

# 3. Deploy C++ backend
python ai-architecture/cpp/build.py --release

# 4. Run in production
python ai-architecture/run.py --cpp
```

### Docker Deployment
```dockerfile
FROM python:3.12

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential cmake libpcap-dev

# Copy code
COPY . /app
WORKDIR /app

# Build C++ backend
RUN python ai-architecture/cpp/build.py --release

# Train system
RUN python ai-architecture/start_training_with_validation.bat

# Run in production
CMD ["python", "ai-architecture/run.py", "--cpp"]
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ids-production
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: ids
        image: ids-production:latest
        args: ["python", "run.py", "--cpp"]
        resources:
          requests:
            memory: "200Mi"
            cpu: "500m"
          limits:
            memory: "500Mi"
            cpu: "1000m"
```

## Files

- `ai-architecture/run.py` - Main entry point
- `ai-architecture/event_bus.py` - Event system
- `ai-architecture/start_production_training.bat` - Training script
- `ai-architecture/start_extended_training.bat` - Extended training
- `ai-architecture/visualizer/dashboard.py` - Dashboard
- `ai-architecture/tests/test_integration.py` - Integration tests

## References

- Co-Evolution: Arms race between attacker and defender
- Event Bus: Asynchronous event processing
- Real-time Validation: FP/FN detection during training
- Auto-Correction: Learning from mistakes

---

**Status**: Production Ready ✓
**Standalone**: No - requires all stages ✓
**Complete System**: Yes ✓
**Final Stage**: Stage 8 - Integration & Training
