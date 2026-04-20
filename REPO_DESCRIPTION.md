# CNNFOLE: Co-Evolutionary Neural Network Intrusion Detection System

## Project Overview

CNNFOLE is an advanced **co-evolutionary Intrusion Detection System (IDS)** that combines:
- **CNN-based feature extraction** for network traffic analysis
- **RNN-based pattern recognition** for temporal anomaly detection
- **Genetic algorithm-based attacker** that evolves evasion techniques
- **Hybrid decision engine** with database-backed threat intelligence
- **Real-time validation system** that minimizes false positives/negatives
- **C++ high-performance backend** for production deployment

## Architecture Philosophy

The system implements a **co-evolutionary arms race**:
1. **Attacker evolves** mutations to evade IDS
2. **IDS learns** from attacker's evolved patterns
3. **Validator measures** accuracy (FP/FN rates)
4. **Auto-corrector fixes** database mistakes
5. **Both systems improve** together iteratively

## Key Components

### 1. Foundation Layer (CNN)
- **Purpose**: Extract network features from raw traffic
- **Input**: Network packets (source, destination, port, protocol, flags, etc.)
- **Output**: 64-dimensional feature vectors
- **Standalone**: Yes - can be used independently for feature extraction

### 2. Pattern Recognition Layer (RNN)
- **Purpose**: Detect temporal patterns and anomalies
- **Input**: Sequence of CNN feature vectors
- **Output**: Pattern scores and anomaly indicators
- **Standalone**: Yes - can analyze traffic sequences independently

### 3. Decision Engine (Decoder)
- **Purpose**: Make final Block/Alert/Log/Ignore decisions
- **Input**: CNN features + RNN patterns + database matches
- **Output**: Decision with confidence and explanation
- **Standalone**: Yes - can make decisions with custom rules

### 4. Database Layer
- **Purpose**: Store threat signatures and learned patterns
- **Storage**: JSONL files + Pinecone vector database
- **Records**: 22,000+ learned patterns from training
- **Standalone**: Yes - can be queried independently

### 5. Attacker Engine
- **Purpose**: Generate evolved attack patterns
- **Profiles**: DoS/DDoS, PortScan, BruteForce, C2, Exfiltration, etc.
- **Evolution**: Genetic algorithm with mutation and selection
- **Standalone**: Yes - can generate attacks independently

### 6. Validation System
- **Purpose**: Track FP/FN and auto-correct database
- **Metrics**: Accuracy, Precision, Recall, F1, FPR, FNR
- **Auto-Correction**: Real-time database updates
- **Standalone**: Yes - can validate any IDS

### 7. C++ Backend (ids_pipeline)
- **Purpose**: High-performance production deployment
- **Performance**: 2-7 µs latency, 24,668 events/sec
- **Feature Parity**: 100% compatible with Python IDS
- **Standalone**: Yes - can run independently

## Build-Up Strategy

The repository is organized in **logical build-up stages**:

```
Stage 1: Foundation (CNN)
  └─ Feature extraction from network traffic
  └─ Standalone feature vector generation

Stage 2: Pattern Recognition (RNN)
  └─ Temporal pattern detection
  └─ Anomaly scoring

Stage 3: Decision Making (Decoder)
  └─ Threat classification
  └─ Decision logic (Block/Alert/Log/Ignore)

Stage 4: Database & Memory
  └─ Threat signature storage
  └─ Vector similarity matching
  └─ Pattern retrieval

Stage 5: Attacker Evolution
  └─ Attack profile generation
  └─ Genetic algorithm mutations
  └─ Evasion techniques

Stage 6: Validation & Learning
  └─ FP/FN detection
  └─ Auto-correction
  └─ Metrics tracking

Stage 7: C++ Production Backend
  └─ High-performance pipeline
  └─ Python bindings
  └─ Feature parity verification

Stage 8: Integration & Training
  └─ Co-evolutionary loop
  └─ Real-time feedback
  └─ Dashboard visualization
```

## Repository Structure

```
CNNFOLE/
├── README.md (this file)
├── REPO_DESCRIPTION.md (project overview)
├── TRAINING_ARCHITECTURE.md (training system design)
├── QUICK_START_TRAINING.md (quick reference)
│
├── Stage_1_Foundation_CNN/
│   ├── README.md (CNN component guide)
│   ├── cnn_engine.py (feature extraction)
│   └── examples/ (standalone usage)
│
├── Stage_2_Pattern_Recognition_RNN/
│   ├── README.md (RNN component guide)
│   ├── rnn_engine.py (pattern detection)
│   └── examples/ (standalone usage)
│
├── Stage_3_Decision_Engine/
│   ├── README.md (Decoder component guide)
│   ├── decoder_engine.py (decision logic)
│   └── examples/ (standalone usage)
│
├── Stage_4_Database_Memory/
│   ├── README.md (Database component guide)
│   ├── db_engine.py (threat storage)
│   ├── ids_signatures.jsonl (known signatures)
│   ├── refined_threats.jsonl (learned patterns)
│   └── examples/ (standalone usage)
│
├── Stage_5_Attacker_Evolution/
│   ├── README.md (Attacker component guide)
│   ├── attack_engine.py (attack generation)
│   ├── mutator.py (genetic algorithm)
│   ├── attack_profiles.py (attack types)
│   └── examples/ (standalone usage)
│
├── Stage_6_Validation_Learning/
│   ├── README.md (Validation component guide)
│   ├── auto_corrector.py (auto-correction)
│   ├── metrics_tracker.py (metrics calculation)
│   └── examples/ (standalone usage)
│
├── Stage_7_CPP_Backend/
│   ├── README.md (C++ IDS guide)
│   ├── ids_pipeline.cpp (Python bindings)
│   ├── ids_mutation_predictor.cpp (mutation detection)
│   ├── include/ (C++ headers)
│   └── examples/ (standalone usage)
│
├── Stage_8_Integration/
│   ├── README.md (Integration guide)
│   ├── run.py (main entry point)
│   ├── event_bus.py (event system)
│   ├── network/ (packet capture)
│   ├── visualizer/ (dashboard)
│   └── tests/ (integration tests)
│
└── real_datasets/ (training data)
    └── 19 CSV files from ISCX/NSL-KDD
```

## Quick Start

### Option 1: Full System Training
```bash
cd ai-architecture
python start_training_with_validation.bat
```

### Option 2: Individual Components
```bash
# Test CNN feature extraction
python Stage_1_Foundation_CNN/examples/test_cnn.py

# Test RNN pattern detection
python Stage_2_Pattern_Recognition_RNN/examples/test_rnn.py

# Test decision engine
python Stage_3_Decision_Engine/examples/test_decoder.py

# Test database
python Stage_4_Database_Memory/examples/test_database.py

# Test attacker
python Stage_5_Attacker_Evolution/examples/test_attacker.py

# Test validation
python Stage_6_Validation_Learning/examples/test_validation.py

# Test C++ backend
python Stage_7_CPP_Backend/examples/test_cpp_ids.py
```

## Key Features

### Co-Evolution
- Attacker evolves mutations based on IDS decisions
- IDS learns from attacker's evolved patterns
- Both systems improve iteratively

### Validation & Auto-Correction
- Real-time FP/FN detection
- Automatic database correction
- Metrics tracking (Accuracy, Precision, Recall, FPR, FNR)

### High Performance
- Python: 100-500 events/sec
- C++: 24,668 events/sec (247x faster)
- 2-7 µs latency per event

### Production Ready
- C++ backend for deployment
- 100% feature parity with Python
- Real-time packet capture
- Dashboard visualization

## Training Results

After training with 22,000+ records:
- **Accuracy**: 93%+
- **Precision**: 92%+
- **Recall**: 92%+
- **FPR**: < 7%
- **FNR**: < 8%

## Documentation

Each stage has its own README with:
- Component overview
- Standalone usage examples
- Integration points
- Performance metrics
- Troubleshooting guide

## Next Steps

1. Start with Stage 1 (CNN) to understand feature extraction
2. Progress through stages 2-6 to build understanding
3. Review Stage 7 (C++) for production deployment
4. Use Stage 8 for full system integration
5. Run training with validation for co-evolution

---

**Status**: Production Ready ✓
**Last Updated**: April 20, 2026
**Version**: 1.0.0
