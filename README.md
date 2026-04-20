# CNNFOLE: Co-Evolutionary Neural Network Intrusion Detection System

[![GitHub](https://img.shields.io/badge/GitHub-patchyevolve%2FAI--IDS--pipeline-blue)](https://github.com/patchyevolve/AI-IDS-pipeline)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)]()
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)]()
[![License](https://img.shields.io/badge/License-MIT-green)]()

## Overview

CNNFOLE is an advanced **co-evolutionary Intrusion Detection System** that combines deep learning with genetic algorithms to detect and adapt to evolving network attacks.

### Key Features

- **CNN-based Feature Extraction**: 64-dimensional feature vectors from network traffic
- **RNN Pattern Recognition**: Temporal anomaly detection using LSTM
- **Hybrid Decision Engine**: Multi-factor threat assessment
- **Co-Evolutionary Training**: Attacker evolves evasions, IDS learns defenses
- **Real-time Validation**: FP/FN detection and auto-correction
- **High Performance**: 24,668 events/sec with C++ backend
- **Production Ready**: 93%+ accuracy with < 7% FPR

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/patchyevolve/AI-IDS-pipeline.git
cd AI-IDS-pipeline

# Install dependencies
pip install -r ai-architecture/requirements.txt

# Build C++ backend (optional)
python ai-architecture/cpp/build.py
```

### Training with Validation

```bash
cd ai-architecture
python start_training_with_validation.bat
```

This will:
1. Start IDS with real-time validation
2. Start Attacker with co-evolutionary mutations
3. Track FP/FN automatically
4. Auto-correct database mistakes
5. Generate validation report

### Individual Component Testing

```bash
# Test CNN feature extraction
python Stage_1_Foundation_CNN/examples/test_cnn.py

# Test RNN pattern detection
python Stage_2_Pattern_Recognition_RNN/examples/test_rnn.py

# Test decision engine
python Stage_3_Decision_Engine/examples/test_decoder.py

# Test validation system
python tests/test_validation_metrics.py
```

## Architecture

### 8-Stage Build-Up

```
Stage 1: CNN Foundation
  └─ Feature extraction (64 dims)

Stage 2: RNN Pattern Recognition
  └─ Temporal anomaly detection

Stage 3: Decision Engine
  └─ Block/Alert/Log/Ignore decisions

Stage 4: Database & Memory
  └─ Threat signature storage

Stage 5: Attacker Evolution
  └─ Genetic algorithm mutations

Stage 6: Validation & Learning
  └─ FP/FN detection & auto-correction

Stage 7: C++ Backend
  └─ High-performance production deployment

Stage 8: Integration & Training
  └─ Co-evolutionary loop
```

### System Flow

```
Network Traffic
    ↓
[CNN] Extract Features (64 dims)
    ↓
[RNN] Detect Patterns (Anomaly Score)
    ↓
[Database] Lookup Similar Threats
    ↓
[Decoder] Make Decision (Block/Alert/Log/Ignore)
    ↓
[Validator] Check Correctness (FP/FN)
    ↓
[Auto-Corrector] Learn from Mistakes
    ↓
[Attacker] Evolve Evasions
    ↓
Loop Back to CNN
```

## Performance

| Metric | Value |
|--------|-------|
| **Accuracy** | 93%+ |
| **Precision** | 92%+ |
| **Recall** | 92%+ |
| **False Positive Rate** | < 7% |
| **False Negative Rate** | < 8% |
| **Latency (Python)** | 100-500 events/sec |
| **Latency (C++)** | 24,668 events/sec |
| **Per-Event Latency** | 2-7 µs |

## Training Results

After training with 22,000+ records:

```
Database Statistics:
  - ids_signatures.jsonl: 1,685 records (known signatures)
  - refined_threats.jsonl: 22,385 records (learned patterns)
  - synthetic_from_datasets.jsonl: 500 records (base data)

Decision Distribution:
  - Log: 55% (low confidence threats)
  - Escalate: 35% (medium confidence)
  - Alert: 6% (high confidence)
  - Block: 4% (immediate action)

Attack Classes Learned:
  - DoS/DDoS: 952 patterns
  - PortScan: 103 patterns
  - BruteForce: 200+ patterns
  - C2/Exfiltration: 134 patterns
  - Unknown High Severity: 7,689 patterns
```

## Documentation

### Main Documentation
- **[REPO_DESCRIPTION.md](REPO_DESCRIPTION.md)** - Complete project overview
- **[TRAINING_ARCHITECTURE.md](ai-architecture/TRAINING_ARCHITECTURE.md)** - Training system design
- **[QUICK_START_TRAINING.md](ai-architecture/QUICK_START_TRAINING.md)** - Quick reference

### Stage Documentation
- **[Stage 1: CNN Foundation](Stage_1_Foundation_CNN/README.md)** - Feature extraction
- **[Stage 2: RNN Pattern Recognition](Stage_2_Pattern_Recognition_RNN/README.md)** - Temporal analysis
- **[Stage 3: Decision Engine](Stage_3_Decision_Engine/README.md)** - Decision making
- **[Stage 4: Database & Memory](ai-architecture/database/README.md)** - Threat storage
- **[Stage 5: Attacker Evolution](ai-architecture/attacker/README.md)** - Attack generation
- **[Stage 6: Validation & Learning](ai-architecture/validation/README.md)** - FP/FN detection
- **[Stage 7: C++ Backend](ai-architecture/cpp/README.md)** - Production deployment
- **[Stage 8: Integration](ai-architecture/README.md)** - Full system

## Components

### Python IDS Pipeline
- **CNN Engine** (`ai-architecture/cnn/cnn_engine.py`) - Feature extraction
- **RNN Engine** (`ai-architecture/rnn/rnn_engine.py`) - Pattern detection
- **Decoder** (`ai-architecture/decoder/decoder_engine.py`) - Decision making
- **Database** (`ai-architecture/database/db_engine.py`) - Threat storage
- **Validator** (`ai-architecture/validation/auto_corrector.py`) - FP/FN detection

### Attacker Engine
- **Attack Engine** (`ai-architecture/attacker/attack_engine.py`) - Attack generation
- **Mutator** (`ai-architecture/attacker/mutator.py`) - Genetic algorithm
- **Profiles** (`ai-architecture/attacker/attack_profiles.py`) - Attack types

### C++ Backend
- **ids_pipeline.cpp** - Python bindings
- **ids_mutation_predictor.cpp** - Mutation detection
- **ids_capture.hpp** - Packet capture

### Network & Integration
- **Event Bus** (`ai-architecture/event_bus.py`) - Event system
- **IDS Bridge** (`ai-architecture/network/ids_bridge.py`) - Packet capture
- **Dashboard** (`ai-architecture/visualizer/dashboard.py`) - Real-time visualization

## Usage Examples

### Basic IDS Usage
```python
from ai_architecture.cnn.cnn_engine import CNNEngine
from ai_architecture.rnn.rnn_engine import RNNEngine
from ai_architecture.decoder.decoder_engine import HybridDecoder
from ai_architecture.database.db_engine import DatabaseEngine
from ai_architecture.event_bus import EventBus

# Initialize
bus = EventBus()
cnn = CNNEngine(bus)
rnn = RNNEngine(bus)
db = DatabaseEngine(bus)
decoder = HybridDecoder(bus)

# Process packet
event = {
    "source": "192.168.1.100",
    "destination": "10.0.0.1",
    "port_dst": 80,
    "protocol": 6,
    "flags": 0x02,
    "payload_size": 1024,
    "rate_hz": 100.0,
}

# Get decision
cnn_out = cnn.process_event(event)
rnn_out = rnn.process_features(cnn_out)
db_matches = db.retrieve_memory(embedding=cnn_out["feature_vector"])
decision = decoder.decode(cnn_out, rnn_out, db_matches["retrieved"])

print(f"Decision: {decision['decision']}")
print(f"Confidence: {decision['confidence']:.2f}")
```

### Standalone Component Usage
```python
# Use CNN independently
features = cnn.process_event(event)
print(f"Feature vector: {features['feature_vector']}")

# Use RNN independently
patterns = rnn.process_features(features)
print(f"Anomaly score: {patterns['anomaly_score']}")

# Use database independently
matches = db.retrieve_memory(embedding=features['feature_vector'])
print(f"Similar threats: {len(matches['retrieved'])}")
```

## Training

### Co-Evolutionary Training
```bash
cd ai-architecture
python start_training_with_validation.bat
```

### Extended Training (1 hour)
```bash
cd ai-architecture
python start_extended_training.bat
```

### Custom Training
```python
from ai_architecture.run import main
import sys

sys.argv = ['run.py', '--synthetic', '--validate']
main()
```

## Validation & Metrics

The system tracks:
- **Accuracy**: Overall correctness
- **Precision**: How many alerts are real attacks?
- **Recall**: How many attacks are detected?
- **F1 Score**: Balanced metric
- **FPR**: False Positive Rate
- **FNR**: False Negative Rate

Reports saved to:
- `validation/validation_report.json` - Final metrics
- `validation/metrics_timeline.jsonl` - Per-event log

## Testing

```bash
# Run all tests
python -m pytest tests/

# Run specific test
python tests/test_cpp_ids.py
python tests/test_validation_metrics.py
python tests/test_auto_correction.py
```

## Performance Optimization

### Python Backend
- Latency: 100-500 events/sec
- Memory: 500 MB - 1 GB
- Best for: Development, research

### C++ Backend
- Latency: 24,668 events/sec (247x faster)
- Memory: 50-100 MB
- Best for: Production deployment

Build C++ backend:
```bash
python ai-architecture/cpp/build.py
```

## Deployment

### Production Deployment
```bash
cd ai-architecture
python run.py --synthetic --cpp
```

### Live Packet Capture
```bash
cd ai-architecture
python run.py  # Requires admin/root
```

### Remote Attacker
```bash
cd ai-architecture
python attacker/run_attacker.py --remote <IDS_IP>
```

## Architecture Highlights

### Co-Evolution
- Attacker evolves mutations based on IDS decisions
- IDS learns from attacker's evolved patterns
- Both systems improve iteratively
- Arms race drives continuous improvement

### Validation & Auto-Correction
- Real-time FP/FN detection
- Automatic database correction
- Prevents same mistakes from repeating
- Metrics guide co-evolution

### High Performance
- CNN: < 1 µs per packet
- RNN: 1-5 µs per sequence
- Decoder: 2-10 µs per decision
- C++: 2-7 µs total latency

### Production Ready
- 100% feature parity (Python ↔ C++)
- Real-time packet capture
- Dashboard visualization
- Comprehensive logging

## Repository Structure

```
AI-IDS-pipeline/
├── README.md (this file)
├── REPO_DESCRIPTION.md (project overview)
├── .gitignore
│
├── Stage_1_Foundation_CNN/
│   └── README.md (CNN guide)
│
├── Stage_2_Pattern_Recognition_RNN/
│   └── README.md (RNN guide)
│
├── Stage_3_Decision_Engine/
│   └── README.md (Decoder guide)
│
├── ai-architecture/
│   ├── cnn/ (CNN implementation)
│   ├── rnn/ (RNN implementation)
│   ├── decoder/ (Decision engine)
│   ├── database/ (Threat storage)
│   ├── attacker/ (Attack generation)
│   ├── validation/ (FP/FN detection)
│   ├── cpp/ (C++ backend)
│   ├── network/ (Packet capture)
│   ├── visualizer/ (Dashboard)
│   ├── tests/ (Test suite)
│   └── run.py (Main entry point)
│
└── real_datasets/ (Training data)
    └── 19 CSV files from ISCX/NSL-KDD
```

## Requirements

- Python 3.9+
- NumPy, SciPy, Scikit-learn
- PyTorch or TensorFlow
- Scapy (for packet capture)
- Pinecone (for vector database)
- C++17 compiler (for C++ backend)

See `ai-architecture/requirements.txt` for full list.

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - See LICENSE file for details

## Citation

If you use CNNFOLE in your research, please cite:

```bibtex
@software{cnnfole2026,
  title={CNNFOLE: Co-Evolutionary Neural Network Intrusion Detection System},
  author={AI-IDS-Pipeline Contributors},
  year={2026},
  url={https://github.com/patchyevolve/AI-IDS-pipeline}
}
```

## Contact

- **GitHub**: [patchyevolve/AI-IDS-pipeline](https://github.com/patchyevolve/AI-IDS-pipeline)
- **Issues**: [GitHub Issues](https://github.com/patchyevolve/AI-IDS-pipeline/issues)

## Acknowledgments

- ISCX/NSL-KDD datasets for training data
- PyTorch/TensorFlow communities
- Scapy for packet processing
- Pinecone for vector database

---

**Status**: Production Ready ✓
**Last Updated**: April 20, 2026
**Version**: 1.0.0
