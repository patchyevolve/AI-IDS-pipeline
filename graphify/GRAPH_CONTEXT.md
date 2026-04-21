# AI-IDS Codebase Graph Context

## Quick Reference

### System Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    MAIN PIPELINE (run.py)                   │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
    ┌───▼────┐          ┌────▼────┐          ┌────▼────┐
    │ CNN    │          │ RNN     │          │ Decoder │
    │ Engine │          │ Engine  │          │ Engine  │
    └────────┘          └────────┘          └────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │ Mutation Predictor│
                    │ (Evasion Predict) │
                    └─────────┬─────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
    ┌───▼────┐          ┌────▼────┐          ┌────▼────┐
    │Database│          │Validator│          │Firewall │
    │ Engine │          │ Engine  │          │Enforcer │
    └────────┘          └────────┘          └────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │ Threat Intelligence
                    │ (MITRE, Campaign) │
                    └───────────────────┘
```

## Module Dependency Map

### Tier 1: Core Engines
```
cnn.cnn_engine
├─ Imports: numpy, torch, datetime
├─ Classes: CNNEngine, GateClassifier, AutoencoderAE
└─ Functions: forward, encode, decode, detect_anomaly

rnn.rnn_engine
├─ Imports: numpy, torch, datetime
├─ Classes: RNNEngine, StateSpaceModel
└─ Functions: forward, update_state, compute_trend

decoder.decoder_engine
├─ Imports: numpy, datetime, threat_intelligence
├─ Classes: HybridDecoder, AdaptiveThresholds, CorrelationEngine
└─ Functions: decode, _classify, _attention_pool
```

### Tier 2: Data & Storage
```
database.db_engine
├─ Imports: pinecone, numpy, threading, json
├─ Classes: ThreatRecord, VectorGraphStore, DatabaseEngine
├─ Functions: insert, search, retrieve_memory, export_ids_signatures
└─ Cloud: Pinecone Vector DB

decoder.mutation_predictor
├─ Imports: numpy, collections
├─ Classes: MutationPredictor, MutationAwareDecoder
└─ Functions: predict_mutations, score_against_mutations
```

### Tier 3: Network & Capture
```
network.ids_bridge
├─ Imports: scapy, socket, threading, json
├─ Classes: IDSBridge
├─ Functions: start, _packet_callback, _process_packet
└─ Modes: synthetic, live, remote

network.net_config
├─ Imports: scapy, psutil, subprocess
├─ Functions: get_interfaces, get_filter, validate_config

network.firewall_enforcer
├─ Imports: subprocess, os, json
├─ Classes: FirewallEnforcer
└─ Functions: block_ip, allow_ip, get_rules
```

### Tier 4: Validation & Learning
```
validation.training_validator
├─ Imports: database.db_engine, datetime, json
├─ Classes: TrainingValidator
├─ Functions: validate_and_correct, _correct_false_negative, _correct_false_positive
└─ Events: db_updated (emitted on corrections)

validation.metrics_tracker
├─ Imports: collections, json, datetime
├─ Classes: MetricsTracker
└─ Functions: track_event, get_metrics, save_report

validation.auto_corrector
├─ Imports: database.db_engine, validation.metrics_tracker
├─ Classes: AutoCorrector
└─ Functions: correct_fn, correct_fp
```

### Tier 5: Attack Simulation
```
attacker.attack_engine
├─ Imports: attacker.attack_profiles, attacker.mutator, event_bus
├─ Classes: AttackEngine
├─ Functions: start, _generate_attacks, _receive_feedback
└─ Feedback: Receives decisions from decoder

attacker.mutator
├─ Imports: numpy, random, collections
├─ Classes: GeneticMutator
├─ Functions: mutate, crossover, fitness_score
└─ Strategy: Evasion-first (learns from validator corrections)

attacker.attack_profiles
├─ Imports: collections, random
├─ Classes: AttackProfile
└─ Profiles: DoS, C2, BruteForce, PortScan, DNSTunnel, Exfiltration
```

### Tier 6: Threat Intelligence
```
threat_intelligence.threat_intelligence_engine
├─ Imports: mitre_mapper, campaign_correlator, behavioral_baseline
├─ Classes: ThreatIntelligenceEngine
└─ Functions: process_attack, enrich_decision

threat_intelligence.mitre_mapper
├─ Imports: json, typing
├─ Classes: MITREMapper
└─ Functions: map_to_tactics, map_to_techniques

threat_intelligence.campaign_correlator
├─ Imports: collections, hashlib, json
├─ Classes: CampaignCorrelator
└─ Functions: correlate_attacks, identify_campaign

threat_intelligence.behavioral_baseline
├─ Imports: collections, statistics, json
├─ Classes: BehavioralBaseline
└─ Functions: build_baseline, detect_anomaly
```

### Tier 7: Visualization & UI
```
visualizer.dashboard
├─ Imports: pygame, threading, collections
├─ Classes: Dashboard
└─ Functions: render, update, handle_events

visualizer.dashboard_tk
├─ Imports: tkinter, threading, event_bus
├─ Classes: TkinterDashboard
└─ Functions: create_ui, update_metrics

visualizer.fast_cli
├─ Imports: threading, collections
├─ Classes: CLIDashboard
└─ Functions: render_cli, update_display
```

## Data Flow

### Packet Processing Flow
```
Network Packet
    ↓
ids_bridge.IDSBridge._packet_callback()
    ↓
Extract Features (source, dest, port, protocol, etc)
    ↓
cnn.cnn_engine.forward() → is_attack_prob, anomaly_score
    ↓
rnn.rnn_engine.forward() → anomaly_trend, drift_score
    ↓
database.db_engine.retrieve_memory() → similar signatures
    ↓
decoder.decoder_engine.decode() → decision, confidence
    ↓
decoder.mutation_predictor.predict_mutations() → evasion tactics
    ↓
threat_intelligence.threat_intelligence_engine.process_attack()
    ↓
Decision: Block/Alert/Log/Escalate
    ↓
firewall_enforcer.block_ip() (if Block)
    ↓
database.db_engine.log_prediction() → store for learning
```

### Validation & Learning Flow
```
Decoder Output
    ↓
validation.training_validator._on_decoder_output()
    ↓
Compare with Ground Truth (from attacker metadata)
    ↓
Detect FN (missed attack) or FP (blocked benign)
    ↓
validation.training_validator._correct_false_negative()
    OR
validation.training_validator._correct_false_positive()
    ↓
database.db_engine.log_prediction() → store correction
    ↓
database.db_engine.export_ids_signatures() → export immediately
    ↓
event_bus.emit("db_updated") → notify all listeners
    ↓
decoder.mutation_predictor._on_db_updated()
    ↓
mutation_predictor.learn_from_database() → reload patterns
    ↓
attacker.attack_engine._receive_feedback()
    ↓
attacker.mutator.fitness_score() → evaluate evasion
    ↓
attacker.mutator.mutate() → evolve next generation
```

### Cloud Synchronization Flow
```
Local Database (Instance 1)
    ↓ (Every 5 minutes)
database.db_engine.sync_batch() → Pinecone
    ↓
Cloud Database (Pinecone)
    ↓ (Broadcast)
Local Database (Instance 2)
Local Database (Instance 3)
Local Database (Instance N)
    ↓
All instances have latest signatures
```

## Key Classes & Methods

### CNNEngine
```python
class CNNEngine:
    def forward(self, packet_features) → (is_attack_prob, anomaly_score)
    def encode(self, features) → embedding
    def decode(self, embedding) → reconstruction
    def detect_anomaly(self, packet) → anomaly_score
```

### RNNEngine
```python
class RNNEngine:
    def forward(self, sequence) → (anomaly_trend, drift_score)
    def update_state(self, new_observation) → None
    def compute_trend(self) → trend_score
```

### HybridDecoder
```python
class HybridDecoder:
    def decode(self, cnn_event, rnn_event, db_memory) → decode_event
    def _classify(self, cnn_event, rnn_event, score) → attack_class
    def _attention_pool(self, tokens) → pooled_vector
```

### DatabaseEngine
```python
class DatabaseEngine:
    def log_prediction(self, decode_event) → record_id
    def retrieve_memory(self, embedding) → similar_records
    def export_ids_signatures(self) → export_count
    def sync_batch(self, records) → cloud_sync_status
```

### TrainingValidator
```python
class TrainingValidator:
    def validate_and_correct(self, event) → None
    def _correct_false_negative(self, event) → None
    def _correct_false_positive(self, event) → None
    def get_metrics() → metrics_dict
```

### AttackEngine
```python
class AttackEngine:
    def start() → None
    def _generate_attacks() → attack_packets
    def _receive_feedback(decision) → None
    def _evolve_population() → None
```

## Event Bus Communication

### Key Events
```
"decoder_output" → Emitted by decoder, consumed by validator
"db_updated" → Emitted by validator, consumed by mutation_predictor
"db_retrieved" → Emitted by database, consumed by decoder
"attack_feedback" → Emitted by firewall, consumed by attacker
"threat_intelligence" → Emitted by TI engine, consumed by decoder
```

## Import Dependencies

### External Libraries
```
numpy - Numerical computing
torch - Deep learning (CNN/RNN)
scapy - Packet manipulation
pinecone - Vector database
pygame - Visualization
tkinter - GUI
psutil - System monitoring
subprocess - System commands
threading - Concurrency
json - Data serialization
```

### Internal Modules
```
event_bus - Event communication
database.db_engine - Data storage
decoder.decoder_engine - Decision making
decoder.mutation_predictor - Evasion prediction
validation.training_validator - FN/FP correction
threat_intelligence - Threat analysis
attacker.attack_engine - Attack simulation
network.ids_bridge - Packet capture
network.firewall_enforcer - Packet blocking
```

## Performance Characteristics

### Latency
- Packet processing: <50ms per packet
- CNN inference: ~10ms
- RNN inference: ~5ms
- Decoder decision: ~15ms
- Database lookup: ~5ms
- Total: ~35ms average

### Throughput
- Per instance: 100K+ packets/sec
- Multi-instance: Scales linearly
- Cloud sync: Async (non-blocking)

### Memory
- Per instance: ~2GB (models + database)
- Local database: ~500MB
- Cloud database: Unlimited (Pinecone)

## Testing & Validation

### Test Files
```
tests/test_validation_integration.py - Full pipeline test
tests/test_coevo_5min.py - 5-minute co-evolution test
tests/test_mutation_predictor.py - Evasion prediction test
tests/test_db_validation_authentication.py - Database validation
tests/test_real_attacker_metrics.py - Attacker metrics
```

### Metrics Tracked
```
Accuracy - Overall detection accuracy
Precision - True positives / (true positives + false positives)
Recall - True positives / (true positives + false negatives)
FNR - False negative rate (missed attacks)
FPR - False positive rate (blocked benign)
F1 Score - Harmonic mean of precision and recall
```

## Future Enhancements

- [ ] Distributed decoder instances
- [ ] Real-time model retraining
- [ ] Advanced SOAR integration
- [ ] Custom plugin system
- [ ] Kubernetes deployment
- [ ] Multi-cloud support
- [ ] Advanced threat hunting
- [ ] Automated incident response

---

**Last Updated:** 2024-04-21  
**Graph Generated:** See `output/codebase_graph.json`  
**Total Modules:** 204  
**Total Dependencies:** 196
