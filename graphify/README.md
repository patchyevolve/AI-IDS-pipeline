# Graphify - Codebase Graph Analysis

This folder contains tools for analyzing and visualizing the AI-IDS codebase structure, dependencies, and relationships.

## Overview

The graphify system generates comprehensive dependency graphs of the entire codebase, showing:
- Module relationships and imports
- Class and function definitions
- Dependency chains
- Component interactions

## Generated Files

### `output/codebase_graph.json`
Complete codebase structure in JSON format:
- All modules with metadata (lines, size, classes, functions)
- Import relationships
- Class definitions per module
- Function definitions per module
- Graph nodes and edges

**Usage:**
```python
import json
with open('output/codebase_graph.json') as f:
    graph_data = json.load(f)
    
# Access modules
modules = graph_data['modules']

# Access imports
imports = graph_data['imports']

# Access graph structure
nodes = graph_data['graph']['nodes']
edges = graph_data['graph']['edges']
```

### `output/codebase_graph.dot`
GraphViz DOT format for visualization:
- Can be rendered with Graphviz tools
- Shows module dependencies with colors
- Useful for creating custom visualizations

**Usage:**
```bash
# Convert to PNG (requires Graphviz)
dot -Tpng codebase_graph.dot -o codebase_graph.png

# Convert to SVG
dot -Tsvg codebase_graph.dot -o codebase_graph.svg
```

## Codebase Statistics

**Total Modules:** 204 Python files

**Core Components:**
- `ai-architecture/` - Main IDS system
- `ai-architecture/attacker/` - Attack simulation engine
- `ai-architecture/decoder/` - Decision making engine
- `ai-architecture/database/` - Threat signature storage
- `ai-architecture/network/` - Network packet handling
- `ai-architecture/validation/` - Real-time validator
- `ai-architecture/threat_intelligence/` - Threat analysis
- `ai-architecture/cnn/` - CNN anomaly detection
- `ai-architecture/rnn/` - RNN temporal analysis
- `ai-architecture/visualizer/` - Dashboard and UI

## Key Dependencies

### Core Pipeline
```
run.py
├── cnn.cnn_engine (Gate + Autoencoder)
├── rnn.rnn_engine (Temporal analysis)
├── decoder.decoder_engine (Decision making)
├── decoder.mutation_predictor (Evasion prediction)
├── database.db_engine (Signature storage)
├── network.ids_bridge (Packet capture)
├── validation.training_validator (FN/FP correction)
└── attacker.attack_engine (Attack simulation)
```

### Database Layer
```
database.db_engine
├── Pinecone (Cloud vector DB)
├── Local SQLite/PostgreSQL
├── Threat signature storage
└── Cloud synchronization
```

### Network Layer
```
network.ids_bridge
├── Scapy (packet capture)
├── network.net_config (interface setup)
├── network.firewall_enforcer (packet blocking)
└── network.remote_attack_listener (remote attacks)
```

### Validation Layer
```
validation.training_validator
├── validation.metrics_tracker (metrics collection)
├── validation.auto_corrector (FN/FP correction)
└── database.db_engine (signature updates)
```

### Threat Intelligence
```
threat_intelligence.threat_intelligence_engine
├── mitre_mapper (MITRE ATT&CK mapping)
├── campaign_correlator (multi-stage attacks)
├── behavioral_baseline (anomaly detection)
└── decoder.decoder_engine (decision enhancement)
```

## Module Breakdown

### Attacker System (ai-architecture/attacker/)
- `attack_engine.py` - Main attack orchestration
- `attack_profiles.py` - Attack type definitions
- `mutator.py` - Genetic algorithm for evasion
- `packet_sender.py` - Network packet transmission
- `target_scanner.py` - Target discovery
- `run_attacker.py` - Standalone attacker runner

### Decoder System (ai-architecture/decoder/)
- `decoder_engine.py` - Hybrid decision engine
- `mutation_predictor.py` - Evasion prediction

### Database System (ai-architecture/database/)
- `db_engine.py` - Vector database engine
- Supports: Pinecone (cloud), SQLite (local)

### Network System (ai-architecture/network/)
- `ids_bridge.py` - Packet capture and processing
- `net_config.py` - Network interface configuration
- `firewall_enforcer.py` - Packet blocking
- `remote_attack_listener.py` - Remote attack reception
- `decision_feedback_server.py` - Decision feedback
- `setup_screen.py` - Interactive setup UI

### Validation System (ai-architecture/validation/)
- `training_validator.py` - Real-time FN/FP detection
- `metrics_tracker.py` - Performance metrics
- `auto_corrector.py` - Automatic database correction

### Threat Intelligence (ai-architecture/threat_intelligence/)
- `threat_intelligence_engine.py` - Main TI engine
- `mitre_mapper.py` - MITRE ATT&CK mapping
- `campaign_correlator.py` - Campaign tracking
- `behavioral_baseline.py` - Behavioral analysis

### ML Engines
- `ai-architecture/cnn/cnn_engine.py` - CNN gate + autoencoder
- `ai-architecture/rnn/rnn_engine.py` - RNN temporal analysis

### Visualizer (ai-architecture/visualizer/)
- `dashboard.py` - Pygame-based dashboard
- `dashboard_tk.py` - Tkinter-based dashboard
- `fast_cli.py` - CLI visualization
- `shared_state.py` - Shared state management

## Usage Examples

### Generate Fresh Graph
```bash
python graphify/generate_codebase_graph.py
```

### Analyze Specific Module
```python
import json

with open('graphify/output/codebase_graph.json') as f:
    data = json.load(f)

# Find all modules that import decoder
decoder_users = [
    module for module, imports in data['imports'].items()
    if any('decoder' in imp for imp in imports)
]

print("Modules using decoder:", decoder_users)
```

### Find Circular Dependencies
```python
import networkx as nx
import json

with open('graphify/output/codebase_graph.json') as f:
    data = json.load(f)

G = nx.DiGraph()
for edge in data['graph']['edges']:
    G.add_edge(edge[0], edge[1])

cycles = list(nx.simple_cycles(G))
if cycles:
    print("Circular dependencies found:")
    for cycle in cycles:
        print(" → ".join(cycle))
else:
    print("No circular dependencies")
```

### Analyze Module Complexity
```python
import json

with open('graphify/output/codebase_graph.json') as f:
    data = json.load(f)

# Find most complex modules
modules_by_size = sorted(
    data['modules'].items(),
    key=lambda x: x[1]['lines'],
    reverse=True
)

print("Top 10 largest modules:")
for module, info in modules_by_size[:10]:
    print(f"{module:50} {info['lines']:6} lines")
```

## Integration with Development

The codebase graph can be used for:

1. **Code Review** - Understand module dependencies before changes
2. **Refactoring** - Identify tightly coupled modules
3. **Documentation** - Auto-generate architecture diagrams
4. **Testing** - Determine test coverage needs
5. **Performance** - Identify bottleneck modules
6. **Onboarding** - Help new developers understand structure

## Future Enhancements

- [ ] Interactive web-based graph viewer
- [ ] Real-time dependency tracking
- [ ] Complexity metrics (cyclomatic, cognitive)
- [ ] Test coverage integration
- [ ] Performance profiling integration
- [ ] API documentation generation
- [ ] Change impact analysis

## Tools Used

- **networkx** - Graph analysis and algorithms
- **pydot** - GraphViz integration
- **ast** - Python AST parsing
- **json** - Data serialization

## Notes

- Graph is generated from Python AST parsing (100% accurate)
- Includes all internal and external imports
- Excludes __pycache__ and build directories
- Color-coded by module type in DOT format
- JSON format suitable for programmatic analysis
