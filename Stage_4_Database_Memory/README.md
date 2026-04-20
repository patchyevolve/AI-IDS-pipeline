# Stage 4: Database & Memory Layer - Threat Intelligence Storage

## Overview

The Database layer stores and retrieves threat signatures and learned patterns using vector similarity matching.

**Purpose**: Maintain a searchable database of known threats and learned attack patterns for fast similarity-based lookups.

**Standalone**: Yes - can be used independently for threat storage and retrieval.

**Dependencies**: Requires CNN feature vectors (Stage 1) for embedding-based queries.

## What It Does

### Input
CNN feature vector (64 dimensions):
```python
{
    "embedding": [0.85, 0.12, 0.45, ..., 0.92],  # 64-dim vector
    "source": "192.168.1.100",
    "destination": "10.0.0.1",
    "port_dst": 80,
}
```

### Processing
1. **Vector Normalization**: Prepare embedding for search
2. **Similarity Search**: Find similar patterns in database
3. **Ranking**: Sort by similarity score
4. **Retrieval**: Return top matches with metadata

### Output
Matching threat records:
```python
{
    "retrieved": [
        {
            "similarity": 0.95,
            "decision": "Block",
            "confidence": 0.98,
            "attack_class": "DoS/DDoS",
            "explanation": "Known DoS pattern",
        },
        {
            "similarity": 0.87,
            "decision": "Alert",
            "confidence": 0.85,
            "attack_class": "PortScan",
            "explanation": "Suspicious port sequence",
        },
    ],
    "db_hits": 2,
}
```

## Architecture

```
CNN Feature Vector (64 dims)
    ↓
[Vector Normalization]
    ↓
[Pinecone Vector Database]
    ├─ Global Store (all threats)
    ├─ IP Store (per-source threats)
    └─ Class Store (by attack type)
    ↓
[Similarity Search]
    ├─ Cosine similarity
    ├─ Euclidean distance
    └─ Dot product
    ↓
[Ranking & Filtering]
    ├─ Sort by similarity
    ├─ Filter by threshold
    └─ Limit results
    ↓
[Metadata Retrieval]
    ├─ Decision (Block/Alert/Log/Ignore)
    ├─ Confidence
    ├─ Attack class
    └─ Explanation
    ↓
Retrieved Threat Records
```

## Database Files

### 1. ids_signatures.jsonl (1,685 records)
Known good signatures from initial training:
```jsonl
{
  "embedding": [0.85, 0.12, ..., 0.92],
  "source": "192.168.1.100",
  "destination": "10.0.0.1",
  "attack_class": "DoS/DDoS",
  "decision": "Block",
  "confidence": 0.98,
  "timestamp": "2026-04-20T10:00:00"
}
```

### 2. refined_threats.jsonl (22,385 records)
Learned patterns from co-evolutionary training:
```jsonl
{
  "embedding": [0.82, 0.15, ..., 0.89],
  "source": "192.168.1.101",
  "destination": "10.0.0.1",
  "attack_class": "PortScan",
  "decision": "Alert",
  "confidence": 0.85,
  "timestamp": "2026-04-20T10:30:00"
}
```

### 3. synthetic_from_datasets.jsonl (500 records)
Base synthetic data from ISCX/NSL-KDD datasets:
```jsonl
{
  "embedding": [0.75, 0.20, ..., 0.80],
  "source": "synthetic",
  "destination": "10.0.0.1",
  "attack_class": "BruteForce",
  "decision": "Log",
  "confidence": 0.70,
  "timestamp": "2026-04-20T09:00:00"
}
```

## Storage Architecture

### Global Store
- **Purpose**: All threats across all sources
- **Size**: 24,000+ records
- **Query**: Fast similarity search
- **Use**: General threat lookup

### IP Store
- **Purpose**: Threats per source IP
- **Size**: 1,000+ unique IPs
- **Query**: Source-specific threats
- **Use**: Per-IP threat history

### Class Store
- **Purpose**: Threats by attack class
- **Classes**: DoS, PortScan, BruteForce, C2, Exfiltration, etc.
- **Query**: Class-specific patterns
- **Use**: Attack-type specific detection

## Standalone Usage

### Basic Example
```python
from database.db_engine import DatabaseEngine
from event_bus import EventBus

# Initialize
bus = EventBus()
db = DatabaseEngine(bus)

# Query database
matches = db.retrieve_memory(
    embedding=[0.85, 0.12, ..., 0.92],  # 64-dim vector
    source="192.168.1.100",
    destination="10.0.0.1",
    port_dst=80,
)

# Get results
for match in matches["retrieved"]:
    print(f"Similarity: {match['similarity']:.2f}")
    print(f"Decision: {match['decision']}")
    print(f"Confidence: {match['confidence']:.2f}")
    print(f"Attack Class: {match['attack_class']}")
```

### Batch Queries
```python
# Query multiple embeddings
embeddings = [
    [0.85, 0.12, ..., 0.92],
    [0.82, 0.15, ..., 0.89],
    [0.75, 0.20, ..., 0.80],
]

for embedding in embeddings:
    matches = db.retrieve_memory(embedding=embedding)
    print(f"Found {len(matches['retrieved'])} matches")
```

### Custom Thresholds
```python
# Query with custom similarity threshold
matches = db.retrieve_memory(
    embedding=embedding,
    similarity_threshold=0.85,  # Only return > 0.85 similarity
    limit=5,  # Return top 5 matches
)
```

### Source-Specific Queries
```python
# Query threats from specific source
matches = db.retrieve_memory(
    embedding=embedding,
    source="192.168.1.100",  # Only this source
)

# Query threats to specific destination
matches = db.retrieve_memory(
    embedding=embedding,
    destination="10.0.0.1",  # Only this destination
)
```

## Performance

| Metric | Value |
|--------|-------|
| **Query Latency** | 1-5 ms |
| **Throughput** | 200-500 queries/sec |
| **Database Size** | 24,000+ records |
| **Vector Dimension** | 64 |
| **Storage** | 50-100 MB (local) |
| **Search Accuracy** | 99%+ |

## Integration Points

### From Stage 3: Decision Engine
```python
# Decoder uses database matches
db_matches = db.retrieve_memory(embedding=cnn_output["feature_vector"])
decision = decoder.decode(cnn_output, rnn_output, db_matches["retrieved"])
```

### To Stage 6: Validation
```python
# Validator uses database for learning
db.memory.global_store.insert(corrected_record)
db.export_ids_signatures()
```

### To Stage 8: Integration
```python
# Full pipeline uses database
matches = db.retrieve_memory(
    embedding=cnn_output["feature_vector"],
    source=event["source"],
    destination=event["destination"],
)
```

## Database Operations

### Insert Records
```python
from database.db_engine import ThreatRecord

# Create record
record = ThreatRecord(
    embedding=[0.85, 0.12, ..., 0.92],
    source="192.168.1.100",
    destination="10.0.0.1",
    attack_class="DoS/DDoS",
    decision="Block",
    confidence=0.98,
    explanation="Known DoS pattern",
)

# Insert into database
db.memory.global_store.insert(record)
db.memory.ip_store["192.168.1.100"].insert(record)
```

### Query Records
```python
# Similarity search
matches = db.retrieve_memory(
    embedding=embedding,
    source=source,
    destination=destination,
    port_dst=port,
)

# Get top matches
for match in matches["retrieved"][:5]:
    print(f"{match['similarity']:.2f} - {match['attack_class']}")
```

### Export Signatures
```python
# Export to JSONL file
count = db.export_ids_signatures()
print(f"Exported {count} signatures")
```

### Get Statistics
```python
# Database statistics
stats = db.get_stats()
print(f"Total records: {stats['threat_count']}")
print(f"Average confidence: {stats['avg_confidence']:.2f}")
print(f"Top attack class: {stats['top_label']}")
print(f"Class distribution: {stats['class_counts']}")
```

## Testing

Run the database test:
```bash
python Stage_4_Database_Memory/examples/test_database.py
```

Expected output:
```
Database Test
=============
Connecting to Pinecone...
✓ Connected successfully
✓ Loaded 1685 signatures

Testing queries...
✓ Query 1: Found 5 matches (similarity: 0.95, 0.87, 0.82, 0.78, 0.75)
✓ Query 2: Found 3 matches (similarity: 0.92, 0.88, 0.81)
✓ Query 3: Found 7 matches (similarity: 0.94, 0.89, 0.85, 0.82, 0.79, 0.76, 0.73)

Average query latency: 2.5 ms
Total queries: 3
Success rate: 100%
```

## Troubleshooting

### Issue: No matches found
**Solution**: Check similarity threshold
```python
# Lower threshold to find more matches
matches = db.retrieve_memory(
    embedding=embedding,
    similarity_threshold=0.70,  # Was 0.85
)
```

### Issue: Slow queries
**Solution**: Check database size and optimize
```python
# Get database stats
stats = db.get_stats()
print(f"Database size: {stats['threat_count']}")

# Consider limiting results
matches = db.retrieve_memory(
    embedding=embedding,
    limit=10,  # Return only top 10
)
```

### Issue: Memory issues
**Solution**: Use Pinecone cloud instead of local
```python
# Pinecone automatically handles large databases
# No local memory issues
db = DatabaseEngine(bus, use_pinecone=True)
```

## Advanced Usage

### Similarity Analysis
```python
import numpy as np

# Analyze similarity distribution
similarities = []
for embedding in embeddings:
    matches = db.retrieve_memory(embedding=embedding)
    for match in matches["retrieved"]:
        similarities.append(match["similarity"])

print(f"Mean similarity: {np.mean(similarities):.2f}")
print(f"Std dev: {np.std(similarities):.2f}")
print(f"Min: {np.min(similarities):.2f}")
print(f"Max: {np.max(similarities):.2f}")
```

### Class-Specific Queries
```python
# Query by attack class
dos_matches = db.retrieve_memory(
    embedding=embedding,
    attack_class="DoS/DDoS",
)

portscan_matches = db.retrieve_memory(
    embedding=embedding,
    attack_class="PortScan",
)
```

### Temporal Queries
```python
# Query recent threats
from datetime import datetime, timedelta

recent_time = (datetime.now() - timedelta(hours=1)).isoformat()
matches = db.retrieve_memory(
    embedding=embedding,
    after_timestamp=recent_time,
)
```

### Batch Insert
```python
# Insert multiple records efficiently
records = [
    ThreatRecord(...),
    ThreatRecord(...),
    ThreatRecord(...),
]

for record in records:
    db.memory.global_store.insert(record)

# Export all
db.export_ids_signatures()
```

## Database Schema

### ThreatRecord Fields
```python
{
    "embedding": list,           # 64-dim vector
    "source": str,               # Source IP
    "destination": str,          # Destination IP
    "attack_class": str,         # Attack type
    "decision": str,             # Block/Alert/Log/Ignore
    "confidence": float,         # 0-1 confidence
    "anomaly_trend": float,      # Anomaly score
    "entropy": float,            # Entropy value
    "rate_hz": float,            # Packet rate
    "port_dst": int,             # Destination port
    "protocol": int,             # Protocol (6=TCP, 17=UDP)
    "flags": int,                # TCP flags
    "explanation": str,          # Decision reasoning
    "timestamp": str,            # ISO timestamp
    "frame_id": int,             # Frame identifier
}
```

## Next Steps

1. **Understand storage**: Review database files
2. **Test queries**: Run standalone examples
3. **Integrate with CNN**: Use embeddings for queries
4. **Optimize performance**: Tune thresholds
5. **Move to Stage 5**: Attacker Evolution

## Files

- `database/db_engine.py` - Main database implementation
- `Stage_4_Database_Memory/examples/test_database.py` - Test suite
- `Stage_4_Database_Memory/examples/query_analysis.py` - Query analysis

## References

- Vector Database: Pinecone for similarity search
- Embeddings: 64-dimensional feature vectors
- Similarity Metrics: Cosine similarity, Euclidean distance
- Storage: JSONL format for persistence

---

**Status**: Production Ready ✓
**Standalone**: Yes ✓
**Dependencies**: Stage 1 (CNN) ✓
**Next Stage**: Stage 5 - Attacker Evolution
