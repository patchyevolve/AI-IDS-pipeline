#!/usr/bin/env python3
"""
Multi-Dataset Threat Loader - Load all CSV files from real_datasets folder.

Pipeline:
1. Scan real_datasets folder for all CSV files
2. Load threats from each dataset
3. Merge threat patterns
4. Build comprehensive initial database
5. Generate synthetic attacks from all patterns
6. Ready for training on combined data
"""
import sys
import os
import json
import csv
import time
from pathlib import Path
from collections import defaultdict, Counter
import hashlib
import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from database.db_engine import DatabaseEngine, ThreatRecord
from event_bus import EventBus


class MultiDatasetExtractor:
    """Extract attack patterns from multiple CSV files."""
    
    def __init__(self):
        self.threat_types = Counter()
        self.protocols = Counter()
        self.actions = Counter()
        self.sources = set()
        self.destinations = set()
        self.user_agents = Counter()
        self.request_paths = Counter()
        self.bytes_stats = []
        self.threat_patterns = defaultdict(list)
        self.dataset_stats = {}
        self.total_rows = 0
        self.total_threats = 0
    
    def process_row(self, row: dict, dataset_name: str = ""):
        """Process a single CSV row."""
        try:
            timestamp = row.get("timestamp", "")
            source_ip = row.get("source_ip", "")
            dest_ip = row.get("dest_ip", "")
            protocol = row.get("protocol", "").upper()
            action = row.get("action", "").lower()
            threat_label = row.get("threat_label", "").lower()
            log_type = row.get("log_type", "").lower()
            bytes_transferred = int(row.get("bytes_transferred", 0))
            user_agent = row.get("user_agent", "")
            request_path = row.get("request_path", "/")
            
            # Track statistics
            self.threat_types[threat_label] += 1
            self.protocols[protocol] += 1
            self.actions[action] += 1
            self.sources.add(source_ip)
            self.destinations.add(dest_ip)
            self.user_agents[user_agent] += 1
            self.request_paths[request_path] += 1
            self.bytes_stats.append(bytes_transferred)
            
            # Store threat patterns
            if threat_label != "benign":
                self.threat_patterns[threat_label].append({
                    "source": source_ip,
                    "destination": dest_ip,
                    "protocol": protocol,
                    "action": action,
                    "bytes": bytes_transferred,
                    "user_agent": user_agent,
                    "path": request_path,
                    "timestamp": timestamp,
                    "dataset": dataset_name,
                })
        except Exception as e:
            pass
    
    def get_stats(self) -> dict:
        """Get extracted statistics."""
        return {
            "threat_types": dict(self.threat_types.most_common(20)),
            "protocols": dict(self.protocols.most_common(10)),
            "actions": dict(self.actions.most_common(10)),
            "unique_sources": len(self.sources),
            "unique_destinations": len(self.destinations),
            "top_user_agents": dict(self.user_agents.most_common(10)),
            "top_paths": dict(self.request_paths.most_common(10)),
            "bytes_mean": np.mean(self.bytes_stats) if self.bytes_stats else 0,
            "bytes_std": np.std(self.bytes_stats) if self.bytes_stats else 0,
            "bytes_min": min(self.bytes_stats) if self.bytes_stats else 0,
            "bytes_max": max(self.bytes_stats) if self.bytes_stats else 0,
            "total_rows": self.total_rows,
            "total_threats": self.total_threats,
        }
    
    def get_threat_patterns(self) -> dict:
        """Get threat patterns for synthetic generation."""
        return dict(self.threat_patterns)


def find_csv_files(datasets_dir: str) -> list:
    """Find all CSV files in datasets directory."""
    datasets_path = Path(datasets_dir)
    if not datasets_path.exists():
        print(f"[multi-loader] ❌ Datasets directory not found: {datasets_dir}")
        return []
    
    csv_files = list(datasets_path.glob("*.csv"))
    print(f"[multi-loader] Found {len(csv_files)} CSV files:")
    for csv_file in csv_files:
        size_mb = csv_file.stat().st_size / (1024 * 1024)
        print(f"  - {csv_file.name} ({size_mb:.1f}MB)")
    
    return csv_files


def load_csv_file(csv_path: str, max_rows: int = None, threat_only: bool = True) -> tuple:
    """Load threats from a single CSV file."""
    extractor = MultiDatasetExtractor()
    dataset_name = Path(csv_path).stem
    row_count = 0
    threat_count = 0
    
    print(f"\n[multi-loader] Loading {dataset_name}...")
    
    try:
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                if max_rows and threat_count >= max_rows:
                    break
                
                row_count += 1
                extractor.total_rows += 1
                
                # Filter for threats only if requested
                threat_label = row.get("threat_label", "").lower()
                if threat_only and threat_label == "benign":
                    continue
                
                extractor.process_row(row, dataset_name)
                threat_count += 1
                extractor.total_threats += 1
                
                if threat_count % 10000 == 0:
                    print(f"  Processed {threat_count} threats ({row_count} total rows)...")
        
        print(f"[multi-loader] ✓ Loaded {threat_count} threats from {dataset_name}")
        return extractor, threat_count
    
    except Exception as e:
        print(f"[multi-loader] ❌ Error loading {dataset_name}: {e}")
        return None, 0


def merge_extractors(extractors: list) -> MultiDatasetExtractor:
    """Merge multiple extractors into one."""
    merged = MultiDatasetExtractor()
    
    for extractor in extractors:
        if extractor is None:
            continue
        
        merged.threat_types.update(extractor.threat_types)
        merged.protocols.update(extractor.protocols)
        merged.actions.update(extractor.actions)
        merged.sources.update(extractor.sources)
        merged.destinations.update(extractor.destinations)
        merged.user_agents.update(extractor.user_agents)
        merged.request_paths.update(extractor.request_paths)
        merged.bytes_stats.extend(extractor.bytes_stats)
        
        for threat_type, patterns in extractor.threat_patterns.items():
            merged.threat_patterns[threat_type].extend(patterns)
        
        merged.total_rows += extractor.total_rows
        merged.total_threats += extractor.total_threats
    
    return merged


def build_initial_database(extractor: MultiDatasetExtractor, db: DatabaseEngine):
    """Build initial database from threat patterns."""
    print(f"\n[multi-loader] Building initial database from threat patterns...")
    
    threat_patterns = extractor.get_threat_patterns()
    stats = extractor.get_stats()
    
    print(f"[multi-loader] Threat types found: {len(threat_patterns)}")
    for threat_type, patterns in threat_patterns.items():
        print(f"  - {threat_type}: {len(patterns)} patterns")
    
    # Create threat records from patterns
    record_count = 0
    for threat_type, patterns in threat_patterns.items():
        # Use up to 200 patterns per threat type
        for pattern in patterns[:200]:
            try:
                # Create embedding from pattern features
                embedding = _create_embedding_from_pattern(pattern, threat_type)
                
                rec = ThreatRecord(
                    source=pattern["source"],
                    destination=pattern["destination"],
                    protocol=pattern["protocol"],
                    port_dst=443 if pattern["protocol"] == "HTTPS" else 80,
                    attack_class=threat_type,
                    anomaly_score=0.7,
                    confidence=0.8,
                    decision="Block",
                    embedding=embedding,
                    metadata={
                        "source": "multi_dataset",
                        "dataset": pattern.get("dataset", "unknown"),
                        "user_agent": pattern["user_agent"],
                        "path": pattern["path"],
                    }
                )
                
                # Write to database
                db.log_prediction({
                    "source": pattern["source"],
                    "destination": pattern["destination"],
                    "attack_class": threat_type,
                    "decision": "Block",
                    "confidence": 0.8,
                    "anomaly_score": 0.7,
                    "feature_vector": embedding,
                })
                
                record_count += 1
            except Exception as e:
                pass
    
    print(f"[multi-loader] ✓ Created {record_count} threat records")
    return record_count


def _create_embedding_from_pattern(pattern: dict, threat_type: str) -> list:
    """Create 64-dim embedding from threat pattern."""
    seed_str = f"{pattern['source']}{pattern['destination']}{threat_type}"
    seed = int(hashlib.md5(seed_str.encode()).hexdigest()[:8], 16)
    
    np.random.seed(seed)
    embedding = np.random.randn(64).astype(float).tolist()
    
    bytes_val = pattern.get("bytes", 0)
    bytes_norm = min(bytes_val / 100000.0, 1.0)
    
    threat_boost = {
        "malware": 0.9,
        "ransomware": 0.95,
        "ddos": 0.85,
        "exfiltration": 0.88,
        "brute_force": 0.75,
        "sql_injection": 0.82,
        "xss": 0.70,
        "suspicious": 0.65,
        "malicious": 0.85,
    }
    
    boost = threat_boost.get(threat_type.lower(), 0.7)
    for i in range(len(embedding)):
        embedding[i] = embedding[i] * boost + bytes_norm * 0.1
    
    return embedding


def generate_synthetic_from_patterns(extractor: MultiDatasetExtractor, count: int = 500):
    """Generate synthetic attacks based on real patterns."""
    print(f"\n[multi-loader] Generating {count} synthetic attacks from real patterns...")
    
    threat_patterns = extractor.get_threat_patterns()
    synthetic_attacks = []
    
    for i in range(count):
        threat_type = np.random.choice(list(threat_patterns.keys()))
        patterns = threat_patterns[threat_type]
        
        if not patterns:
            continue
        
        base_pattern = np.random.choice(patterns)
        
        mutated = {
            "source": _mutate_ip(base_pattern["source"]),
            "destination": _mutate_ip(base_pattern["destination"]),
            "protocol": base_pattern["protocol"],
            "action": base_pattern["action"],
            "bytes": int(base_pattern["bytes"] * np.random.uniform(0.5, 2.0)),
            "user_agent": base_pattern["user_agent"],
            "path": base_pattern["path"],
            "threat_type": threat_type,
            "dataset": base_pattern.get("dataset", "unknown"),
        }
        
        synthetic_attacks.append(mutated)
    
    print(f"[multi-loader] ✓ Generated {len(synthetic_attacks)} synthetic attacks")
    return synthetic_attacks


def _mutate_ip(ip: str) -> str:
    """Mutate IP address slightly."""
    parts = ip.split(".")
    if len(parts) == 4:
        parts[-1] = str(np.random.randint(1, 255))
    return ".".join(parts)


def main():
    print("\n" + "="*60)
    print("MULTI-DATASET THREAT LOADER")
    print("="*60)
    
    # Find all CSV files
    datasets_dir = Path(_HERE).parent / "real_datasets"
    csv_files = find_csv_files(str(datasets_dir))
    
    if not csv_files:
        print("❌ No CSV files found in real_datasets folder")
        return
    
    # Load all datasets
    print(f"\n[multi-loader] Loading {len(csv_files)} datasets...")
    extractors = []
    total_threats = 0
    
    for csv_file in csv_files:
        extractor, threat_count = load_csv_file(str(csv_file), max_rows=50000, threat_only=True)
        if extractor:
            extractors.append(extractor)
            total_threats += threat_count
    
    if not extractors:
        print("❌ Failed to load any datasets")
        return
    
    # Merge all extractors
    print(f"\n[multi-loader] Merging {len(extractors)} datasets...")
    merged = merge_extractors(extractors)
    
    # Print statistics
    stats = merged.get_stats()
    print(f"\n[multi-loader] Combined Statistics:")
    print(f"  Total rows: {stats['total_rows']:,}")
    print(f"  Total threats: {stats['total_threats']:,}")
    print(f"  Threat types: {len(stats['threat_types'])}")
    print(f"  Top threats: {list(stats['threat_types'].keys())[:5]}")
    print(f"  Protocols: {stats['protocols']}")
    print(f"  Unique sources: {stats['unique_sources']:,}")
    print(f"  Unique destinations: {stats['unique_destinations']:,}")
    print(f"  Bytes: mean={stats['bytes_mean']:.0f}, std={stats['bytes_std']:.0f}, "
          f"min={stats['bytes_min']}, max={stats['bytes_max']}")
    
    # Build initial database
    event_bus = EventBus()
    db = DatabaseEngine(event_bus, max_memory=50000, cloud_enabled=False)
    
    record_count = build_initial_database(merged, db)
    
    # Generate synthetic attacks
    synthetic = generate_synthetic_from_patterns(merged, count=500)
    
    # Export database
    db_dir = Path(_HERE) / "database"
    db_dir.mkdir(exist_ok=True)
    
    sig_file = db_dir / "ids_signatures.jsonl"
    print(f"\n[multi-loader] Exporting to {sig_file}")
    exported = db.export_ids_signatures(str(sig_file))
    print(f"[multi-loader] ✓ Exported {exported} signatures")
    
    # Save synthetic attacks for reference
    synthetic_file = db_dir / "synthetic_from_datasets.jsonl"
    with open(synthetic_file, 'w') as f:
        for attack in synthetic:
            f.write(json.dumps(attack) + "\n")
    print(f"[multi-loader] ✓ Saved {len(synthetic)} synthetic attacks to {synthetic_file}")
    
    # Save dataset statistics
    stats_file = db_dir / "dataset_statistics.json"
    with open(stats_file, 'w') as f:
        json.dump({
            "datasets": len(csv_files),
            "total_rows": stats['total_rows'],
            "total_threats": stats['total_threats'],
            "threat_types": stats['threat_types'],
            "protocols": stats['protocols'],
            "unique_sources": stats['unique_sources'],
            "unique_destinations": stats['unique_destinations'],
        }, f, indent=2)
    print(f"[multi-loader] ✓ Saved statistics to {stats_file}")
    
    print("\n" + "="*60)
    print("✓ Multi-dataset initialization complete!")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
