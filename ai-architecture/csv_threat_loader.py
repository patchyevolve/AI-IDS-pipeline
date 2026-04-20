#!/usr/bin/env python3
"""
CSV Threat Loader - Load real cybersecurity logs and build initial database.

Pipeline:
1. Read cybersecurity_threat_detection_logs.csv (800MB)
2. Extract threat patterns (attack types, IPs, protocols, payloads)
3. Build initial database (ids_signatures.jsonl)
4. Generate synthetic attacks based on real patterns
5. Train IDS on real data
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


class ThreatPatternExtractor:
    """Extract attack patterns from CSV logs."""
    
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
    
    def process_row(self, row: dict):
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
                })
        except Exception as e:
            print(f"[csv-loader] Error processing row: {e}")
    
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
        }
    
    def get_threat_patterns(self) -> dict:
        """Get threat patterns for synthetic generation."""
        return dict(self.threat_patterns)


def load_csv_threats(csv_path: str, max_rows: int = None, chunk_size: int = 10000, threat_only: bool = True):
    """Load threats from CSV file."""
    print(f"\n[csv-loader] Loading threats from {csv_path}")
    print(f"[csv-loader] Threat-only mode: {threat_only}")
    print(f"[csv-loader] Max rows: {max_rows or 'all'}")
    
    extractor = ThreatPatternExtractor()
    row_count = 0
    threat_count = 0
    
    try:
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                if max_rows and threat_count >= max_rows:
                    break
                
                row_count += 1
                
                # Filter for threats only if requested
                threat_label = row.get("threat_label", "").lower()
                if threat_only and threat_label == "benign":
                    continue
                
                extractor.process_row(row)
                threat_count += 1
                
                if threat_count % chunk_size == 0:
                    print(f"[csv-loader] Processed {threat_count} threats ({row_count} total rows)...")
        
        print(f"[csv-loader] ✓ Loaded {threat_count} threats (from {row_count} total rows)")
        return extractor
    
    except Exception as e:
        print(f"[csv-loader] ❌ Error loading CSV: {e}")
        return None


def build_initial_database(extractor: ThreatPatternExtractor, db: DatabaseEngine):
    """Build initial database from threat patterns."""
    print(f"\n[csv-loader] Building initial database from threat patterns...")
    
    threat_patterns = extractor.get_threat_patterns()
    stats = extractor.get_stats()
    
    print(f"[csv-loader] Threat types found: {len(threat_patterns)}")
    for threat_type, patterns in threat_patterns.items():
        print(f"  - {threat_type}: {len(patterns)} patterns")
    
    # Create threat records from patterns
    record_count = 0
    for threat_type, patterns in threat_patterns.items():
        for pattern in patterns[:100]:  # Limit to 100 per threat type for now
            try:
                # Create embedding from pattern features
                embedding = _create_embedding_from_pattern(pattern, threat_type)
                
                rec = ThreatRecord(
                    source=pattern["source"],
                    destination=pattern["destination"],
                    protocol=pattern["protocol"],
                    port_dst=443 if pattern["protocol"] == "HTTPS" else 80,
                    attack_class=threat_type,
                    anomaly_score=0.7,  # Real threats are high confidence
                    confidence=0.8,
                    decision="Block",
                    embedding=embedding,
                    metadata={
                        "source": "csv_threat_log",
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
                print(f"[csv-loader] Error creating record: {e}")
    
    print(f"[csv-loader] ✓ Created {record_count} threat records")
    return record_count


def _create_embedding_from_pattern(pattern: dict, threat_type: str) -> list:
    """Create 64-dim embedding from threat pattern."""
    # Hash-based deterministic embedding
    seed_str = f"{pattern['source']}{pattern['destination']}{threat_type}"
    seed = int(hashlib.md5(seed_str.encode()).hexdigest()[:8], 16)
    
    np.random.seed(seed)
    embedding = np.random.randn(64).astype(float).tolist()
    
    # Inject threat-specific features
    bytes_val = pattern.get("bytes", 0)
    bytes_norm = min(bytes_val / 100000.0, 1.0)
    
    # Modify embedding based on threat type
    threat_boost = {
        "malware": 0.9,
        "ransomware": 0.95,
        "ddos": 0.85,
        "exfiltration": 0.88,
        "brute_force": 0.75,
        "sql_injection": 0.82,
        "xss": 0.70,
    }
    
    boost = threat_boost.get(threat_type.lower(), 0.7)
    for i in range(len(embedding)):
        embedding[i] = embedding[i] * boost + bytes_norm * 0.1
    
    return embedding


def generate_synthetic_from_patterns(extractor: ThreatPatternExtractor, count: int = 100):
    """Generate synthetic attacks based on real patterns."""
    print(f"\n[csv-loader] Generating {count} synthetic attacks from real patterns...")
    
    threat_patterns = extractor.get_threat_patterns()
    stats = extractor.get_stats()
    
    synthetic_attacks = []
    
    for i in range(count):
        # Pick random threat type
        threat_type = np.random.choice(list(threat_patterns.keys()))
        patterns = threat_patterns[threat_type]
        
        if not patterns:
            continue
        
        # Pick random pattern as base
        base_pattern = np.random.choice(patterns)
        
        # Mutate pattern
        mutated = {
            "source": _mutate_ip(base_pattern["source"]),
            "destination": _mutate_ip(base_pattern["destination"]),
            "protocol": base_pattern["protocol"],
            "action": base_pattern["action"],
            "bytes": int(base_pattern["bytes"] * np.random.uniform(0.5, 2.0)),
            "user_agent": base_pattern["user_agent"],
            "path": base_pattern["path"],
            "threat_type": threat_type,
        }
        
        synthetic_attacks.append(mutated)
    
    print(f"[csv-loader] ✓ Generated {len(synthetic_attacks)} synthetic attacks")
    return synthetic_attacks


def _mutate_ip(ip: str) -> str:
    """Mutate IP address slightly."""
    parts = ip.split(".")
    if len(parts) == 4:
        # Change last octet
        parts[-1] = str(np.random.randint(1, 255))
    return ".".join(parts)


def main():
    print("\n" + "="*60)
    print("CSV THREAT LOADER - Build Database from Real Logs")
    print("="*60)
    
    csv_path = Path(_HERE).parent / "cybersecurity_threat_detection_logs.csv"
    
    if not csv_path.exists():
        print(f"❌ CSV file not found: {csv_path}")
        return
    
    # Load CSV (load only threats, not benign traffic)
    extractor = load_csv_threats(str(csv_path), max_rows=50000, threat_only=True)
    
    if not extractor:
        print("❌ Failed to load CSV")
        return
    
    # Print statistics
    stats = extractor.get_stats()
    print(f"\n[csv-loader] Statistics:")
    print(f"  Threat types: {len(stats['threat_types'])}")
    print(f"  Top threats: {list(stats['threat_types'].keys())[:5]}")
    print(f"  Protocols: {stats['protocols']}")
    print(f"  Unique sources: {stats['unique_sources']}")
    print(f"  Unique destinations: {stats['unique_destinations']}")
    print(f"  Bytes: mean={stats['bytes_mean']:.0f}, std={stats['bytes_std']:.0f}, "
          f"min={stats['bytes_min']}, max={stats['bytes_max']}")
    
    # Build initial database
    event_bus = EventBus()
    db = DatabaseEngine(event_bus, max_memory=10000, cloud_enabled=False)
    
    record_count = build_initial_database(extractor, db)
    
    # Generate synthetic attacks
    synthetic = generate_synthetic_from_patterns(extractor, count=100)
    
    # Export database
    db_dir = Path(_HERE) / "database"
    db_dir.mkdir(exist_ok=True)
    
    sig_file = db_dir / "ids_signatures.jsonl"
    print(f"\n[csv-loader] Exporting to {sig_file}")
    exported = db.export_ids_signatures(str(sig_file))
    print(f"[csv-loader] ✓ Exported {exported} signatures")
    
    # Save synthetic attacks for reference
    synthetic_file = db_dir / "synthetic_from_csv.jsonl"
    with open(synthetic_file, 'w') as f:
        for attack in synthetic:
            f.write(json.dumps(attack) + "\n")
    print(f"[csv-loader] ✓ Saved {len(synthetic)} synthetic attacks to {synthetic_file}")
    
    print("\n" + "="*60)
    print("✓ Database initialization complete!")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
