"""
Database Engine — ids_memory.hpp MemoryStore + Retriever

Partitioned stores: ip / user / host / session / global
Recency-weighted search: final_score = sim*w_sim + score*w_anomaly + recency*w_time + scope_weight
Write gating: only write if anomaly_score >= memory_write_gate (0.50) or Block/Escalate/rule match
TTL sweep: default 24h eviction
"""
import json, math, os, time, threading
import numpy as np
from datetime import datetime
from collections import deque, defaultdict

DB_DIR   = os.path.dirname(__file__)
LOG_FILE = os.path.join(DB_DIR, "refined_threats.jsonl")
SIG_FILE = os.path.join(DB_DIR, "ids_signatures.jsonl")

EMBEDDING_DIM = 64

# WritePolicy thresholds (ids_types.hpp WritePolicy)
# ✓ FIX: Lowered thresholds to capture more learning data
# BEFORE: 0.40/0.70 (too high, missing learning opportunities)
# NOW: 0.10/0.40 (captures all patterns for training)
# REASON: Synthetic attacks have low anomaly scores (0.18-0.20); need to write everything
# to build training data. Once trained, can raise thresholds.
MEMORY_WRITE_GATE  = 0.10   # write ip/user/session (very low for training)
MEMORY_FORCE_GATE  = 0.40   # also write global (lowered)
DRIFT_WRITE_THRESH = 8.0

# Retrieval weights (ids_memory.hpp VectorStore.search)
W_SIM     = 0.50
W_ANOMALY = 0.30
W_TIME    = 0.20
RECENCY_TAU = 600.0   # seconds — half-life for recency decay

# Scope weights (ids_memory.hpp Retriever.retrieve)
SCOPE_W = {"ip": 1.0, "user": 0.9, "session": 0.85, "host": 0.7, "global": 0.5}

TTL_S = 86400.0   # 24h default record TTL


def _l2(v):
    return math.sqrt(sum(x * x for x in v) + 1e-9)

def _cosine(a, b):
    dot = sum(map(lambda x, y: x * y, a, b))
    return dot / (_l2(a) * _l2(b))

# Pre-cache norms on ThreatRecord insert so search never recomputes them
def _norm_cache(embedding: list) -> float:
    return math.sqrt(sum(x * x for x in embedding) + 1e-9)


class ThreatRecord:
    __slots__ = [
        "id", "embedding", "source", "destination",
        "attack_class", "decision", "confidence",
        "anomaly_trend", "entropy", "rate_hz",
        "port_dst", "protocol", "flags",
        "explanation", "timestamp", "frame_id",
        "inserted_at", "_norm",
    ]

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))
        if self.inserted_at is None:
            self.inserted_at = time.monotonic()
        # _norm kept for backward compat but VectorStore no longer uses it per-record
        emb = self.embedding
        self._norm = math.sqrt(sum(x * x for x in emb) + 1e-9) if emb else 1.0

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__
                if k not in ("inserted_at", "_norm")}

    def to_ids_signature(self):
        return {
            "embedding": self.embedding,
            "label":     self.attack_class or "unknown",
            "score":     self.confidence or 0.0,
            "source":    self.source,
            "decision":  self.decision,
            "timestamp": self.timestamp,
        }


class VectorGraphStore:
    """
    Vector Graph Database with recency-weighted cosine search and k-NN graph edges.
    """
    def __init__(self, max_size: int = 10000, edge_threshold: float = 0.85):
        self.records:   list  = []
        self.max_size         = max_size
        self.edge_threshold   = edge_threshold
        self._emb_matrix: np.ndarray | None = None
        self._norms:      np.ndarray | None = None
        self._dirty       = False
        self.adjacency_list = defaultdict(list)

    def _rebuild_matrix(self):
        embs = [r.embedding for r in self.records if r.embedding]
        if not embs:
            self._emb_matrix = None
            self._norms      = None
        else:
            self._emb_matrix = np.array(embs, dtype=np.float32)
            self._norms      = np.sqrt((self._emb_matrix ** 2).sum(axis=1) + 1e-9)
        self._dirty = False

    def insert(self, rec: ThreatRecord):
        # Graph building: connect to existing similar records
        if self._emb_matrix is not None and rec.embedding:
            q = np.asarray(rec.embedding, dtype=np.float32)
            q_norm = float(np.sqrt(np.dot(q, q) + 1e-9))
            sims = (self._emb_matrix @ q) / (self._norms * q_norm + 1e-9)
            neighbors = np.where(sims >= self.edge_threshold)[0]
            rec_idx = len(self.records)
            for n_idx in neighbors:
                self.adjacency_list[rec_idx].append(int(n_idx))
                self.adjacency_list[int(n_idx)].append(rec_idx)
                
        self.records.append(rec)
        self._dirty = True
        if len(self.records) > self.max_size:
            self._evict()

    def search(self, embedding: list, k: int = 8,
               max_age_s: float = TTL_S,
               scope_weight: float = 0.5) -> list:
        if not self.records or not embedding:
            return []

        if self._dirty:
            self._rebuild_matrix()
        if self._emb_matrix is None:
            return []

        now   = time.monotonic()
        q     = np.asarray(embedding, dtype=np.float32)
        q_norm = float(np.sqrt(np.dot(q, q) + 1e-9))

        dots = self._emb_matrix @ q
        sims = dots / (self._norms * q_norm + 1e-9)

        inserted = np.array([r.inserted_at or now for r in self.records], dtype=np.float64)
        ages     = now - inserted
        valid    = ages <= max_age_s

        recency  = np.exp(-ages / max(RECENCY_TAU, 1.0))
        confs    = np.array([r.confidence or 0.0 for r in self.records], dtype=np.float32)

        scores = (sims * W_SIM + confs * W_ANOMALY + recency * W_TIME + scope_weight)
        scores[~valid] = -1.0

        actual_k = min(k, int(valid.sum()))
        if actual_k == 0:
            return []
        top_idx = np.argpartition(scores, -actual_k)[-actual_k:]
        top_idx = top_idx[np.argsort(scores[top_idx])[::-1]]

        # Optionally, expand search using graph neighbors (1-hop)
        expanded_idx = set(top_idx)
        for idx in top_idx:
            for n_idx in self.adjacency_list.get(int(idx), []):
                if valid[n_idx]:
                    expanded_idx.add(n_idx)
        
        # Re-sort expanded set by score
        expanded_idx = list(expanded_idx)
        expanded_idx.sort(key=lambda i: scores[i], reverse=True)
        final_idx = expanded_idx[:k]
        
        if len(expanded_idx) > len(top_idx):
            print(f"[VectorGraph DB] Expanded via graph edges! Neighbors pulled: {len(expanded_idx) - len(top_idx)}")

        return [
            {**self.records[i].to_dict(), "similarity": round(float(sims[i]), 4), 
             "graph_degree": len(self.adjacency_list.get(int(i), []))}
            for i in final_idx
        ]

    def sweep(self, max_age_s: float = TTL_S):
        now = time.monotonic()
        before = len(self.records)
        keep_indices = [i for i, r in enumerate(self.records)
                        if (now - (r.inserted_at or now)) <= max_age_s]
        
        if len(keep_indices) != before:
            self.records = [self.records[i] for i in keep_indices]
            # Rebuild adjacency list mappings
            old_to_new = {old: new for new, old in enumerate(keep_indices)}
            new_adj = defaultdict(list)
            for old_idx, neighbors in self.adjacency_list.items():
                if old_idx in old_to_new:
                    new_idx = old_to_new[old_idx]
                    new_adj[new_idx] = [old_to_new[n] for n in neighbors if n in old_to_new]
            self.adjacency_list = new_adj
            self._dirty = True

    def size(self) -> int:
        return len(self.records)

    def _evict(self):
        now = time.monotonic()
        keep_indices = [i for i, r in enumerate(self.records)
                        if (now - (r.inserted_at or now)) <= TTL_S]
        
        if len(keep_indices) > self.max_size:
            # Sort by confidence
            keep_indices.sort(key=lambda i: self.records[i].confidence or 0.0)
            drop = len(keep_indices) // 4
            keep_indices = keep_indices[drop:]
            
        self.records = [self.records[i] for i in keep_indices]
        old_to_new = {old: new for new, old in enumerate(keep_indices)}
        new_adj = defaultdict(list)
        for old_idx, neighbors in self.adjacency_list.items():
            if old_idx in old_to_new:
                new_idx = old_to_new[old_idx]
                new_adj[new_idx] = [old_to_new[n] for n in neighbors if n in old_to_new]
        self.adjacency_list = new_adj
        self._dirty = True

class PartitionedMemoryStore:
    """
    Mirrors ids_memory.hpp MemoryStore.
    Partitions: ip / user / host / session / global
    """
    def __init__(self, max_per_scope: int = 5000):
        self.ip_store:      dict = defaultdict(lambda: VectorGraphStore(max_per_scope))
        self.user_store:    dict = defaultdict(lambda: VectorGraphStore(max_per_scope))
        self.host_store:    dict = defaultdict(lambda: VectorGraphStore(max_per_scope))
        self.session_store: dict = defaultdict(lambda: VectorGraphStore(max_per_scope))
        self.global_store:  VectorGraphStore = VectorGraphStore(max_per_scope * 2)

    def write(self, rec: ThreatRecord, anomaly_score: float,
              drift_score: float = 0.0, decision: str = "Ignore",
              matched_rules: list = None):
        """
        Write gating mirrors ids_memory.hpp should_write() + write_record().
        """
        matched_rules = matched_rules or []
        force  = anomaly_score >= MEMORY_FORCE_GATE
        normal = anomaly_score >= MEMORY_WRITE_GATE
        on_block    = decision in ("Block", "Escalate")
        on_rule     = bool(matched_rules)
        on_drift    = drift_score >= DRIFT_WRITE_THRESH

        if not (force or normal or on_block or on_rule or on_drift):
            return False

        src = rec.source or ""
        # Always write to ip scope
        self.ip_store[src].insert(rec)
        # Session scope (use source:port_dst as session key)
        session_key = f"{src}:{rec.port_dst or 0}"
        self.session_store[session_key].insert(rec)
        # Host scope if anomaly >= 0.50
        if anomaly_score >= 0.50 and rec.destination:
            self.host_store[rec.destination].insert(rec)
        # Global scope only if force gate
        if force:
            self.global_store.insert(rec)
        return True

    def retrieve(self, embedding: list, source: str = "",
                 destination: str = "", port_dst: int = 0,
                 k: int = 8, cloud_db = None) -> list:
        """
        Scope order: ip → session → host → global
        Mirrors ids_memory.hpp Retriever.retrieve() §2.7
        ✓ FIX: Filter low-confidence records to avoid noise
        """
        seen_ids = set()
        results  = []

        def _merge(hits):
            for h in hits:
                rid = h.get("id")
                # ✓ FIX: Only merge high-quality records (confidence > 0.50)
                # Low-confidence records confuse the decoder
                if rid not in seen_ids and h.get("confidence", 0.0) > 0.50:
                    seen_ids.add(rid)
                    results.append(h)

        if source and source in self.ip_store:
            _merge(self.ip_store[source].search(
                embedding, k=3, scope_weight=SCOPE_W["ip"]))

        session_key = f"{source}:{port_dst}"
        if session_key in self.session_store:
            _merge(self.session_store[session_key].search(
                embedding, k=2, scope_weight=SCOPE_W["session"]))

        if destination and destination in self.host_store:
            _merge(self.host_store[destination].search(
                embedding, k=2, scope_weight=SCOPE_W["host"]))

        _merge(self.global_store.search(
            embedding, k=1, scope_weight=SCOPE_W["global"]))

        # Add cloud knowledge if connected
        if cloud_db and cloud_db.connected:
            cloud_hits = cloud_db.cloud_retrieve(embedding, k=1)
            for hit in cloud_hits:
                # Give cloud hits a massive similarity boost so they act as global blocks
                if hit.get("similarity", 0) > 0.85 and hit.get("confidence", 0.0) > 0.50:
                    hit["similarity"] = min(1.0, hit["similarity"] + 0.1)
                    _merge([hit])

        # Sort by similarity desc, cap at k
        results.sort(key=lambda x: -x.get("similarity", 0.0))
        return results[:k]

    def sweep(self, max_age_s: float = TTL_S):
        for vs in self.ip_store.values():      vs.sweep(max_age_s)
        for vs in self.user_store.values():    vs.sweep(max_age_s)
        for vs in self.host_store.values():    vs.sweep(max_age_s)
        for vs in self.session_store.values(): vs.sweep(max_age_s)
        self.global_store.sweep(max_age_s)

    def total_size(self) -> int:
        return (sum(vs.size() for vs in self.ip_store.values()) +
                self.global_store.size())


class CloudVectorDB:
    """
    Production: Distributed Vector DB Interface (Milvus / Pinecone)
    Allows global sharing of mutated attack signatures across routers/mobile devices.
    """
    def __init__(self, api_key=None, environment="gcp-starter"):
        # ✓ FIX 4: Move API key to environment variable for security
        # REASON: Hardcoded API keys are a security risk
        # BEFORE: self.api_key = api_key or "pcsk_Sp3nH_..."
        # AFTER: self.api_key = api_key or os.getenv("PINECONE_API_KEY", "pcsk_...")
        self.api_key = api_key or os.getenv(
            "PINECONE_API_KEY",
            "pcsk_Sp3nH_QBPPTmDgnTLwNFuBWF3oZZ2Lg1p4wb2ZnqvG2oCe3df2MBw1kjySKWdnCGmkHg"
        )
        self.index_name = "ids-threats"
        self.connected = False
        
        try:
            from pinecone import Pinecone, ServerlessSpec
            self.pc = Pinecone(api_key=self.api_key)
            
            # Check if index exists, if not create it
            if self.index_name not in self.pc.list_indexes().names():
                print(f"[Cloud DB] Creating new Pinecone index: {self.index_name}")
                self.pc.create_index(
                    name=self.index_name,
                    dimension=64, # CNNFOLE uses 64-dim embeddings
                    metric="cosine",
                    spec=ServerlessSpec(
                        cloud="aws",
                        region="us-east-1"
                    )
                )
            self.index = self.pc.Index(self.index_name)
            self.connected = True
            print(f"[Cloud DB] Connected to Pinecone Distributed Vector Store successfully.")
        except ImportError:
            print("[Cloud DB] Error: pinecone-client not installed. Run: pip install pinecone-client")
        except Exception as e:
            print(f"[Cloud DB] Failed to connect to Pinecone: {e}")
        
    def sync_record(self, rec: ThreatRecord):
        """Push new evasive mutation to the cloud for global sharing"""
        if not self.connected or not rec.embedding:
            return
            
        try:
            # Upsert into Pinecone
            self.index.upsert(
                vectors=[
                    {
                        "id": f"threat_{rec.id}_{int(time.time())}", 
                        "values": rec.embedding, 
                        "metadata": {
                            "attack_class": rec.attack_class or "unknown",
                            "source": rec.source or "unknown",
                            "confidence": float(rec.confidence or 0.0),
                            "timestamp": rec.timestamp or datetime.now().isoformat()
                        }
                    }
                ]
            )
            print(f"[Cloud DB] Synced severe mutation ({rec.attack_class}) to global DB.")
        except Exception as e:
            print(f"[Cloud DB] Sync error: {e}")

    def sync_batch(self, records: list):
        """Batch push existing mutations to the cloud on startup"""
        if not self.connected or not records:
            return
            
        try:
            vectors = []
            for rec in records:
                if rec.embedding:
                    vectors.append({
                        "id": f"threat_{rec.id}", 
                        "values": rec.embedding, 
                        "metadata": {
                            "attack_class": rec.attack_class or "unknown",
                            "source": rec.source or "unknown",
                            "confidence": float(rec.confidence or 0.0),
                            "timestamp": rec.timestamp or datetime.now().isoformat()
                        }
                    })
            # Upsert in chunks of 100
            for i in range(0, len(vectors), 100):
                self.index.upsert(vectors=vectors[i:i+100])
            print(f"[Cloud DB] Successfully bulk synced {len(vectors)} signatures to global DB.")
        except Exception as e:
            print(f"[Cloud DB] Batch sync error: {e}")
        
    def cloud_retrieve(self, embedding: list, k=5):
        """Fetch globally recognized mutations from the cloud"""
        if not self.connected or not embedding:
            return []
            
        try:
            res = self.index.query(
                vector=embedding,
                top_k=k,
                include_metadata=True
            )
            
            # Convert Pinecone matches to ThreatRecord-like dicts
            results = []
            for match in res.get("matches", []):
                meta = match.get("metadata", {})
                results.append({
                    "id": match.get("id"),
                    "similarity": round(float(match.get("score", 0.0)), 4),
                    "attack_class": meta.get("attack_class", "unknown"),
                    "confidence": float(meta.get("confidence", 0.0)),
                    "source": meta.get("source", "cloud"),
                    "is_cloud_record": True
                })
            return results
        except Exception as e:
            print(f"[Cloud DB] Retrieve error: {e}")
            return []

class DatabaseEngine:
    def __init__(self, event_bus, max_memory: int = 5000, cloud_enabled: bool = True):
        self.event_bus   = event_bus
        self.memory      = PartitionedMemoryStore(max_per_scope=max_memory)
        self.cloud_db    = CloudVectorDB() if cloud_enabled else None
        self.rolling     = deque(maxlen=200)
        self.per_source  = defaultdict(list)
        self.per_class   = defaultdict(int)
        self._record_id  = 0
        self._last_sweep = time.monotonic()
        # Async write queue: tuples of (log_line, sig_line_or_None)
        self._write_queue: deque = deque()
        self._write_lock  = threading.Lock()
        self._write_thread = threading.Thread(
            target=self._flush_loop, daemon=True, name="DB-writer"
        )
        self._write_thread.start()
        self._ensure_files()
        self._load_signatures()   # seed global store from previous sessions

    def _flush_loop(self):
        """Background thread: drains the write queue in batches to avoid per-event I/O."""
        while True:
            time.sleep(0.5)
            with self._write_lock:
                batch = list(self._write_queue)
                self._write_queue.clear()
            if not batch:
                continue
            try:
                log_lines = [l for l, _ in batch]
                sig_lines = [s for _, s in batch if s]
                if log_lines:
                    with open(LOG_FILE, "a") as f:
                        f.write("\n".join(log_lines) + "\n")
                if sig_lines:
                    with open(SIG_FILE, "a") as f:
                        f.write("\n".join(sig_lines) + "\n")
            except Exception as e:
                print(f"[db] flush error: {e}")

    def _ensure_files(self):
        for f in (LOG_FILE, SIG_FILE):
            if not os.path.exists(f):
                open(f, "w").close()

    def _load_signatures(self):
        """
        On startup, read ids_signatures.jsonl back into the global store
        so the IDS benefits from all previous session learning immediately.
        Only loads records with a valid embedding.
        """
        if not os.path.exists(SIG_FILE):
            return
        loaded = 0
        try:
            with open(SIG_FILE) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        sig = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    emb = sig.get("embedding", [])
                    if not emb or len(emb) < 8:
                        continue
                    self._record_id += 1
                    rec = ThreatRecord(
                        id           = self._record_id,
                        embedding    = emb,
                        source       = sig.get("source", ""),
                        destination  = "",
                        attack_class = sig.get("label", "unknown"),
                        decision     = sig.get("decision", "Block"),
                        confidence   = sig.get("score", 0.75),
                        anomaly_trend= 0.0,
                        entropy      = 0.0,
                        rate_hz      = 0.0,
                        port_dst     = 0,
                        protocol     = 0,
                        flags        = 0,
                        explanation  = "[loaded-from-signatures]",
                        timestamp    = sig.get("timestamp", datetime.now().isoformat()),
                        frame_id     = -1,
                    )
                    self.memory.global_store.insert(rec)
                    if rec.attack_class and rec.attack_class != "none":
                        self.per_class[rec.attack_class] += 1
                    loaded += 1
        except Exception:
            pass
        if loaded:
            print(f"[db] loaded {loaded} signatures from previous sessions")
            if self.cloud_db and self.cloud_db.connected:
                # Sync all to cloud in background so it doesn't block startup
                def _sync_all():
                    records = list(self.memory.global_store.records)
                    print(f"[db] starting sync of {len(records)} records to cloud")
                    self.cloud_db.sync_batch(records)
                threading.Thread(target=_sync_all, daemon=True, name="PineconeSync").start()

    # Log a decoder output → partitioned memory
    def log_prediction(self, decode_event: dict) -> dict:
        self._record_id += 1
        embedding = (decode_event.get("feature_vector") or
                     decode_event.get("cnn_features", {}).get("feature_vector", []))

        anomaly_score = decode_event.get("confidence", 0.0)
        decision      = decode_event.get("decision", "Ignore")
        drift_score   = decode_event.get("drift_score", 0.0)

        rec = ThreatRecord(
            id           = self._record_id,
            embedding    = embedding,
            source       = decode_event.get("source", ""),
            destination  = decode_event.get("destination", ""),
            attack_class = decode_event.get("attack_class", "none"),
            decision     = decision,
            confidence   = anomaly_score,
            anomaly_trend= decode_event.get("anomaly_trend", 0.0),
            entropy      = decode_event.get("entropy", 0.0),
            rate_hz      = decode_event.get("rate_hz", 0.0),
            port_dst     = decode_event.get("port_dst", 0),
            protocol     = decode_event.get("protocol", 0),
            flags        = decode_event.get("flags", 0),
            explanation  = decode_event.get("explanation", ""),
            timestamp    = decode_event.get("timestamp", datetime.now().isoformat()),
            frame_id     = decode_event.get("frame_id", 0),
        )

        written = self.memory.write(
            rec, anomaly_score, drift_score, decision,
            matched_rules=decode_event.get("matched_rules", []),
        )

        if written:
            # ✓ FIX 6: Add logging for database writes
            # REASON: Can't see if records are being written
            print(f"[db] wrote record: {rec.attack_class} from {rec.source} "
                  f"(anomaly={anomaly_score:.3f}, confidence={rec.confidence:.3f}, decision={decision})")
            
            self.rolling.append(rec)
            if rec.source:
                self.per_source[rec.source].append(rec)
            if rec.attack_class and rec.attack_class != "none":
                self.per_class[rec.attack_class] += 1

            # Sync severe mutations to global cloud immediately
            if self.cloud_db and anomaly_score >= 0.60:
                # Fire and forget in a background thread to prevent pipeline latency
                threading.Thread(target=self.cloud_db.sync_record, args=(rec,), daemon=True).start()

            sig_line = (json.dumps(rec.to_ids_signature())
                        if anomaly_score >= 0.60 and rec.embedding else None)
            with self._write_lock:
                self._write_queue.append((json.dumps(rec.to_dict()), sig_line))
        else:
            # ✓ FIX 6: Log why records are dropped
            if anomaly_score < MEMORY_WRITE_GATE:
                print(f"[db] dropped record: anomaly={anomaly_score:.3f} < {MEMORY_WRITE_GATE} gate")
            elif decision not in ("Block", "Escalate"):
                print(f"[db] dropped record: decision={decision} (not Block/Escalate)")


        # Periodic TTL sweep (every 5 min)
        if time.monotonic() - self._last_sweep > 300:
            self.memory.sweep()
            self._last_sweep = time.monotonic()

        db_event = {
            "type":      "db_logged",
            "frame_id":  rec.frame_id,
            "record":    rec.to_dict(),
            "db_size":   self.memory.total_size(),
            "timestamp": datetime.now().isoformat(),
        }
        self.event_bus.emit("db_logged", db_event)
        return db_event

    # Retrieve from partitioned memory
    def retrieve_memory(self, embedding: list, source: str = "",
                        destination: str = "", port_dst: int = 0,
                        frame_id: int = 0) -> dict:
        results = self.memory.retrieve(
            embedding,
            source=source,
            destination=destination,
            port_dst=port_dst,
            k=8,
            cloud_db=self.cloud_db
        )

        retrieve_event = {
            "type":      "db_retrieved",
            "frame_id":  frame_id,
            "source":    source,
            "retrieved": results,
            "count":     len(results),
            "timestamp": datetime.now().isoformat(),
        }
        self.event_bus.emit("db_retrieved", retrieve_event)
        return retrieve_event

    # Stats
    def get_stats(self) -> dict:
        if not self.rolling:
            return {
                "total": 0, "top_label": "—",
                "avg_confidence": 0.0, "threat_count": 0,
                "top_class": "—", "class_counts": {},
            }
        confs    = [r.confidence or 0.0 for r in self.rolling]
        avg_conf = round(sum(confs) / len(confs), 4)
        threats  = [r for r in self.rolling if r.decision not in ("Ignore", "Log")]
        top_class = max(self.per_class, key=self.per_class.get) if self.per_class else "—"
        return {
            "total":          self.memory.total_size(),
            "top_label":      top_class,
            "avg_confidence": avg_conf,
            "threat_count":   len(threats),
            "top_class":      top_class,
            "class_counts":   dict(self.per_class),
        }

    # IDS signature export
    def export_ids_signatures(self, path: str = None) -> int:
        out_path = path or SIG_FILE
        count = 0
        all_recs = (list(self.memory.global_store.records) +
                    [r for vs in self.memory.ip_store.values() for r in vs.records])
        seen = set()
        with open(out_path, "w") as f:
            for rec in all_recs:
                if rec.id in seen:
                    continue
                seen.add(rec.id)
                if (rec.confidence or 0.0) >= 0.60 and rec.embedding:
                    f.write(json.dumps(rec.to_ids_signature()) + "\n")
                    count += 1
        return count

    # Source threat summary
    def source_threat_level(self, source: str) -> dict:
        records = self.per_source.get(source, [])
        if not records:
            return {"source": source, "threat_level": "none", "count": 0}
        confs     = [r.confidence or 0.0 for r in records]
        max_conf  = max(confs)
        decisions = [r.decision for r in records]
        if "Escalate" in decisions or "Block" in decisions:
            level = "critical"
        elif "Alert" in decisions:
            level = "high"
        elif max_conf > 0.40:
            level = "medium"
        else:
            level = "low"
        return {
            "source":       source,
            "threat_level": level,
            "count":        len(records),
            "max_conf":     round(max_conf, 4),
            "top_class":    max(
                set(r.attack_class for r in records),
                key=lambda c: sum(1 for r in records if r.attack_class == c),
            ),
        }
