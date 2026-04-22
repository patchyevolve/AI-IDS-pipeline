"""
Hybrid Decoder — ids_reasoning.hpp + ids_decision.hpp + ids_correlation.hpp

Pipeline:
  1. Build token sequence: [local_emb, seg_state, L2s_state, L2l_state, ...retrieved]
  2. Single-head softmax attention pool → fused context vector
  3. fuse_score() with ScoreFusionWeights
  4. classifyAttack() mirroring ids_reasoning.hpp
  5. Adaptive thresholds (ids_adaptive.hpp AdaptiveLayer)
  6. DecisionEngine: hysteresis, cooldown, repeat escalation
  7. CorrelationEngine: repeat/multi-stage/distributed/slow-attack detection
"""
import math, time
import numpy as np
from datetime import datetime
from collections import defaultdict, deque

# Constants
EMBEDDING_DIM    = 64
SSM_STATE_DIM    = 32
NUM_HIERARCHY    = 4
K_TOP_RETRIEVAL  = 8

# ScoreFusionWeights (ids_types.hpp)
W_LOCAL     = 0.50
W_SEGMENT   = 0.25
W_HISTORY   = 0.15
W_DRIFT     = 0.10
W_RETRIEVAL = 0.15
W_RULE      = 0.10

# Default DecisionThresholds
T_IGNORE = 0.20
T_LOG    = 0.40
T_ALERT  = 0.60
T_BLOCK  = 0.85

DECISIONS = ["Ignore", "Log", "Alert", "Block", "Escalate"]

ATTACK_CLASSES = [
    "none", "DoS/DDoS", "EncryptedC2/Exfiltration",
    "BruteForce/CredentialStuffing", "FileSystemAnomaly/Ransomware",
    "LateralMovement/Persistence", "PortScan", "DNSTunnel",
    "UnknownHighSeverity", "UnknownLowSeverity",
]




# Attention pool (ids_reasoning.hpp detail::attention_pool)
def _attention_pool(tokens: list, weights: list) -> list:
    """Weighted sum of token vectors — vectorised."""
    T = np.asarray(tokens, dtype=np.float32)   # (n_tokens, dim)
    w = np.asarray(weights, dtype=np.float32)  # (n_tokens,)
    return (w @ T).tolist()                    # (dim,)


def _single_head_attention(tokens: list) -> tuple:
    """
    Single-head attention with query = tokens[0] (local embedding).
    Returns (pooled_vector, attention_weights).
    """
    if not tokens:
        return [0.0] * EMBEDDING_DIM, []
    T      = np.asarray(tokens, dtype=np.float32)   # (n, dim)
    query  = T[0]                                    # (dim,)
    scale  = 1.0 / math.sqrt(EMBEDDING_DIM)
    scores = (T @ query) * scale                     # (n,) — single matmul
    scores -= scores.max()                           # numerical stability
    exps    = np.exp(scores)
    weights = (exps / (exps.sum() + 1e-9)).tolist()
    pooled  = _attention_pool(tokens, weights)
    return pooled, weights


# Adaptive threshold tracker (ids_adaptive.hpp)
class AdaptiveThresholds:
    """
    Per-scope EMA baselines → adaptive alert/block thresholds.
    Global baseline (α=0.001), IP baseline (α=0.05).
    """
    K_ALERT = 3.0
    K_BLOCK = 5.0
    MIN_T   = 0.30
    MAX_T   = 0.90

    def __init__(self):
        self._global_mean = 0.0
        self._global_var  = 1e-6
        self._ip_mean:  dict = defaultdict(float)
        self._ip_var:   dict = defaultdict(lambda: 1e-6)
        self._frozen:   dict = defaultdict(bool)

    def update(self, source: str, anomaly_score: float):
        # Freeze if anomaly is high (ids_adaptive.hpp maybe_freeze)
        self._frozen[source] = anomaly_score >= 0.70

        # Global EMA (very slow)
        if not self._frozen.get("__global__", False):
            delta = anomaly_score - self._global_mean
            self._global_mean += 0.001 * delta
            self._global_var  += 0.001 * (delta * delta - self._global_var)

        # IP EMA (fast)
        if not self._frozen[source]:
            delta = anomaly_score - self._ip_mean[source]
            self._ip_mean[source] += 0.05 * delta
            self._ip_var[source]  += 0.05 * (delta * delta - self._ip_var[source])

    def thresholds(self, source: str = "") -> dict:
        mean = self._ip_mean.get(source, self._global_mean) if source else self._global_mean
        std  = math.sqrt(max(self._ip_var.get(source, self._global_var), 1e-6))
        alert = max(self.MIN_T, min(self.MAX_T, mean + self.K_ALERT * std))
        block = max(alert + 0.05, min(0.95, mean + self.K_BLOCK * std))
        log   = max(0.10, min(alert - 0.05, alert * 0.6))
        return {"ignore": log * 0.5, "log": log, "alert": alert, "block": block}


# Correlation engine (ids_correlation.hpp)
class CorrelationEngine:
    """
    Detects: repeat, multi-stage, distributed, slow-attack, campaigns.
    """
    REPEAT_N      = 3
    REPEAT_WIN    = 60.0
    DIST_SOURCES  = 5
    DIST_WIN      = 60.0
    SLOW_WIN      = 3600.0
    SLOW_N        = 10
    SLOW_SCORE    = 0.30
    CAMPAIGN_IDLE = 1800.0

    MULTI_STAGE_PATTERNS = [
        ("LateralMovement",
         ["PortScan", "BruteForce/CredentialStuffing", "LateralMovement/Persistence"],
         600.0),
        ("APT-Exfiltration",
         ["BruteForce/CredentialStuffing", "FileSystemAnomaly/Ransomware",
          "EncryptedC2/Exfiltration"],
         3600.0),
    ]

    def __init__(self):
        self._ip_records:   dict = defaultdict(deque)   # ip → deque of (ts, class, score)
        self._host_records: dict = defaultdict(deque)   # host → deque of (ts, src, score)
        self._campaigns:    dict = {}                   # id → dict

    def process(self, source: str, destination: str, attack_class: str,
                confidence: float, decision: str) -> dict:
        if decision == "Ignore":
            return {"corr_score": 0.0, "campaign_id": "", "upgraded_decision": decision,
                    "repeat": False, "multi_stage": False, "distributed": False, "slow": False}

        ts = time.time()
        self._ip_records[source].append((ts, attack_class, confidence))
        self._host_records[destination].append((ts, source, confidence))
        # Trim old
        cutoff = ts - self.SLOW_WIN
        while self._ip_records[source] and self._ip_records[source][0][0] < cutoff:
            self._ip_records[source].popleft()
        while self._host_records[destination] and self._host_records[destination][0][0] < cutoff:
            self._host_records[destination].popleft()

        score = 0.0
        repeat      = self._detect_repeat(source, ts)
        multi_stage = self._detect_multi_stage(source)
        distributed = self._detect_distributed(destination, ts)
        slow        = self._detect_slow(source, ts)

        if repeat:      score += 0.20
        if multi_stage: score += 0.30
        if distributed: score += 0.25
        if slow:        score += 0.15

        score = min(score, 1.0)
        campaign_id = self._update_campaign(source, destination, attack_class, confidence, ts)

        upgraded = decision
        if score > 0.4 and decision == "Alert":
            upgraded = "Escalate"

        return {
            "corr_score":        round(score, 4),
            "campaign_id":       campaign_id,
            "upgraded_decision": upgraded,
            "repeat":            repeat,
            "multi_stage":       multi_stage,
            "distributed":       distributed,
            "slow":              slow,
        }

    def _detect_repeat(self, ip: str, now: float) -> bool:
        cutoff = now - self.REPEAT_WIN
        count  = sum(1 for ts, _, _ in self._ip_records[ip] if ts >= cutoff)
        return count >= self.REPEAT_N

    def _detect_multi_stage(self, ip: str) -> bool:
        records = list(self._ip_records[ip])
        for _, seq, max_gap in self.MULTI_STAGE_PATTERNS:
            matched, last_t = 0, 0.0
            for ts, cls, _ in records:
                if matched < len(seq) and cls == seq[matched]:
                    if matched == 0 or (ts - last_t) <= max_gap:
                        matched += 1
                        last_t   = ts
            if matched == len(seq):
                return True
        return False

    def _detect_distributed(self, host: str, now: float) -> bool:
        cutoff  = now - self.DIST_WIN
        sources = {src for ts, src, _ in self._host_records[host] if ts >= cutoff}
        return len(sources) >= self.DIST_SOURCES

    def _detect_slow(self, ip: str, now: float) -> bool:
        cutoff = now - self.SLOW_WIN
        count  = sum(1 for ts, _, sc in self._ip_records[ip]
                     if ts >= cutoff and sc >= self.SLOW_SCORE)
        return count >= self.SLOW_N

    def _update_campaign(self, src, dst, cls, score, ts) -> str:
        for cid, c in self._campaigns.items():
            if not c["active"]:
                continue
            if src in c["sources"] or c["attack_class"] == cls:
                c["last_seen"]   = ts
                c["event_count"] += 1
                c["max_score"]   = max(c["max_score"], score)
                if src not in c["sources"]:
                    c["sources"].append(src)
                return cid
        if score < 0.4:
            return ""
        cid = f"camp_{len(self._campaigns)}"
        self._campaigns[cid] = {
            "active": True, "attack_class": cls,
            "sources": [src], "hosts": [dst],
            "first_seen": ts, "last_seen": ts,
            "event_count": 1, "max_score": score,
        }
        return cid

    def active_campaigns(self) -> list:
        now = time.time()
        out = []
        for cid, c in self._campaigns.items():
            if c["active"]:
                if now - c["last_seen"] > self.CAMPAIGN_IDLE:
                    c["active"] = False
                else:
                    out.append({**c, "id": cid})
        return out


# Decision engine (ids_decision.hpp DecisionEngine)
class DecisionEngine:
    """
    Hysteresis, cooldown, repeat escalation, allow/block lists.
    """
    ALERT_COOLDOWN = 5.0
    BLOCK_COOLDOWN = 30.0
    HYST_HOLD      = 10.0
    HYST_DELTA     = 0.05
    ESC_REPEAT_N   = 3
    ESC_REPEAT_WIN = 300.0
    ESC_HIST       = 0.75
    ESC_DRIFT      = 8.0

    def __init__(self):
        self._last_decision:  dict = {}   # source → decision str
        self._last_time:      dict = {}   # source → float ts
        self._alert_count:    dict = defaultdict(int)
        self._first_alert:    dict = {}
        self._last_alert:     dict = {}

    def apply(self, decision: str, source: str, confidence: float,
              anomaly_history: float, drift_score: float,
              thresholds: dict) -> str:
        now = time.time()

        # Cooldown
        if source in self._last_time:
            age = now - self._last_time[source]
            ld  = self._last_decision.get(source, "Ignore")
            if ld == "Block" and age < self.BLOCK_COOLDOWN:
                if decision != "Escalate":
                    return ld
            elif ld == "Alert" and age < self.ALERT_COOLDOWN:
                if decision not in ("Block", "Escalate"):
                    return ld

        # Hysteresis
        if source in self._last_decision:
            age = now - self._last_time.get(source, 0)
            if age < self.HYST_HOLD:
                ld = self._last_decision[source]
                if ld == "Block" and confidence >= thresholds["block"] - self.HYST_DELTA:
                    decision = "Block"

        # Escalation checks
        if decision in ("Alert", "Block"):
            if anomaly_history >= self.ESC_HIST:
                decision = "Escalate"
            if drift_score >= self.ESC_DRIFT:
                decision = "Escalate"
            if self._should_escalate_repeat(source, now):
                decision = "Escalate"

        self._last_decision[source] = decision
        self._last_time[source]     = now

        if decision in ("Alert", "Block", "Escalate"):
            self._alert_count[source] += 1
            if source not in self._first_alert:
                self._first_alert[source] = now
            self._last_alert[source] = now

        return decision

    def _should_escalate_repeat(self, source: str, now: float) -> bool:
        if self._alert_count.get(source, 0) < self.ESC_REPEAT_N:
            return False
        first = self._first_alert.get(source)
        if first is None:
            return False
        return (now - first) <= self.ESC_REPEAT_WIN


class MetaLearningCoordinator:
    """
    Coordinates ThresholdLearner, FusionController, AdaptiveCollaborator
    and performs CNN + AE fusion adaptive BATCH UPDATE.
    """
    def __init__(self):
        self.performance_feedback = []
        self.batch_size = 10
        self.fusion_weights = {"cnn": 0.6, "ae": 0.4}
        self.adaptive_threshold = 0.5
        
    def threshold_learner(self, anomaly_scores):
        if anomaly_scores:
            self.adaptive_threshold = np.mean(anomaly_scores) + 0.1 * np.std(anomaly_scores)
            
    def fusion_controller(self, cnn_prob, recon_error):
        # Normalize recon error roughly
        norm_recon = min(recon_error / 100.0, 1.0)
        fused_score = self.fusion_weights["cnn"] * cnn_prob + self.fusion_weights["ae"] * norm_recon
        return fused_score
        
    def adaptive_collaborator(self, fused_score, true_label=None):
        self.performance_feedback.append(fused_score)
        if len(self.performance_feedback) >= self.batch_size:
            # Adaptive BATCH UPDATE
            self.threshold_learner(self.performance_feedback)
            # Adjust fusion weights based on variance (simple heuristic)
            var = np.var(self.performance_feedback)
            old_weights = dict(self.fusion_weights)
            if var > 0.1:
                self.fusion_weights["cnn"] = min(0.9, self.fusion_weights["cnn"] + 0.05)
                self.fusion_weights["ae"]  = max(0.1, self.fusion_weights["ae"] - 0.05)
            else:
                self.fusion_weights["cnn"] = max(0.1, self.fusion_weights["cnn"] - 0.05)
                self.fusion_weights["ae"]  = min(0.9, self.fusion_weights["ae"] + 0.05)
            
            print(f"\n[Meta-Learning] BATCH UPDATE! | Var: {var:.3f} | Threshold: {self.adaptive_threshold:.3f}")
            print(f"[Meta-Learning] Fusion Weights: {old_weights} -> {self.fusion_weights}")
            
            self.performance_feedback.clear()
            
    def process(self, cnn_event):
        cnn_prob = cnn_event.get("is_attack_prob", 0.0)
        recon_error = cnn_event.get("recon_error", 0.0)
        fused_score = self.fusion_controller(cnn_prob, recon_error)
        self.adaptive_collaborator(fused_score)
        return fused_score

# Main HybridDecoder
class HybridDecoder:
    def __init__(self, event_bus):
        self.event_bus   = event_bus
        self.adaptive    = AdaptiveThresholds()
        self.correlation = CorrelationEngine()
        self.decision_eng= DecisionEngine()
        self.meta_coordinator = MetaLearningCoordinator()
        
        # Initialize threat intelligence engine
        try:
            from threat_intelligence import ThreatIntelligenceEngine
            self.ti_engine = ThreatIntelligenceEngine()
        except ImportError:
            self.ti_engine = None

    def decode(self, cnn_event: dict, rnn_event: dict, db_memory: list = None,
               metadata: dict = None) -> dict:
        frame_id = cnn_event.get("frame_id", 0)
        source   = cnn_event.get("source", "")
        _metadata = metadata or {}
        db_memory = db_memory or []

        # 1. Build token sequence
        local_emb  = cnn_event.get("feature_vector", [0.0] * EMBEDDING_DIM)
        seg_vec    = rnn_event.get("context_vector",
                     rnn_event.get("global_state", {}).get("level_states", [[]])[0]
                     if rnn_event.get("global_state") else [0.0] * SSM_STATE_DIM)
        gs         = rnn_event.get("global_state", {})
        l2s_state  = (gs.get("level_states", [[]] * 4)[0]
                      if gs.get("level_states") else [0.0] * SSM_STATE_DIM)
        l2l_state  = (gs.get("level_states", [[]] * 4)[3]
                      if gs.get("level_states") else [0.0] * SSM_STATE_DIM)

        # Normalize all vectors to EMBEDDING_DIM (64) to prevent shape mismatches
        def _normalize_embedding(v, target_dim=EMBEDDING_DIM):
            """Normalize vector to target dimension by truncating or padding"""
            v_list = list(v) if not isinstance(v, list) else v
            if len(v_list) == 0:
                return [0.0] * target_dim
            if len(v_list) > target_dim:
                # Truncate: take first target_dim elements
                return v_list[:target_dim]
            else:
                # Pad: add zeros to reach target_dim
                return v_list + [0.0] * (target_dim - len(v_list))

        tokens = [
            _normalize_embedding(local_emb),
            _normalize_embedding(seg_vec),
            _normalize_embedding(l2s_state),
            _normalize_embedding(l2l_state),
        ]
        # Add retrieved DB records as tokens (up to K_TOP_RETRIEVAL)
        for rec in db_memory[:K_TOP_RETRIEVAL]:
            emb = rec.get("embedding") or rec.get("feature_vector")
            if emb:
                tokens.append(_normalize_embedding(emb))

        # 2. Single-head attention
        pooled, attn_weights = _single_head_attention(tokens)
        attn_weight = round(attn_weights[0] if attn_weights else 0.0, 4)

        # 3. fuse_score()
        local_score   = cnn_event.get("is_attack_prob", 0.0)
        segment_trend = rnn_event.get("anomaly_trend", 0.0)
        anomaly_hist  = rnn_event.get("anomaly_history", 0.0)
        drift_score   = rnn_event.get("drift_score", 0.0)
        drift_norm    = min(drift_score / 10.0, 1.0)

        retrieval_boost = 0.0
        if db_memory:
            # Check for high similarity hits (the cloud & local graphs now set confidence to anomaly_score, but might be empty early on)
            # The VectorGraphDB uses "similarity" to show how close the match is
            high_sims = [r.get("similarity", 0.0) for r in db_memory
                         if r.get("similarity", 0.0) > 0.8]
            if high_sims:
                retrieval_boost = W_RETRIEVAL

        # Rule signal: high entropy + SYN
        entropy = cnn_event.get("entropy", 0.0)
        flags   = cnn_event.get("flags", 0)
        rule_signal = min(entropy * (1.5 if (flags & 0x02) else 0.5), 1.0)
        rule_boost  = W_RULE * rule_signal

        # Use MetaLearningCoordinator for CNN + AE fusion
        meta_fused = self.meta_coordinator.process(cnn_event)

        # Boost the fused score dynamically if it's a known attack class from Tri-Model
        cnn_is_attack = cnn_event.get("is_attack_prob", 0.0) > 0.5

        # ✓ FIX: Use corrected signatures (confidence=0.95) from validator to boost decisions
        # REASON: Validator stores FN/FP corrections with high confidence (0.95)
        # These should directly boost the fused score to improve accuracy
        db_boost = 0.0
        db_decision_override = None
        if db_memory:
            # Find corrected signatures: high confidence (>0.85) indicates validator correction
            corrected_sigs = [r for r in db_memory 
                             if r.get("confidence", 0.0) > 0.85]
            
            if corrected_sigs:
                # Use the best corrected signature
                best_corrected = corrected_sigs[0]
                corrected_conf = best_corrected.get("confidence", 0.0)
                corrected_decision = best_corrected.get("decision", None)
                
                # Boost based on how confident the correction is
                # confidence=0.95 → boost=0.30, confidence=0.90 → boost=0.25, etc.
                db_boost = (corrected_conf - 0.60) * 0.5  # Maps 0.85→0.125, 0.95→0.175
                
                # If corrected signature is very confident (>0.90), use its decision directly
                if corrected_conf > 0.90 and corrected_decision in DECISIONS:
                    db_decision_override = corrected_decision
            
            # Also check for high-similarity matches (even if not corrected)
            # These provide additional context but don't override decisions
            high_sim_matches = [r for r in db_memory 
                               if r.get("similarity", 0.0) > 0.90 and r.get("confidence", 0.0) > 0.60]
            if high_sim_matches and not db_decision_override:
                # Add extra boost for high-similarity matches
                db_boost += 0.10

        # Calculate base score with proper normalization
        # Base weights sum to 1.0: W_LOCAL + W_SEGMENT + W_HISTORY + W_DRIFT = 1.0
        base_score = (W_LOCAL    * local_score   +
                      W_SEGMENT  * segment_trend +
                      W_HISTORY  * anomaly_hist  +
                      W_DRIFT    * drift_norm)
        
        # Additional signals: retrieval_boost, rule_boost, meta_fused
        # These are already normalized to [0, 1], so limit their contribution
        additional_signals = (retrieval_boost + rule_boost + meta_fused) * 0.05  # Max 5% boost
        
        # Combine base score with additional signals and database boost
        fused = base_score + additional_signals + db_boost
                 
        if cnn_is_attack:
            # If CNN is confident it's an attack, use CNN score as minimum
            fused = max(fused, cnn_event.get("is_attack_prob", 0.0) * 0.7)
        else:
            # ✓ FIX: During training, don't suppress scores too aggressively
            # Only suppress if Gate CNN is VERY confident it's normal (prob < 0.15)
            gate_prob = cnn_event.get("is_attack_prob", 0.0)
            if gate_prob < 0.15:
                fused = min(fused, 0.35)  # Suppress only if very confident normal
            # Otherwise, let other signals (RNN, DB) contribute
            
        fused = min(max(fused, 0.0), 1.0)

        # 4. Adaptive thresholds
        self.adaptive.update(source, local_score)
        thresholds = self.adaptive.thresholds(source)

        # 5. Score → decision
        # ✓ FIX 3: Use database override if available, otherwise use thresholds
        if db_decision_override and db_decision_override in DECISIONS:
            decision = db_decision_override
        elif   fused < thresholds["ignore"]: decision = "Ignore"
        elif fused < thresholds["log"]:    decision = "Log"
        elif fused < thresholds["alert"]:  decision = "Alert"
        elif fused < thresholds["block"]:  decision = "Block"
        else:                              decision = "Escalate"

        # 6. classifyAttack()
        attack_class = cnn_event.get("atk_class", "none")
        if attack_class == "none":
            attack_class = self._classify(cnn_event, rnn_event, fused, thresholds)

        # 7. DecisionEngine (hysteresis, cooldown, escalation)
        decision = self.decision_eng.apply(
            decision, source, fused, anomaly_hist, drift_score, thresholds)

        # 8. Correlation engine
        destination = cnn_event.get("destination", "")
        corr = self.correlation.process(source, destination, attack_class, fused, decision)
        if corr["upgraded_decision"] in DECISIONS:
            decision = corr["upgraded_decision"]

        # 9. Consistency guard — no Block/Escalate with class=none
        # If score is high enough to block but classifier found nothing,
        # label it UnknownHighSeverity rather than silently blocking "none".
        if attack_class == "none" and decision in ("Alert", "Block", "Escalate"):
            attack_class = "UnknownHighSeverity"
            
        # Inverse: if class is none and score is below alert, don't alert/block
        # And if it is normal traffic (Ignore/Log), it shouldn't have an attack class.
        if decision in ("Ignore", "Log"):
            attack_class = "none"

        explanation = (
            f"[AI] decision={decision} class={attack_class} "
            f"conf={fused:.3f} local={local_score:.3f} "
            f"trend={segment_trend:.3f} hist={anomaly_hist:.3f} "
            f"drift={drift_score:.3f} attn={attn_weight:.4f} "
            f"db_hits={len(db_memory)} corr={corr['corr_score']:.3f} "
            f"campaign={corr['campaign_id']}"
        )

        decode_event = {
            "type":             "decoder_output",
            "frame_id":         frame_id,
            "source":           source,
            "decision":         decision,
            "prediction":       attack_class,
            "confidence":       round(fused, 4),
            "attack_class":     attack_class,
            "explanation":      explanation,
            "attention_weight": attn_weight,
            "local_score":      round(local_score, 4),
            "anomaly_trend":    round(segment_trend, 4),
            "db_memory_used":   bool(db_memory),
            "db_hits":          len(db_memory),
            "corr_score":       corr["corr_score"],
            "campaign_id":      corr["campaign_id"],
            "repeat_detected":  corr["repeat"],
            "multi_stage":      corr["multi_stage"],
            "distributed":      corr["distributed"],
            "all_probs": {
                "DoS/DDoS":    round(fused * 0.30, 4),
                "C2/Exfil":    round(fused * 0.25, 4),
                "BruteForce":  round(fused * 0.20, 4),
                "PortScan":    round(fused * 0.15, 4),
                "DNSTunnel":   round(fused * 0.10, 4),
                "Normal":      round(1.0 - fused,  4),
            },
            "timestamp": datetime.now().isoformat(),
            "metadata":  _metadata,
        }
        
        # Process through threat intelligence engine
        if self.ti_engine and decision != "none":
            try:
                attack_data = {
                    "source_ip": cnn_event.get("source", ""),
                    "destination_ip": cnn_event.get("destination", ""),
                    "attack_class": decision,
                    "severity": fused * 10,  # Scale to 0-10
                    "timestamp": datetime.now().timestamp(),
                    "protocol": cnn_event.get("protocol", 0),
                    "port_dst": cnn_event.get("port_dst", 0),
                    "entropy": cnn_event.get("entropy", 0),
                    "bytes_in": cnn_event.get("bytes_in", 0),
                    "bytes_out": cnn_event.get("bytes_out", 0),
                    "rate_hz": cnn_event.get("rate_hz", 0)
                }
                
                intelligence = self.ti_engine.process_attack(attack_data)
                
                # Enhance decision with threat intelligence
                decode_event["threat_level"] = intelligence.get("threat_level")
                decode_event["recommendations"] = intelligence.get("recommendations", [])
                decode_event["campaign_id"] = intelligence["campaign_correlation"].get("campaign_id")
                decode_event["threat_actor"] = intelligence["campaign_correlation"].get("threat_actor")
                decode_event["mitre_tactics"] = [t["name"] for t in intelligence.get("mitre_mapping", {}).get("tactics", [])]
                decode_event["mitre_techniques"] = [t["id"] for t in intelligence.get("mitre_mapping", {}).get("techniques", [])]
                decode_event["behavioral_anomalies"] = intelligence.get("behavioral_analysis", {}).get("ip_anomalies", [])
                
                # Escalate if critical
                if intelligence.get("threat_level") == "CRITICAL":
                    decode_event["decision"] = "Block"
                    decode_event["escalate"] = True
                    
            except Exception as e:
                print(f"[TI] Error processing threat intelligence: {e}")
        
        self.event_bus.emit("decoder_output", decode_event)
        return decode_event

    def _classify(self, cnn_event: dict, rnn_event: dict, score: float,
                  thresholds: dict = None) -> str:
        """Mirrors ids_reasoning.hpp ReasoningModel::classifyAttack()"""
        if score < 0.20:
            return "none"
        t_alert = (thresholds or {}).get("alert", T_ALERT)
        t_block = (thresholds or {}).get("block", T_BLOCK)

        rate_hz    = cnn_event.get("rate_hz",   0.0)
        entropy    = cnn_event.get("entropy",   0.0)
        port_dst   = cnn_event.get("port_dst",  0)
        flags      = cnn_event.get("flags",     0)
        protocol   = cnn_event.get("protocol",  0)
        burst      = cnn_event.get("burst_metric", 0.0)
        error_freq = rnn_event.get("error_freq", 0.0)
        trend      = rnn_event.get("anomaly_trend", 0.0)
        dom_type   = rnn_event.get("dominant_type", "")

        if burst > 0.8 and rate_hz > 500:                               return "DoS/DDoS"
        if entropy > 0.9 and error_freq > 0.5:                          return "EncryptedC2/Exfiltration"
        if dom_type == "auth" and trend > 0.6:                          return "BruteForce/CredentialStuffing"
        if dom_type == "file" and score > 0.7:                          return "FileSystemAnomaly/Ransomware"
        if dom_type == "proc" and rnn_event.get("drift_score", 0) > 5.0: return "LateralMovement/Persistence"
        if port_dst == 53 and entropy > 0.80 and protocol == 17:        return "DNSTunnel"
        if (flags & 0x02) and rate_hz > 200 and port_dst < 1024:        return "PortScan"
        # Fallback: use adaptive thresholds, not hardcoded constants
        if score >= t_block:  return "UnknownHighSeverity"
        if score >= t_alert:  return "UnknownLowSeverity"
        return "none"

    def active_campaigns(self) -> list:
        return self.correlation.active_campaigns()
