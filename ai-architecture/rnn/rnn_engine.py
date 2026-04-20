"""
RNN Engine — L1 SegmentSSM + L2 HierarchicalSSM (ids_level1.hpp + ids_ssm.hpp)

L1: per-source Mamba-style SSM (kSSMStateDim=32) with flush rules →
    produces SegmentState (anomaly_trend, rate_mean, error_freq, dominant_type)

L2: 4-level hierarchy (L2s/L2m/L2l-short/L2l-global) with signal-driven
    promotion and skip rules → produces GlobalState
    (level_states[4], anomaly_history, drift_score, baseline_model)
"""
import math, random
import numpy as np
from datetime import datetime
from collections import defaultdict, deque

# Constants matching ids_types.hpp
SSM_STATE_DIM    = 32    # kSSMStateDim
EMBEDDING_DIM    = 64    # kEmbeddingDim
NUM_HIERARCHY    = 4     # kNumHierarchyLvl
FLUSH_N          = 100   # FlushRules.flush_n
FLUSH_ANOMALY    = 0.70  # FlushRules.flush_anomaly
FLUSH_T          = 10.0  # FlushRules.flush_t (seconds)
PROMOTE_THRESH   = 0.50  # L1→L2s promote_threshold
SKIP_THRESH      = 0.20  # SkipRules.skip_threshold
MIN_SEGMENTS     = 3     # SkipRules.min_segments
TICK_RATES       = [1, 10, 60, 600]   # L2s/L2m/L2l-short/L2l-global




class MambaSSM:
    """
    Mamba-style selective SSM (ids_ssm.hpp SSM<SDIM,IDIM,ODIM>).
    ZOH discretization: A_bar = exp(-delta * exp(A_log))
    h_t = A_bar * h_{t-1} + delta * B(x) * x
    y   = C * h + D * x

    All weight matrices stored as float32 numpy arrays.
    The matmuls release the GIL via BLAS, giving real concurrency.
    """
    def __init__(self, state_dim: int, input_dim: int, seed: int):
        self.sdim = state_dim
        self.idim = input_dim
        rng       = random.Random(seed)
        s         = math.sqrt(1.0 / (state_dim + input_dim))

        def _mat(r, c): return np.array(
            [[rng.gauss(0, s) for _ in range(c)] for _ in range(r)], dtype=np.float32)
        def _vec(n, std): return np.array(
            [rng.gauss(0, std) for _ in range(n)], dtype=np.float32)

        self.A_log      = _vec(state_dim, 0.1) - 0.5          # (sdim,)
        self.B_proj     = _mat(state_dim, input_dim)           # (sdim, idim)
        self.C_proj     = _mat(state_dim, state_dim)           # (sdim, sdim)
        self.D_skip     = _vec(min(state_dim, input_dim), 0.01)
        self.delta_proj = _mat(state_dim, input_dim)           # (sdim, idim)
        self.h          = np.zeros(state_dim, dtype=np.float32)

    def step(self, x: list) -> list:
        xp = np.zeros(self.idim, dtype=np.float32)
        src = np.asarray(x, dtype=np.float32)
        n   = min(len(src), self.idim)
        xp[:n] = src[:n]

        # delta: softplus(delta_proj @ xp)  shape (sdim,)
        raw_delta = self.delta_proj @ xp
        delta = np.where(raw_delta > 20, raw_delta,
                         np.log1p(np.exp(np.clip(raw_delta, -20, 20))))

        # ZOH: A_bar = exp(-delta * exp(A_log))
        A_bar = np.exp(-delta * np.exp(self.A_log))

        # Bx = B_proj @ xp  shape (sdim,)
        Bx = self.B_proj @ xp

        # State update
        new_h = A_bar * self.h + delta * Bx

        # Stability clamp
        energy = float(np.sqrt(np.dot(new_h, new_h) + 1e-9))
        if energy > 100.0:
            np.clip(new_h, -10.0, 10.0, out=new_h)
        if not np.all(np.isfinite(new_h)):
            new_h = np.zeros(self.sdim, dtype=np.float32)
        self.h = new_h

        # Output: y = C @ h  (+D skip)
        y = self.C_proj @ self.h
        d = min(self.sdim, self.idim)
        y[:d] += self.D_skip[:d] * xp[:d]

        return y.tolist()

    def energy(self) -> float:
        return float(np.sqrt(np.dot(self.h, self.h) + 1e-9))

    def reset(self):
        self.h = np.zeros(self.sdim, dtype=np.float32)


class SegmentSSM:
    """
    L1 per-source SSM with flush rules (ids_level1.hpp SegmentSSM).
    Accumulates events, flushes into SegmentState on trigger.
    """
    def __init__(self, source: str):
        self.source  = source
        self.ssm     = MambaSSM(SSM_STATE_DIM, EMBEDDING_DIM, seed=hash(source) & 0xFFFF)
        self._reset_accum()
        self._seg_count   = 0
        self._last_flush  = None   # timestamp float

    def _reset_accum(self):
        self._count      = 0
        self._score_acc  = 0.0
        self._rate_acc   = 0.0
        self._err_count  = 0
        self._type_freq  = defaultdict(int)

    def update(self, local_state: dict, cnn_event: dict, ts: float):
        """
        Feed one LocalState into the SSM.
        Returns SegmentState dict if flush triggered, else None.
        """
        embedding = cnn_event.get("feature_vector", [0.0] * EMBEDDING_DIM)
        ssm_out   = self.ssm.step(embedding)

        self._count     += 1
        self._score_acc += local_state.get("anomaly_score", 0.0)
        self._rate_acc  += cnn_event.get("rate_hz", 0.0)
        if local_state.get("anomaly_score", 0.0) > 0.5:
            self._err_count += 1
        self._type_freq[cnn_event.get("event_type", "NetworkPacket")] += 1

        # Flush rules
        by_count   = self._count >= FLUSH_N
        avg_score  = self._score_acc / max(self._count, 1)
        by_anomaly = avg_score > FLUSH_ANOMALY
        by_time    = (self._last_flush is not None and
                      (ts - self._last_flush) >= FLUSH_T)

        if by_count or by_anomaly or by_time:
            return self._flush(ssm_out, ts)
        return None

    def _flush(self, ssm_out: list, ts: float) -> dict:
        n = max(self._count, 1)
        dom = max(self._type_freq, key=self._type_freq.get) if self._type_freq else "NetworkPacket"
        seg = {
            "state_vector":  [round(v, 6) for v in ssm_out],
            "anomaly_trend": round(self._score_acc / n, 4),
            "rate_mean":     round(self._rate_acc  / n, 2),
            "error_freq":    round(self._err_count / n, 4),
            "dominant_type": dom,
            "segment_count": self._seg_count,
        }
        self._seg_count += 1
        self._last_flush = ts
        self._reset_accum()
        return seg

    def reset(self):
        self.ssm.reset()
        self._reset_accum()
        self._seg_count  = 0
        self._last_flush = None


class HierarchicalSSM:
    """
    4-level hierarchy (ids_ssm.hpp HierarchicalSSM).
    L2s (fast) → L2m (medium) → L2l-short → L2l-global (slowest).
    Signal-driven promotion with skip rules.
    Maintains GlobalState: level_states[4], anomaly_history, drift_score, baseline_model.
    """
    def __init__(self, seed: int = 0):
        self.layers = [
            MambaSSM(SSM_STATE_DIM, SSM_STATE_DIM, seed=seed + i)
            for i in range(NUM_HIERARCHY)
        ]
        self.level_states    = [np.zeros(SSM_STATE_DIM, dtype=np.float32)
                                 for _ in range(NUM_HIERARCHY)]
        self.baseline_model  = np.zeros(SSM_STATE_DIM, dtype=np.float32)
        self.anomaly_history = 0.0
        self.drift_score     = 0.0
        self._tick           = 0

    def update(self, seg: dict, seg_count: int = 0, force_all: bool = False) -> dict:
        self._tick += 1
        anomaly_trend = seg.get("anomaly_trend", 0.0)
        state_vec     = seg.get("state_vector", [0.0] * SSM_STATE_DIM)

        # L2s (layer 0) — §1.5 L1→L2s
        promote_l2s = force_all or anomaly_trend > PROMOTE_THRESH
        skip_l2s    = (not force_all and
                       anomaly_trend < SKIP_THRESH and
                       seg_count < MIN_SEGMENTS)
        if promote_l2s and not skip_l2s:
            try:
                out = self.layers[0].step(state_vec)
                self.level_states[0] = np.asarray(out, dtype=np.float32)
            except Exception:
                self.layers[0].reset()

        # L2m (layer 1) — §1.6 L2s→L2m
        promote_l2m = (force_all or
                       self._tick % TICK_RATES[1] == 0 or
                       self.anomaly_history > 0.55 or
                       self.drift_score > 3.0)
        skip_l2m    = (not force_all and
                       self.anomaly_history < SKIP_THRESH and
                       self.drift_score < 1.0)
        if promote_l2m and not skip_l2m:
            try:
                out = self.layers[1].step(self.level_states[0].tolist())
                self.level_states[1] = np.asarray(out, dtype=np.float32)
            except Exception:
                self.layers[1].reset()

        # L2l-short (layer 2) — §1.7 L2m→L2l
        promote_l2l = (force_all or
                       self._tick % TICK_RATES[2] == 0 or
                       self.drift_score > 8.0 or
                       self.anomaly_history > 0.70)
        skip_l2l    = (not force_all and
                       self.anomaly_history < 0.70 and
                       self.drift_score < 8.0)
        if promote_l2l and not skip_l2l:
            try:
                out = self.layers[2].step(self.level_states[1].tolist())
                self.level_states[2] = np.asarray(out, dtype=np.float32)
            except Exception:
                self.layers[2].reset()

        # L2l-global (layer 3) — slowest
        promote_global = (force_all or
                          self._tick % TICK_RATES[3] == 0 or
                          self.drift_score > 12.0)
        if promote_global:
            try:
                out = self.layers[3].step(self.level_states[2].tolist())
                self.level_states[3] = np.asarray(out, dtype=np.float32)
            except Exception:
                self.layers[3].reset()

        # Baseline EMA (α=0.01) — vectorised
        self.baseline_model += 0.01 * (self.level_states[3] - self.baseline_model)

        # Drift = L2(deepest_state, baseline) — single numpy call
        diff = self.level_states[3] - self.baseline_model
        self.drift_score = round(float(np.sqrt(np.dot(diff, diff))), 4)

        # Anomaly history EMA (τ=0.05)
        self.anomaly_history += 0.05 * (anomaly_trend - self.anomaly_history)
        self.anomaly_history  = round(self.anomaly_history, 4)

        return self._global_state()

    def _global_state(self) -> dict:
        return {
            "level_states":    [[round(float(v), 4) for v in ls] for ls in self.level_states],
            "baseline_model":  [round(float(v), 4) for v in self.baseline_model],
            "anomaly_history": self.anomaly_history,
            "drift_score":     self.drift_score,
        }

    def layer_energies(self) -> list:
        return [round(l.energy(), 4) for l in self.layers]

    def reset(self):
        for l in self.layers:
            l.reset()
        self.level_states    = [np.zeros(SSM_STATE_DIM, dtype=np.float32)
                                 for _ in range(NUM_HIERARCHY)]
        self.baseline_model  = np.zeros(SSM_STATE_DIM, dtype=np.float32)
        self.anomaly_history = 0.0
        self.drift_score     = 0.0
        self._tick           = 0


class RNNEngine:
    """
    Wires L1 SegmentSSM (per-source) + L2 HierarchicalSSM (per-source).
    Emits rnn_context with full GlobalState for the decoder.
    """
    def __init__(self, event_bus):
        self.event_bus  = event_bus
        self._l1:  dict = {}   # source → SegmentSSM
        self._l2:  dict = {}   # source → HierarchicalSSM
        self._event_count: dict = defaultdict(int)  # source → total events seen
        self._last_seg: dict = defaultdict(lambda: {
            "state_vector":  [0.0] * SSM_STATE_DIM,
            "anomaly_trend": 0.0,
            "rate_mean":     0.0,
            "error_freq":    0.0,
            "dominant_type": "NetworkPacket",
            "segment_count": 0,
        })
        self._last_global: dict = defaultdict(lambda: {
            "level_states":    [[0.0] * SSM_STATE_DIM] * NUM_HIERARCHY,
            "baseline_model":  [0.0] * SSM_STATE_DIM,
            "anomaly_history": 0.0,
            "drift_score":     0.0,
        })
        import time as _t
        self._ts = _t.time

    def _get_l1(self, source: str) -> SegmentSSM:
        if source not in self._l1:
            self._l1[source] = SegmentSSM(source)
        return self._l1[source]

    def _get_l2(self, source: str) -> HierarchicalSSM:
        if source not in self._l2:
            self._l2[source] = HierarchicalSSM(seed=hash(source) & 0xFFFF)
        return self._l2[source]

    def process_features(self, cnn_event: dict) -> dict:
        frame_id = cnn_event.get("frame_id", 0)
        source   = cnn_event.get("source", "unknown")
        ts       = self._ts()

        local_state = {
            "anomaly_score": cnn_event.get("anomaly_score", 0.0),
            "entropy":       cnn_event.get("entropy",       0.0),
            "burst_metric":  cnn_event.get("burst_metric",  0.0),
            "embedding":     cnn_event.get("feature_vector", []),
        }

        l1 = self._get_l1(source)
        l2 = self._get_l2(source)
        self._event_count[source] += 1

        # L1 step — may produce a SegmentState on flush
        seg = l1.update(local_state, cnn_event, ts)
        if seg is not None:
            self._last_seg[source] = seg
            # Promote to L2 hierarchy
            gs = l2.update(seg, seg_count=seg.get("segment_count", 0))
            self._last_global[source] = gs
            # Only emit rnn_context on segment flush — not every packet
            seg_state = seg
            gs_state  = gs
            h = l1.ssm.h
            forget_approx = round(sum(abs(v) for v in h[:16]) / (16 + 1e-9), 4)
            input_approx  = round(sum(abs(v) for v in h[16:]) / (16 + 1e-9), 4)
            output_approx = round(l1.ssm.energy() / (SSM_STATE_DIM + 1e-9), 4)
            context_event = {
                "type":            "rnn_context",
                "frame_id":        frame_id,
                "source":          source,
                "sequence_length": self._event_count[source],
                "context_vector":  seg_state["state_vector"],
                "anomaly_trend":   seg_state["anomaly_trend"],
                "rate_mean":       seg_state["rate_mean"],
                "error_freq":      seg_state["error_freq"],
                "dominant_type":   seg_state["dominant_type"],
                "segment_count":   seg_state["segment_count"],
                "global_state":    gs_state,
                "anomaly_history": gs_state["anomaly_history"],
                "drift_score":     gs_state["drift_score"],
                "layer_energies":  l2.layer_energies(),
                "gate_stats": {
                    "forget": forget_approx,
                    "input":  input_approx,
                    "output": output_approx,
                },
                "cell_energy": round(l1.ssm.energy(), 4),
                "timestamp":   datetime.now().isoformat(),
            }
            self.event_bus.emit("rnn_context", context_event)

        seg_state = self._last_seg[source]
        gs_state  = self._last_global[source]

        # Build return dict (used by decoder — always returned, not just on flush)
        h = l1.ssm.h
        forget_approx = round(sum(abs(v) for v in h[:16]) / (16 + 1e-9), 4)
        input_approx  = round(sum(abs(v) for v in h[16:]) / (16 + 1e-9), 4)
        output_approx = round(l1.ssm.energy() / (SSM_STATE_DIM + 1e-9), 4)

        return {
            "type":            "rnn_context",
            "frame_id":        frame_id,
            "source":          source,
            "sequence_length": self._event_count[source],
            "context_vector":  seg_state["state_vector"],
            "anomaly_trend":   seg_state["anomaly_trend"],
            "rate_mean":       seg_state["rate_mean"],
            "error_freq":      seg_state["error_freq"],
            "dominant_type":   seg_state["dominant_type"],
            "segment_count":   seg_state["segment_count"],
            "global_state":    gs_state,
            "anomaly_history": gs_state["anomaly_history"],
            "drift_score":     gs_state["drift_score"],
            "layer_energies":  l2.layer_energies(),
            "gate_stats": {
                "forget": forget_approx,
                "input":  input_approx,
                "output": output_approx,
            },
            "cell_energy": round(l1.ssm.energy(), 4),
            "timestamp":   datetime.now().isoformat(),
        }

    def active_sources(self) -> list:
        return list(self._l1.keys())

    def reset_source(self, source: str):
        if source in self._l1:
            self._l1[source].reset()
        if source in self._l2:
            self._l2[source].reset()
        self._last_seg.pop(source, None)
        self._last_global.pop(source, None)
