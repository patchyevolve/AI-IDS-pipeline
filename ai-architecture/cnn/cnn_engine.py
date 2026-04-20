"""
CNN Engine — L0 LocalAnalyzer (ids_level0.hpp)
Produces 64-dim embedding + rolling z-score anomaly score,
burst metric, and entropy — matching LocalState exactly.
"""
import math, random
import numpy as np
from datetime import datetime
from collections import deque, defaultdict

EMBEDDING_DIM = 64   # kEmbeddingDim
LOCAL_WINDOW  = 64   # kLocalWindow

NORM = {
    "bytes_in":  65535.0, "bytes_out": 65535.0,
    "port_src":  65535.0, "port_dst":  65535.0,
    "protocol":  255.0,   "flags":     255.0,
    "entropy":   1.0,     "rate_hz":   10000.0,
}

def _relu(x):    return max(0.0, x)
def _sigmoid(x): return 1.0 / (1.0 + math.exp(-max(-20, min(20, x))))


class CNNLayer:
    """1D conv projection with Xavier init — deterministic per seed."""
    def __init__(self, name, in_dim, out_dim, seed, activation="relu"):
        self.name, self.in_dim, self.out_dim = name, in_dim, out_dim
        self.activation_fn = activation
        rng   = random.Random(seed)
        scale = math.sqrt(2.0 / (in_dim + out_dim))
        self.W = np.array(
            [[rng.gauss(0, scale) for _ in range(in_dim)] for _ in range(out_dim)],
            dtype=np.float32,
        )
        self.b = np.array(
            [rng.gauss(0, 0.01) for _ in range(out_dim)],
            dtype=np.float32,
        )

    def forward(self, x):
        xv  = np.asarray(x[:self.in_dim], dtype=np.float32)
        out = self.W @ xv + self.b
        if self.activation_fn == "relu":
            out = np.maximum(0.0, out)
        elif self.activation_fn == "sigmoid":
            out = 1.0 / (1.0 + np.exp(-np.clip(out, -20, 20)))
        elif self.activation_fn == "softmax":
            e_x = np.exp(out - np.max(out))
            out = e_x / e_x.sum()
        activation = float(out.mean())
        return out.tolist(), round(activation, 4)

class GateCNN:
    def __init__(self):
        self.layer1 = CNNLayer("gate_fc1", 64, 16, seed=111)
        self.layer2 = CNNLayer("gate_fc2", 16, 1, seed=222, activation="sigmoid")
    def forward(self, raw_features):
        # ✓ FIX: Use feature-based heuristic on raw features (8 dims)
        # raw_features = [bytes_in, bytes_out, port_src, port_dst, protocol, flags, entropy, rate_hz]
        # All normalized to [0, 1]
        if len(raw_features) < 8:
            return 0.0
        
        bytes_in = raw_features[0]   # Normalized bytes_in
        bytes_out = raw_features[1]  # Normalized bytes_out
        entropy = raw_features[6]    # Normalized entropy
        rate_hz = raw_features[7]    # Normalized rate_hz
        
        # Attack heuristic: multiple signals indicate attack
        # ✓ TRAINING PHASE: More aggressive detection to catch all attack types
        prob = 0.0
        
        # Signal 1: High entropy (encrypted/obfuscated traffic like C2, Exfiltration, DNS Tunnel)
        if entropy > 0.60:  # Lowered from 0.70
            prob += 0.35
        
        # Signal 2: High rate (DoS/scanning/brute force)
        if rate_hz > 0.20:  # Lowered from 0.30 to catch more attacks
            prob += 0.35
        
        # Signal 3: Large payload (exfiltration/C2)
        if bytes_in > 0.40 or bytes_out > 0.40:  # Lowered from 0.50
            prob += 0.25
        
        # Signal 4: Combination of moderate entropy + rate (catches low-rate C2)
        if entropy > 0.30 and rate_hz > 0.05:  # Lowered thresholds
            prob += 0.15
        
        # Signal 5: Asymmetric traffic (exfiltration has high bytes_out)
        if bytes_out > 0.30 and bytes_in < 0.20:
            prob += 0.20
        
        return min(prob, 1.0)

class AttackCNN:
    def __init__(self):
        self.layer1 = CNNLayer("atk_fc1", 64, 32, seed=333)
        self.layer2 = CNNLayer("atk_fc2", 32, 6, seed=444, activation="softmax")
        self.classes = ["DoS/DDoS", "EncryptedC2/Exfiltration", "BruteForce/CredentialStuffing", 
                        "FileSystemAnomaly/Ransomware", "LateralMovement/Persistence", "PortScan"]
    def forward(self, emb):
        x, _ = self.layer1.forward(emb)
        out, _ = self.layer2.forward(x)
        idx = np.argmax(out)
        return self.classes[idx], out

class Autoencoder:
    def __init__(self):
        self.enc1 = CNNLayer("ae_enc", 64, 16, seed=555)
        self.dec1 = CNNLayer("ae_dec", 16, 64, seed=666, activation="none")
    def forward(self, emb):
        encoded, _ = self.enc1.forward(emb)
        decoded, _ = self.dec1.forward(encoded)
        recon_error = np.mean((np.array(emb) - np.array(decoded)) ** 2)
        return float(recon_error)



class LocalAnalyzer:
    """
    Mirrors ids_level0.hpp LocalAnalyzer.
    Per-source rolling window → z-score anomaly, burst metric, entropy.
    """
    def __init__(self, window=LOCAL_WINDOW):
        self.window = window
        self._buf   = deque(maxlen=window)
        # Welford online mean/variance for bytes_total and rate_hz
        self._n     = 0
        self._mean  = [0.0, 0.0]
        self._M2    = [0.0, 0.0]

    def process(self, payload: dict) -> dict:
        self._buf.append(payload)
        feat = [
            payload.get("bytes_in", 0) + payload.get("bytes_out", 0),
            payload.get("rate_hz", 0.0),
        ]
        # Welford update
        self._n += 1
        for i in range(2):
            delta       = feat[i] - self._mean[i]
            self._mean[i] += delta / self._n
            self._M2[i]   += delta * (feat[i] - self._mean[i])

        anomaly_score = 0.0
        if self._n >= 4:
            for i in range(2):
                var   = self._M2[i] / max(self._n - 1, 1)
                sigma = math.sqrt(max(var, 1e-6))
                z     = abs(feat[i] - self._mean[i]) / sigma
                anomaly_score = max(anomaly_score, z)
            entropy = payload.get("entropy", 0.0)
            burst   = self._burst_metric()
            anomaly_score += 0.5 if entropy > 0.85 else 0.0
            anomaly_score += 0.3 if burst   > 0.70 else 0.0
            anomaly_score  = min(anomaly_score / 5.0, 1.0)

        return {
            "anomaly_score": round(anomaly_score, 4),
            "entropy":       round(payload.get("entropy", 0.0), 4),
            "burst_metric":  round(self._burst_metric(), 4),
        }

    def _burst_metric(self) -> float:
        if len(self._buf) < 3:
            return 0.0
        rates = [p.get("rate_hz", 0.0) for p in self._buf]
        mean  = sum(rates) / len(rates)
        if mean < 1e-9:
            return 1.0
        var   = sum((r - mean) ** 2 for r in rates) / len(rates)
        return min(math.sqrt(var) / mean, 1.0)

    def reset(self):
        self._buf.clear()
        self._n = 0
        self._mean = [0.0, 0.0]
        self._M2   = [0.0, 0.0]


class CNNEngine:
    """
    L0 stage: per-source LocalAnalyzer + 3-layer CNN projection.
    Emits LocalState-equivalent: embedding(64), anomaly_score, entropy, burst_metric.
    """
    def __init__(self, event_bus):
        self.event_bus = event_bus
        self.layers = [
            CNNLayer("conv1",  8, 32, seed=42),
            CNNLayer("conv2", 32, 64, seed=137),
            CNNLayer("conv3", 64, 64, seed=999),
        ]
        self._analyzers: dict = defaultdict(LocalAnalyzer)
        self.gate_cnn = GateCNN()
        self.attack_cnn = AttackCNN()
        self.autoencoder = Autoencoder()

    def _raw_features(self, payload: dict) -> list:
        return [
            payload.get("bytes_in",  0) / NORM["bytes_in"],
            payload.get("bytes_out", 0) / NORM["bytes_out"],
            payload.get("port_src",  0) / NORM["port_src"],
            payload.get("port_dst",  0) / NORM["port_dst"],
            payload.get("protocol",  0) / NORM["protocol"],
            payload.get("flags",     0) / NORM["flags"],
            min(payload.get("entropy",  0.0), 1.0),
            min(payload.get("rate_hz",  0.0) / NORM["rate_hz"], 1.0),
        ]

    def process_event(self, network_event: dict) -> dict:
        payload    = network_event.get("payload", {})
        frame_id   = network_event.get("frame_id", 0)
        source     = network_event.get("source", "")
        event_type = network_event.get("event_type", "NetworkPacket")

        # L0 rolling anomaly
        local = self._analyzers[source].process(payload)

        raw_features = self._raw_features(payload)
        x = raw_features
        last_activation = 0.0
        for layer in self.layers:
            x, last_activation = layer.forward(x)

        # New Pipeline: Gate -> Attack / Normal (AE)
        # ✓ FIX: Pass raw features to gate heuristic, not the 64-dim embedding
        is_attack_prob = self.gate_cnn.forward(raw_features)
        atk_class, atk_probs = "none", [0.0]*6
        recon_error = 0.0
        
        if is_attack_prob > 0.5:
            atk_class, atk_probs = self.attack_cnn.forward(x)
            print(f"[CNN Engine] Gate=Attack ({is_attack_prob:.2f}) -> AttackCNN: {atk_class}")
        else:
            recon_error = self.autoencoder.forward(x)
            print(f"[CNN Engine] Gate=Normal ({is_attack_prob:.2f}) -> Autoencoder err: {recon_error:.4f}")

        feature_event = {
            "type":           "cnn_features",
            "frame_id":       frame_id,
            "source":         source,
            "event_type":     event_type,
            "feature_vector": [round(v, 6) for v in x],   # 64-dim embedding
            # New outputs
            "is_attack_prob": float(is_attack_prob),
            "atk_class":      atk_class,
            "atk_probs":      atk_probs,
            "recon_error":    recon_error,
            # LocalState fields
            "anomaly_score":  local["anomaly_score"],
            "entropy":        local["entropy"],
            "burst_metric":   local["burst_metric"],
            # raw payload fields for decoder
            "rate_hz":        payload.get("rate_hz",  0.0),
            "bytes_in":       payload.get("bytes_in", 0),
            "port_dst":       payload.get("port_dst", 0),
            "protocol":       payload.get("protocol", 0),
            "flags":          payload.get("flags",    0),
            "activation":     last_activation,
            "timestamp":      datetime.now().isoformat(),
        }
        self.event_bus.emit("cnn_features", feature_event)
        return feature_event

    def process_frame(self, frame_id: int) -> dict:
        """Synthetic shim."""
        fake = {
            "bytes_in":  random.randint(60, 1500),
            "bytes_out": random.randint(0, 500),
            "port_src":  random.randint(1024, 65535),
            "port_dst":  random.choice([80, 443, 22, 53, 8080]),
            "protocol":  random.choice([6, 17]),
            "flags":     random.choice([0x02, 0x18, 0x10]),
            "entropy":   round(random.uniform(0.1, 0.95), 4),
            "rate_hz":   round(random.uniform(10, 5000), 2),
        }
        return self.process_event({
            "payload":    fake,
            "frame_id":   frame_id,
            "source":     f"192.168.1.{random.randint(1, 50)}",
            "event_type": "NetworkPacket",
        })
