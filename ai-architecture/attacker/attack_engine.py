"""
Attack Engine — orchestrates synthetic attack generation against discovered targets.

Flow:
  1. TargetScanner discovers live IPs on local subnet
  2. MutationEngine selects a profile (fitness-weighted)
  3. AttackEngine emits network_event into the IDS pipeline event bus
  4. Pipeline processes it → decoder emits decision
  5. AttackEngine records outcome → MutationEngine updates fitness
  6. Every EVOLVE_INTERVAL attacks, MutationEngine.evolve() breeds new variants

This is a SIMULATION — packets are injected as synthetic events into the
pipeline event bus, not sent over the wire as real network packets.
"""
import threading
import time
import random
import json
import os
from datetime import datetime
from collections import defaultdict, deque

from .attack_profiles import sample_payload
from .mutator import MutationEngine
from .target_scanner import TargetScanner

EVOLVE_INTERVAL  = 30    # evolve population every N attacks
LOG_FILE         = os.path.join(os.path.dirname(__file__), "attack_log.jsonl")


class AttackEngine:
    """
    Generates attack traffic, feeds it into the event bus,
    listens for decoder decisions, and evolves profiles accordingly.
    """

    def __init__(self, event_bus, synthetic_targets: bool = False,
                 rate_limit: float = 0.4, on_status=None,
                 evolve_interval: int = 30,
                 locked_profile: str = None,
                 forced_target: str = None):
        """
        event_bus        — shared EventBus (same one as the IDS pipeline)
        synthetic_targets— if True, skip real ARP scan, use fake IPs
        rate_limit       — min seconds between attack events
        evolve_interval  — evolve population every N attacks
        locked_profile   — if set, only use this profile name
        forced_target    — if set, always attack this IP
        on_status        — optional callback(str) for status messages
        """
        self.event_bus      = event_bus
        self.rate_limit     = rate_limit
        self.on_status      = on_status or (lambda m: None)
        self.evolve_interval= evolve_interval
        self.locked_profile = locked_profile
        self.forced_target  = forced_target
        self.mutator        = MutationEngine()
        self.scanner        = TargetScanner(synthetic=synthetic_targets)
        self._running    = False
        self._duration_s = None
        self._start_time = None
        self._thread     = None
        self._lock       = threading.Lock()

        # Track in-flight attacks: frame_id → profile_name
        self._pending:   dict  = {}
        # Stats
        self._stats = {
            "total_sent":    0,
            "total_blocked": 0,
            "total_evaded":  0,
            "total_alerted": 0,
            "generation":    0,
            "active_targets": [],
            "top_profile":   "—",
            "last_decision": "—",
            "last_target":   "—",
            "last_profile":  "—",
        }
        self._decision_history: deque = deque(maxlen=200)

        # Subscribe to decoder output to capture decisions
        self.event_bus.subscribe("decoder_output", self._on_decoder_output)

    # Public API
    def start(self):
        self.scanner.start()
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.on_status("AttackEngine started")

    def stop(self):
        self._running = False
        self.scanner.stop()
        self.on_status("AttackEngine stopped")

    @property
    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def population_stats(self) -> list:
        return self.mutator.stats()

    # Main loop
    def _loop(self):
        attack_count = 0
        while self._running:
            try:
                # Profile selection — locked or evolved
                if self.locked_profile:
                    profile = next(
                        (p for p in self.mutator.population
                         if p.name == self.locked_profile),
                        self.mutator.select_profile(),
                    )
                else:
                    profile = self.mutator.select_profile()

                # Target selection — forced or scanned
                target = self.forced_target or self.scanner.random_target()

                self._fire(profile, target)
                attack_count += 1

                if attack_count % self.evolve_interval == 0:
                    self.mutator.evolve()
                    with self._lock:
                        self._stats["generation"] = self.mutator._gen
                    self.on_status(
                        f"[attacker] evolved gen={self.mutator._gen}  "
                        f"pop={len(self.mutator.population)}"
                    )

                # Vary inter-attack delay — clamp to a tighter window to avoid flooding
                delay = random.uniform(self.rate_limit, self.rate_limit * 3.0)
                time.sleep(delay)

            except Exception as e:
                self.on_status(f"[attacker] error: {e}")
                time.sleep(1.0)

    # Fire one attack event
    def _fire(self, profile, target: str):
        payload = sample_payload(profile.params)

        # Pick a spoofed source from known attacker IPs
        attacker_ips = [
            "203.0.113.10", "198.51.100.22", "185.220.101.5",
            "45.33.32.156",  "91.108.4.1",   "104.21.0.99",
        ]
        source = random.choice(attacker_ips)

        with self._lock:
            fid = self._stats["total_sent"] + 1
            self._stats["total_sent"]     = fid
            self._stats["last_target"]    = target
            self._stats["last_profile"]   = profile.name
            self._stats["active_targets"] = self.scanner.get_targets()[:6]

        # Use a unique attack tag so we can match the decoder response
        # regardless of how run.py reassigns frame_id
        atk_tag = f"atk-{fid}"
        self._pending[atk_tag] = profile.name

        # ✓ GROUND TRUTH: Include is_attack and attack_class for validator
        # This allows the validator to check if IDS decision was correct
        attack_class = self._profile_to_class(profile.name)
        
        ev = {
            "type":        "network_event",
            "frame_id":    fid,
            "source":      source,
            "destination": target,
            "event_type":  "NetworkPacket",
            "payload":     payload,
            "metadata": {
                "attacker":     True,
                "atk_tag":      atk_tag,
                "profile":      profile.name,
                "generation":   profile.generation,
                "synthetic":    True,
                "is_attack":    True,           # ✓ Ground truth: this IS an attack
                "attack_class": attack_class,   # ✓ Ground truth: attack type
            },
            "timestamp": datetime.now().isoformat(),
            "live":      False,
        }
        self.event_bus.emit("network_event", ev)

    # Capture decoder decision
    def _on_decoder_output(self, data: dict):
        decision = data.get("decision", "Ignore")

        # Match via the unique atk_tag embedded in metadata
        atk_tag = (data.get("metadata") or {}).get("atk_tag")
        if atk_tag is None:
            # ✓ FIX 5: Add logging for debugging feedback loop
            self.on_status(f"[attacker] received decision without atk_tag: {decision}")
            return   # not our frame

        profile_name = self._pending.pop(atk_tag, None)
        if profile_name is None:
            # ✓ FIX 5: Log unknown tags
            self.on_status(f"[attacker] received decision for unknown atk_tag: {atk_tag}")
            return   # already handled or unknown tag

        # ✓ FIX 5: Log feedback reception
        self.on_status(f"[attacker] feedback: {profile_name} → {decision}")

        self.mutator.record_outcome(profile_name, decision)

        # ✓ FIX 5: Log fitness update
        profile = next((p for p in self.mutator.population if p.name == profile_name), None)
        if profile:
            self.on_status(
                f"[attacker] fitness: {profile_name} = {profile.fitness:.3f} "
                f"(sent={profile.sent}, evaded={profile.evaded}, blocked={profile.blocked})"
            )

        with self._lock:
            self._stats["last_decision"] = decision
            if decision in ("Block", "Escalate"):
                self._stats["total_blocked"] += 1
            elif decision in ("Ignore", "Log"):
                self._stats["total_evaded"]  += 1
            else:
                self._stats["total_alerted"] += 1

            # ✓ FIX: Log stats update
            total = self._stats["total_sent"]
            blocked = self._stats["total_blocked"]
            evaded = self._stats["total_evaded"]
            alerted = self._stats["total_alerted"]
            if (blocked + evaded + alerted) % 10 == 0:
                self.on_status(
                    f"[attacker] stats: sent={total} blocked={blocked} evaded={evaded} alerted={alerted}"
                )

            # Top profile by evasion rate
            best = max(self.mutator.population, key=lambda p: p.fitness)
            self._stats["top_profile"] = best.name

        entry = {
            "atk_tag":       atk_tag,
            "profile":       profile_name,
            "decision":      decision,
            "confidence":    data.get("confidence", 0.0),
            "attack_class":  data.get("attack_class", "none"),
            "target":        data.get("source", ""),
            "timestamp":     data.get("timestamp", ""),
            "feature_vector":data.get("feature_vector", []),
        }
        self._decision_history.append(entry)

        # Persist to log
        try:
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    def recent_outcomes(self, n: int = 20) -> list:
        return list(self._decision_history)[-n:]

    def run_session(self, duration_s: int):
        self._duration_s = duration_s
        self._start_time = time.time()
        self.start()
        
        while self._running and (time.time() - self._start_time) < duration_s:
            time.sleep(1.0)
        self.stop()

    def _profile_to_class(self, name: str) -> str:
        """Convert profile name to attack class for ground truth."""
        name_l = name.lower()
        if "dos" in name_l or "flood" in name_l:    return "DoS/DDoS"
        if "scan" in name_l:                         return "PortScan"
        if "brute" in name_l:                        return "BruteForce/CredentialStuffing"
        if "c2" in name_l or "beacon" in name_l:     return "EncryptedC2/Exfiltration"
        if "exfil" in name_l:                        return "EncryptedC2/Exfiltration"
        if "dns" in name_l:                          return "DNSTunnel"
        if "lateral" in name_l or "smb" in name_l:  return "LateralMovement/Persistence"
        if "slow" in name_l:                         return "DoS/DDoS"
        return "UnknownHighSeverity"
