"""
Shared dashboard state — imported by both dashboard.py and dashboard_tk.py
so neither needs to import the other.
"""
import threading
from collections import deque

MAX_LOG      = 40
MAX_WAVE     = 80
MAX_ACT_HIST = 80
MAX_TIMELINE = 120   # time-series buckets

state = {
    "frame_id":         0,
    "cnn_layer":        "—",
    "cnn_activation":   0.0,
    "cnn_shape":        "—",
    "cnn_act_history":  [],
    "rnn_seq_len":      0,
    "rnn_forget":       0.0,
    "rnn_input":        0.0,
    "rnn_output_g":     0.0,
    "rnn_wave":         [],
    "decoder_pred":     "—",
    "decoder_conf":     0.0,
    "decoder_attn":     0.0,
    "decoder_mem":      False,
    "decoder_probs":    {},
    "decoder_decision": "Ignore",
    "decoder_source":   "—",
    "decoder_db_hits":  0,
    "db_size":          0,
    "db_retrieved":     0,
    "db_top_label":     "—",
    "db_avg_conf":      0.0,
    "db_history":       [],
    "db_threat_count":  0,
    "db_sigs_exported": 0,
    "db_class_counts":  {},
    "ids_connected":    False,
    "ids_interface":    "synthetic",
    "decoder_db_hits":  0,
    "decoder_mem":      False,
    "ids_pkts":         0,
    "ids_bytes":        0,
    "ids_alerts_sent":  0,
    "ids_last_src":     "—",
    "ids_last_dst":     "—",
    "ids_last_proto":   "—",
    "ids_last_entropy": 0.0,
    "flow_log":         [],
    "running":          True,
    # Attacker state
    "atk_enabled":      False,
    "atk_total_sent":   0,
    "atk_blocked":      0,
    "atk_evaded":       0,
    "atk_generation":   0,
    "atk_top_profile":  "—",
    "atk_last_decision":"—",
    "atk_last_target":  "—",
    "atk_last_profile": "—",
    "atk_targets":      [],
    "atk_population":   [],

    # ── SOC dashboard extras ──────────────────────────────────
    # timeline: list of {t, ignore, log, alert, block, escalate, total}
    "timeline":         [],
    # per-decision totals (cumulative)
    "total_ignore":     0,
    "total_log":        0,
    "total_alert":      0,
    "total_block":      0,
    "total_escalate":   0,
    # top sources table: list of {src, count, decision, class}
    "top_sources":      [],
    # top attack classes: dict {class: count}
    "class_counts":     {},
    # protocol distribution: dict {proto: count}
    "proto_counts":     {},
    # alert terms table: list of {term, count}
    "alert_terms":      [],
    # confidence trend (last N values)
    "conf_trend":       [],
    # live in-progress timeline bucket (always current)
    "timeline_live":    {},
    # pipeline health
    "bus_queue_depth":  0,
}

lock = threading.RLock()

# Internal accumulators (not exposed directly)
_src_counts:   dict = {}
_class_counts: dict = {}
_proto_counts: dict = {}
_alert_terms:  dict = {}
_decision_totals = {"Ignore": 0, "Log": 0, "Alert": 0, "Block": 0, "Escalate": 0}

# Current timeline bucket
_tl_bucket = {"t": "", "ignore": 0, "log": 0, "alert": 0, "block": 0, "escalate": 0, "total": 0}
_tl_last_t = ""


def add_log(tag, msg, color):
    with lock:
        state["flow_log"].append({"tag": tag, "msg": msg, "color": color})
        if len(state["flow_log"]) > MAX_LOG:
            state["flow_log"].pop(0)


def record_decision(decision: str, source: str, attack_class: str,
                    protocol: str, confidence: float, timestamp: str):
    """
    Called by EventBus worker thread. Does all aggregation work WITHOUT
    holding the main lock, then does a single atomic swap at the end.
    """
    global _tl_last_t, _tl_bucket

    # All aggregation work done outside the lock
    key = decision if decision in _decision_totals else "Ignore"
    _decision_totals[key] += 1

    if source and source not in ("—", ""):
        _src_counts[source] = _src_counts.get(source, 0) + 1

    if attack_class and attack_class not in ("—", "none", ""):
        _class_counts[attack_class] = _class_counts.get(attack_class, 0) + 1

    if protocol and protocol not in ("—", ""):
        _proto_counts[protocol] = _proto_counts.get(protocol, 0) + 1

    if decision in ("Alert", "Block", "Escalate") and attack_class not in ("none", "—", ""):
        _alert_terms[attack_class] = _alert_terms.get(attack_class, 0) + 1

    # Timeline bucket
    if len(timestamp) >= 8:
        try:
            h, m, s = timestamp[:8].split(":")
            s5 = (int(s) // 5) * 5
            t_bucket = f"{h}:{m}:{s5:02d}"
        except Exception:
            t_bucket = timestamp[:5]
    else:
        t_bucket = timestamp[:5] if len(timestamp) >= 5 else timestamp

    new_tl_entry = None
    if t_bucket != _tl_last_t:
        if _tl_last_t:
            new_tl_entry = dict(_tl_bucket)
        _tl_bucket = {"t": t_bucket, "ignore": 0, "log": 0,
                      "alert": 0, "block": 0, "escalate": 0, "total": 0}
        _tl_last_t = t_bucket
    _tl_bucket["total"] += 1
    _tl_bucket[key.lower()] += 1

    # Pre-compute sorted lists outside lock
    top_src = sorted(_src_counts.items(), key=lambda x: -x[1])[:10]
    top_src_list = [
        {"src": s, "count": c, "decision": decision, "class": attack_class}
        for s, c in top_src
    ]
    alert_list = sorted(
        [{"term": k, "count": v} for k, v in _alert_terms.items()],
        key=lambda x: -x["count"]
    )[:12] if _alert_terms else []

    # Single short critical section — just assignments, no computation
    with lock:
        state["total_ignore"]   = _decision_totals["Ignore"]
        state["total_log"]      = _decision_totals["Log"]
        state["total_alert"]    = _decision_totals["Alert"]
        state["total_block"]    = _decision_totals["Block"]
        state["total_escalate"] = _decision_totals["Escalate"]
        if source and source not in ("—", ""):
            state["top_sources"] = top_src_list
        if attack_class and attack_class not in ("—", "none", ""):
            state["class_counts"] = dict(_class_counts)
        if protocol and protocol not in ("—", ""):
            state["proto_counts"] = dict(_proto_counts)
        if decision in ("Alert", "Block", "Escalate") and attack_class not in ("none", "—", ""):
            state["alert_terms"] = alert_list
        state["conf_trend"].append(round(confidence, 4))
        if len(state["conf_trend"]) > MAX_ACT_HIST:
            state["conf_trend"].pop(0)
        if new_tl_entry:
            state["timeline"].append(new_tl_entry)
            if len(state["timeline"]) > MAX_TIMELINE:
                state["timeline"].pop(0)
        state["timeline_live"] = dict(_tl_bucket)
