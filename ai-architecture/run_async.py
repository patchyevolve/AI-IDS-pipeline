#!/usr/bin/env python3
"""
Optimized Async Pipeline Runner
Uses multi-threaded workers to maximize throughput
"""

import sys
import os
import time
import threading
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from event_bus import EventBus
from cnn.cnn_engine import CNNEngine
from rnn.rnn_engine import RNNEngine
from decoder.decoder_engine import HybridDecoder
from decoder.mutation_predictor import MutationAwareDecoder
from database.db_engine import DatabaseEngine
from network.ids_bridge import IDSBridge
from network.firewall_enforcer import FirewallEnforcer
from validation.training_validator import TrainingValidator
from async_pipeline import AsyncPipeline


def main():
    args = sys.argv[1:]
    force_synthetic = "--synthetic" in args
    enable_attacker = "--attack" in args
    enable_validation = "--validate" in args
    use_async = "--async" in args or True  # Default to async
    
    print("[*] AI-IDS Async Pipeline")
    print(f"[*] Synthetic Mode: {force_synthetic}")
    print(f"[*] Attack Engine: {enable_attacker}")
    print(f"[*] Validation: {enable_validation}")
    print(f"[*] Async Pipeline: {use_async}")
    
    # Initialize components
    bus = EventBus()
    cnn = CNNEngine(bus)
    rnn = RNNEngine(bus)
    db = DatabaseEngine(bus)
    base_decoder = HybridDecoder(bus)
    decoder = MutationAwareDecoder(base_decoder, db)
    
    # Network bridge
    bridge = IDSBridge(
        event_bus=bus,
        interface="",
        scapy_name="",
        bpf_filter="",
        mode="synthetic" if force_synthetic else "live",
        on_status=lambda msg: print(f"[bridge] {msg}"),
    )
    
    # Validator
    validator = None
    if enable_validation or enable_attacker:
        validator = TrainingValidator(bus, db=db, output_dir="validation")
        print("[*] Validation enabled")
    
    # Firewall
    firewall = FirewallEnforcer()
    print(f"[*] Firewall enforcer initialized ({firewall.platform})")
    
    # Start bridge
    bridge.start()
    
    # Create async pipeline
    if use_async:
        print("[*] Using async pipeline with worker threads")
        async_pipeline = AsyncPipeline(
            num_cnn_workers=2,
            num_rnn_workers=2,
            num_decoder_workers=2,
            num_validator_workers=1,
            num_db_workers=1,
        )
        async_pipeline.start(cnn, rnn, decoder, db, validator, firewall)
        
        # Subscribe to network events and submit to async pipeline
        def on_network_event(ev):
            async_pipeline.submit_packet(ev)
        
        bus.subscribe("network_event", on_network_event)
    else:
        print("[*] Using synchronous pipeline")
        # Original synchronous pipeline
        def on_network_event(ev):
            fid = ev.get("frame_id", 0)
            meta = ev.get("metadata", {})
            
            cnn_out = cnn.process_event(ev)
            rnn_out = rnn.process_features(cnn_out)
            db_mem = db.retrieve_memory(
                embedding=cnn_out["feature_vector"],
                source=ev.get("source", ""),
                destination=ev.get("destination", ""),
                port_dst=cnn_out.get("port_dst", 0),
                frame_id=fid,
            )
            
            if isinstance(decoder, MutationAwareDecoder):
                dec_out = decoder.decode_with_mutation_awareness(
                    cnn_out, rnn_out, db_mem["retrieved"], metadata=meta
                )
            else:
                dec_out = decoder.decode(cnn_out, rnn_out, db_mem["retrieved"], metadata=meta)
            
            db.log_prediction(dec_out)
            
            if validator and meta.get("is_attack") is not None:
                validator.validate_and_correct({
                    "is_attack": meta.get("is_attack", False),
                    "decision": dec_out["decision"],
                    "attack_class": meta.get("attack_class", "unknown"),
                    "confidence": dec_out["confidence"],
                    "feature_vector": cnn_out["feature_vector"],
                    "source": ev.get("source", ""),
                    "destination": ev.get("destination", ""),
                    "port_dst": cnn_out.get("port_dst", 0),
                    "protocol": cnn_out.get("protocol", 0),
                    "flags": cnn_out.get("flags", 0),
                    "rate_hz": cnn_out.get("rate_hz", 0.0),
                    "timestamp": dec_out.get("timestamp", ""),
                })
            
            if firewall and dec_out["decision"] in ("Block", "Escalate"):
                source_ip = dec_out.get("source", "")
                if source_ip:
                    firewall.block_ip(source_ip)
        
        bus.subscribe("network_event", on_network_event)
    
    # Optional: Start attacker
    if enable_attacker:
        from attacker.attack_engine import AttackEngine
        attacker = AttackEngine(
            event_bus=bus,
            synthetic_targets=force_synthetic,
            rate_limit=0.1,  # Reduced rate limit for async pipeline
            on_status=lambda m: print(f"[attacker] {m}"),
        )
        attacker.start()
    
    # Optional: Start remote listeners
    from network.remote_attack_listener import RemoteAttackListener
    from network.decision_feedback_server import DecisionFeedbackServer
    
    remote_listener = RemoteAttackListener(bus, on_status=lambda m: print(m))
    remote_listener.start()
    
    feedback_server = DecisionFeedbackServer(bus, on_status=lambda m: print(m))
    feedback_server.start()
    
    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        if use_async:
            async_pipeline.stop()
        bridge.stop()
        if validator:
            validator.save_report()


if __name__ == "__main__":
    main()
