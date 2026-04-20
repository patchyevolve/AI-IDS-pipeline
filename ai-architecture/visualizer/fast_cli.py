import sys
import os
import time
import threading
from collections import deque

# Standard ANSI colors
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_CYAN = "\033[36m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_RED = "\033[31m"
C_MAGENTA = "\033[35m"
C_DIM = "\033[2m"

def clear_screen():
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()

class FastCLI:
    """
    A high-performance 'htop'-style Terminal Dashboard.
    Runs completely decoupled from the AI pipeline thread, causing zero latency.
    """
    def __init__(self, state, lock):
        self.state = state
        self.lock = lock
        self.running = True
        self.recent_logs = deque(maxlen=10)
        self.start_time = time.time()
        self.last_pkts = 0
        self.pkts_per_sec = 0

    def start(self):
        threading.Thread(target=self._render_loop, daemon=True).start()

    def stop(self):
        self.running = False
        print(C_RESET)

    def _render_loop(self):
        while self.running:
            with self.lock:
                frames = self.state.get("frame_id", 0)
                pkts = self.state.get("pkts", 0)
                alerts = self.state.get("alerts", 0)
                blocks = self.state.get("blocks", 0)
                db_size = self.state.get("db_size", 0)
                db_hits = self.state.get("decoder_db_hits", 0)
                db_active = "ACTIVE" if self.state.get("decoder_mem") else "NONE"
                classes = dict(self.state.get("cls", {}))
                mode = "C++ Native Pipeline" if "ids_pipeline" in sys.modules else "Python AI Pipeline"
                q_depth = self.state.get("q_depth", 0)
            
            # Calculate Packets Per Second
            now = time.time()
            self.pkts_per_sec = pkts - self.last_pkts
            self.last_pkts = pkts

            # Draw UI
            clear_screen()
            print(f"{C_BOLD}{C_CYAN}=== AI-IDS HIGH-PERFORMANCE CLI DASHBOARD ==={C_RESET}")
            print(f"Engine: {C_GREEN}{mode}{C_RESET} | Uptime: {int(now - self.start_time)}s | Queue Depth: {q_depth}")
            print("-" * 60)
            print(f"{C_BOLD}TRAFFIC STATS:{C_RESET}")
            print(f"  Total Packets: {pkts:,}   |   Throughput: {C_YELLOW}{self.pkts_per_sec:,} pkts/sec{C_RESET}")
            print(f"  Frames Analyzed: {frames:,}")
            print("-" * 60)
            print(f"{C_BOLD}SECURITY STATS:{C_RESET}")
            print(f"  Alerts Triggered: {C_YELLOW}{alerts:,}{C_RESET}")
            print(f"  Attacks Blocked:  {C_RED}{blocks:,}{C_RESET}")
            
            print("-" * 60)
            print(f"{C_BOLD}DATABASE & META-LEARNING:{C_RESET}")
            print(f"  Memory Status:    {C_GREEN if 'ACTIVE' in db_active else C_DIM}{db_active}{C_RESET}")
            print(f"  Total Signatures: {C_MAGENTA}{db_size:,} stored{C_RESET}")
            print(f"  Live DB Hits:     {C_CYAN}{db_hits:,} recent retrievals{C_RESET}")
            
            print("-" * 60)
            print(f"{C_BOLD}TOP DETECTED THREAT CLASSES:{C_RESET}")
            if not classes:
                print(f"  {C_DIM}(No attacks detected yet){C_RESET}")
            for cls, count in sorted(classes.items(), key=lambda x: -x[1])[:5]:
                print(f"  - {C_RED}{cls:<30}{C_RESET} : {count}")
            
            print("-" * 60)
            print(f"{C_BOLD}RECENT EVENTS:{C_RESET}")
            with self.lock:
                logs = list(self.state.get("flow_log", []))[:10]  # flow_log is a deque where left is newest
                if not logs:
                    print(f"  {C_DIM}Waiting for events...{C_RESET}")
                for log in reversed(logs):  # print oldest to newest top-down
                    tag = log.get("tag", "")
                    msg = log.get("msg", "")
                    color = C_RED if "BLO" in tag else (C_YELLOW if "ALE" in tag else C_DIM)
                    print(f"  {color}{tag} {msg}{C_RESET}")

            print(f"\n{C_DIM}Press Ctrl+C to exit...{C_RESET}")
            
            # Sleep 1 second so the UI updates at 1Hz (causing zero CPU drag)
            time.sleep(1.0)

def main(bus=None, cnn=None, rnn=None, decoder=None, db=None, bridge=None, attacker=None):
    from visualizer.dashboard import (
        state, lock,
        on_cnn_layer, on_cnn_features, on_rnn_context,
        on_decoder_output, on_db_logged, on_db_retrieved, on_ids_export
    )

    if bus:
        bus.subscribe("cnn_layer_output", on_cnn_layer)
        bus.subscribe("cnn_features",     on_cnn_features)
        bus.subscribe("rnn_context",      on_rnn_context)
        bus.subscribe("decoder_output",   on_decoder_output)
        bus.subscribe("db_logged",        on_db_logged)
        bus.subscribe("db_retrieved",     on_db_retrieved)
        bus.subscribe("ids_export",       on_ids_export)

    def _poll():
        while state.get("running", True):
            if bridge:
                st = bridge.stats
                with lock:
                    state["ids_connected"] = bridge.connected
                    state["ids_interface"] = st.get("interface", "—")
                    state["ids_pkts"]      = st.get("packets_received", 0)
            if bus:
                with lock:
                    state["q_depth"] = bus.queue_depth
            time.sleep(0.5)

    threading.Thread(target=_poll, daemon=True).start()

    cli = FastCLI(state, lock)
    cli.start()
    
    # Only sleep in a loop if we are NOT running an attacker session.
    # When attacker is running, run.py manages the main thread.
    if attacker is None:
        try:
            while state.get("running", True):
                time.sleep(1)
        except KeyboardInterrupt:
            state["running"] = False
            cli.stop()
    else:
        # If attacker is present, we must still loop so the CLI stays open 
        # until the attacker is completely done, but we check attacker's status.
        try:
            while getattr(attacker, '_running', True) and state.get("running", True):
                time.sleep(1)
        except KeyboardInterrupt:
            state["running"] = False
        cli.stop()
    return
