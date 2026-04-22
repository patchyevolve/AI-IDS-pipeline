"""
Asynchronous Pipeline Optimization
Decouples packet processing stages to maximize throughput
"""

import threading
import queue
import time
from collections import deque
from datetime import datetime


class AsyncPipeline:
    """
    Multi-stage async pipeline with worker threads
    
    Flow:
    Network → Queue1 → CNN Workers → Queue2 → RNN Workers → Queue3 → 
    Decoder Workers → Queue4 → Validator Workers → Queue5 → DB Workers
    
    Each stage runs in parallel, maximizing CPU utilization
    """
    
    def __init__(self, num_cnn_workers=2, num_rnn_workers=2, num_decoder_workers=2, 
                 num_validator_workers=1, num_db_workers=1):
        """
        Initialize async pipeline with configurable worker counts
        
        Args:
            num_cnn_workers: CNN processing threads
            num_rnn_workers: RNN processing threads
            num_decoder_workers: Decoder processing threads
            num_validator_workers: Validator threads
            num_db_workers: Database threads
        """
        self.num_cnn_workers = num_cnn_workers
        self.num_rnn_workers = num_rnn_workers
        self.num_decoder_workers = num_decoder_workers
        self.num_validator_workers = num_validator_workers
        self.num_db_workers = num_db_workers
        
        # Queues between stages
        self.network_queue = queue.Queue(maxsize=1000)
        self.cnn_queue = queue.Queue(maxsize=1000)
        self.rnn_queue = queue.Queue(maxsize=1000)
        self.decoder_queue = queue.Queue(maxsize=1000)
        self.validator_queue = queue.Queue(maxsize=1000)
        self.db_queue = queue.Queue(maxsize=1000)
        
        # Metrics
        self.metrics = {
            "network_received": 0,
            "cnn_processed": 0,
            "rnn_processed": 0,
            "decoder_processed": 0,
            "validator_processed": 0,
            "db_processed": 0,
            "queue_depths": {},
            "stage_latencies": {},
        }
        self.metrics_lock = threading.Lock()
        
        # Worker threads
        self.workers = []
        self.running = False
        
    def start(self, cnn, rnn, decoder, db, validator=None, firewall=None):
        """Start all worker threads"""
        self.running = True
        self.cnn = cnn
        self.rnn = rnn
        self.decoder = decoder
        self.db = db
        self.validator = validator
        self.firewall = firewall
        
        # Start CNN workers
        for i in range(self.num_cnn_workers):
            t = threading.Thread(target=self._cnn_worker, name=f"cnn-{i}", daemon=True)
            t.start()
            self.workers.append(t)
        
        # Start RNN workers
        for i in range(self.num_rnn_workers):
            t = threading.Thread(target=self._rnn_worker, name=f"rnn-{i}", daemon=True)
            t.start()
            self.workers.append(t)
        
        # Start Decoder workers
        for i in range(self.num_decoder_workers):
            t = threading.Thread(target=self._decoder_worker, name=f"decoder-{i}", daemon=True)
            t.start()
            self.workers.append(t)
        
        # Start Validator workers
        for i in range(self.num_validator_workers):
            t = threading.Thread(target=self._validator_worker, name=f"validator-{i}", daemon=True)
            t.start()
            self.workers.append(t)
        
        # Start DB workers
        for i in range(self.num_db_workers):
            t = threading.Thread(target=self._db_worker, name=f"db-{i}", daemon=True)
            t.start()
            self.workers.append(t)
        
        # Start metrics reporter
        t = threading.Thread(target=self._metrics_reporter, name="metrics", daemon=True)
        t.start()
        self.workers.append(t)
        
        print(f"[AsyncPipeline] Started with {len(self.workers)} workers")
    
    def stop(self):
        """Stop all workers"""
        self.running = False
        for t in self.workers:
            t.join(timeout=1.0)
    
    def submit_packet(self, event):
        """Submit packet to pipeline"""
        try:
            self.network_queue.put_nowait(event)
            with self.metrics_lock:
                self.metrics["network_received"] += 1
        except queue.Full:
            print("[AsyncPipeline] Network queue full, dropping packet")
    
    def _cnn_worker(self):
        """CNN processing worker"""
        while self.running:
            try:
                event = self.network_queue.get(timeout=1.0)
                start = time.time()
                
                # Process CNN
                cnn_out = self.cnn.process_event(event)
                cnn_out["_network_event"] = event
                
                # Send to RNN queue
                self.cnn_queue.put(cnn_out)
                
                with self.metrics_lock:
                    self.metrics["cnn_processed"] += 1
                    if "cnn_latency" not in self.metrics["stage_latencies"]:
                        self.metrics["stage_latencies"]["cnn_latency"] = deque(maxlen=100)
                    self.metrics["stage_latencies"]["cnn_latency"].append(time.time() - start)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[cnn-worker] Error: {e}")
    
    def _rnn_worker(self):
        """RNN processing worker"""
        while self.running:
            try:
                cnn_out = self.cnn_queue.get(timeout=1.0)
                start = time.time()
                
                # Process RNN
                rnn_out = self.rnn.process_features(cnn_out)
                rnn_out["_cnn_out"] = cnn_out
                
                # Send to Decoder queue
                self.rnn_queue.put(rnn_out)
                
                with self.metrics_lock:
                    self.metrics["rnn_processed"] += 1
                    if "rnn_latency" not in self.metrics["stage_latencies"]:
                        self.metrics["stage_latencies"]["rnn_latency"] = deque(maxlen=100)
                    self.metrics["stage_latencies"]["rnn_latency"].append(time.time() - start)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[rnn-worker] Error: {e}")
    
    def _decoder_worker(self):
        """Decoder processing worker"""
        while self.running:
            try:
                rnn_out = self.rnn_queue.get(timeout=1.0)
                start = time.time()
                
                cnn_out = rnn_out["_cnn_out"]
                event = cnn_out["_network_event"]
                
                try:
                    # Database retrieval (can be slow, but now parallel)
                    db_mem = self.db.retrieve_memory(
                        embedding=cnn_out["feature_vector"],
                        source=event.get("source", ""),
                        destination=event.get("destination", ""),
                        port_dst=cnn_out.get("port_dst", 0),
                        frame_id=event.get("frame_id", 0),
                    )
                except Exception as db_err:
                    print(f"[decoder-worker] DB retrieval error: {db_err}")
                    db_mem = {"retrieved": []}
                
                try:
                    # Decode
                    from decoder.mutation_predictor import MutationAwareDecoder
                    if isinstance(self.decoder, MutationAwareDecoder):
                        dec_out = self.decoder.decode_with_mutation_awareness(
                            cnn_out, rnn_out, db_mem["retrieved"], 
                            metadata=event.get("metadata", {})
                        )
                    else:
                        dec_out = self.decoder.decode(
                            cnn_out, rnn_out, db_mem["retrieved"],
                            metadata=event.get("metadata", {})
                        )
                except Exception as decode_err:
                    print(f"[decoder-worker] Decode error: {decode_err}")
                    # Create minimal valid output on error
                    dec_out = {
                        "decision": "Log",
                        "confidence": 0.0,
                        "attack_class": "unknown",
                        "source": event.get("source", ""),
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "explanation": f"Decode error: {decode_err}",
                    }
                
                # Attach metadata for next stages
                dec_out["_event"] = event
                dec_out["_cnn_out"] = cnn_out
                
                # Send to Validator queue
                self.decoder_queue.put(dec_out)
                
                with self.metrics_lock:
                    self.metrics["decoder_processed"] += 1
                    if "decoder_latency" not in self.metrics["stage_latencies"]:
                        self.metrics["stage_latencies"]["decoder_latency"] = deque(maxlen=100)
                    self.metrics["stage_latencies"]["decoder_latency"].append(time.time() - start)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[decoder-worker] Unexpected error: {e}")
    
    def _validator_worker(self):
        """Validator processing worker"""
        while self.running:
            try:
                dec_out = self.decoder_queue.get(timeout=1.0)
                start = time.time()
                
                event = dec_out["_event"]
                cnn_out = dec_out["_cnn_out"]
                
                # Validate
                if self.validator and event.get("metadata", {}).get("is_attack") is not None:
                    self.validator.validate_and_correct({
                        "is_attack": event.get("metadata", {}).get("is_attack", False),
                        "decision": dec_out["decision"],
                        "attack_class": event.get("metadata", {}).get("attack_class", "unknown"),
                        "confidence": dec_out["confidence"],
                        "feature_vector": cnn_out["feature_vector"],
                        "source": event.get("source", ""),
                        "destination": event.get("destination", ""),
                        "port_dst": cnn_out.get("port_dst", 0),
                        "protocol": cnn_out.get("protocol", 0),
                        "flags": cnn_out.get("flags", 0),
                        "rate_hz": cnn_out.get("rate_hz", 0.0),
                        "timestamp": dec_out.get("timestamp", ""),
                    })
                
                # Send to DB queue
                self.validator_queue.put(dec_out)
                
                with self.metrics_lock:
                    self.metrics["validator_processed"] += 1
                    if "validator_latency" not in self.metrics["stage_latencies"]:
                        self.metrics["stage_latencies"]["validator_latency"] = deque(maxlen=100)
                    self.metrics["stage_latencies"]["validator_latency"].append(time.time() - start)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[validator-worker] Error: {e}")
    
    def _db_worker(self):
        """Database logging worker"""
        while self.running:
            try:
                dec_out = self.validator_queue.get(timeout=1.0)
                start = time.time()
                
                # Log to database
                self.db.log_prediction(dec_out)
                
                # Firewall enforcement
                if self.firewall and dec_out["decision"] in ("Block", "Escalate"):
                    source_ip = dec_out.get("source", "")
                    if source_ip:
                        self.firewall.block_ip(source_ip)
                
                with self.metrics_lock:
                    self.metrics["db_processed"] += 1
                    if "db_latency" not in self.metrics["stage_latencies"]:
                        self.metrics["stage_latencies"]["db_latency"] = deque(maxlen=100)
                    self.metrics["stage_latencies"]["db_latency"].append(time.time() - start)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[db-worker] Error: {e}")
    
    def _metrics_reporter(self):
        """Report metrics every 10 seconds"""
        while self.running:
            time.sleep(10.0)
            with self.metrics_lock:
                print("\n" + "="*70)
                print("ASYNC PIPELINE METRICS")
                print("="*70)
                print(f"Network Received:    {self.metrics['network_received']:8}")
                print(f"CNN Processed:       {self.metrics['cnn_processed']:8}")
                print(f"RNN Processed:       {self.metrics['rnn_processed']:8}")
                print(f"Decoder Processed:   {self.metrics['decoder_processed']:8}")
                print(f"Validator Processed: {self.metrics['validator_processed']:8}")
                print(f"DB Processed:        {self.metrics['db_processed']:8}")
                
                print("\nQueue Depths:")
                print(f"  Network Queue:   {self.network_queue.qsize():4}")
                print(f"  CNN Queue:       {self.cnn_queue.qsize():4}")
                print(f"  RNN Queue:       {self.rnn_queue.qsize():4}")
                print(f"  Decoder Queue:   {self.decoder_queue.qsize():4}")
                print(f"  Validator Queue: {self.validator_queue.qsize():4}")
                print(f"  DB Queue:        {self.db_queue.qsize():4}")
                
                print("\nAverage Latencies (ms):")
                for stage, latencies in self.metrics["stage_latencies"].items():
                    if latencies:
                        avg = sum(latencies) / len(latencies) * 1000
                        print(f"  {stage:20} {avg:8.2f}")
                
                # Calculate throughput
                total_processed = self.metrics["db_processed"]
                if total_processed > 0:
                    print(f"\nThroughput: {total_processed} packets processed")
                    print(f"Backlog: {self.network_queue.qsize()} packets waiting")
                print("="*70 + "\n")
    
    def get_metrics(self):
        """Get current metrics"""
        with self.metrics_lock:
            return dict(self.metrics)
