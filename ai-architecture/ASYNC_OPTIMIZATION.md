# Async Pipeline Optimization

## Problem

The original synchronous pipeline processes packets sequentially:
```
Packet 1: CNN → RNN → Decoder → Validator → DB (blocks until complete)
Packet 2: CNN → RNN → Decoder → Validator → DB (waits for Packet 1)
Packet 3: CNN → RNN → Decoder → Validator → DB (waits for Packet 2)
```

**Result**: Attacker sends 22,000 packets but IDS only processes 3-4K (5-18% throughput)

## Solution: Async Multi-Worker Pipeline

Each stage runs in parallel with dedicated worker threads:

```
Network Queue
    ↓
[CNN Worker 1] [CNN Worker 2]  (2 threads)
    ↓
CNN Queue
    ↓
[RNN Worker 1] [RNN Worker 2]  (2 threads)
    ↓
RNN Queue
    ↓
[Decoder Worker 1] [Decoder Worker 2]  (2 threads)
    ↓
Decoder Queue
    ↓
[Validator Worker]  (1 thread)
    ↓
Validator Queue
    ↓
[DB Worker]  (1 thread)
```

## Performance Improvement

### Synchronous Pipeline
- **Throughput**: 100-500 packets/sec
- **Latency per packet**: 2-10ms
- **Bottleneck**: Sequential processing
- **CPU Utilization**: ~25% (single core)

### Async Pipeline (Expected)
- **Throughput**: 5,000-10,000 packets/sec (10-100x improvement)
- **Latency per packet**: 2-10ms (same, but parallel)
- **Bottleneck**: Database I/O
- **CPU Utilization**: ~80-90% (multi-core)

## Usage

### Run with Async Pipeline (Default)
```bash
cd ai-architecture
python run_async.py --synthetic --attack --validate
```

### Run with Synchronous Pipeline (Original)
```bash
cd ai-architecture
python run_async.py --synthetic --attack --validate --no-async
```

## Configuration

Adjust worker counts in `run_async.py`:

```python
async_pipeline = AsyncPipeline(
    num_cnn_workers=2,      # Increase for more CNN parallelism
    num_rnn_workers=2,      # Increase for more RNN parallelism
    num_decoder_workers=2,  # Increase for more decoder parallelism
    num_validator_workers=1,# Usually 1 (validation is fast)
    num_db_workers=1,       # Usually 1 (DB is bottleneck)
)
```

### Tuning Guide

**For High Throughput (22K+ packets/sec):**
```python
AsyncPipeline(
    num_cnn_workers=4,
    num_rnn_workers=4,
    num_decoder_workers=4,
    num_validator_workers=2,
    num_db_workers=2,
)
```

**For Balanced Performance:**
```python
AsyncPipeline(
    num_cnn_workers=2,
    num_rnn_workers=2,
    num_decoder_workers=2,
    num_validator_workers=1,
    num_db_workers=1,
)
```

**For Low Latency (real-time):**
```python
AsyncPipeline(
    num_cnn_workers=1,
    num_rnn_workers=1,
    num_decoder_workers=1,
    num_validator_workers=1,
    num_db_workers=1,
)
```

## Metrics

The async pipeline reports metrics every 10 seconds:

```
======================================================================
ASYNC PIPELINE METRICS
======================================================================
Network Received:        22000
CNN Processed:           18500
RNN Processed:           18200
Decoder Processed:       17800
Validator Processed:     17500
DB Processed:            17200

Queue Depths:
  Network Queue:           500
  CNN Queue:               200
  RNN Queue:               150
  Decoder Queue:           100
  Validator Queue:          50
  DB Queue:                 20

Average Latencies (ms):
  cnn_latency              2.50
  rnn_latency              1.80
  decoder_latency          3.20
  validator_latency        0.50
  db_latency               1.50

Throughput: 17200 packets processed
Backlog: 500 packets waiting
======================================================================
```

## Queue Depth Analysis

- **Network Queue**: Should be < 1000 (max size)
- **CNN Queue**: Should be < 500 (CNN is fast)
- **RNN Queue**: Should be < 300 (RNN is fast)
- **Decoder Queue**: Should be < 200 (decoder is slower)
- **Validator Queue**: Should be < 100 (validator is fast)
- **DB Queue**: Should be < 50 (DB is bottleneck)

If queues are growing, increase workers for that stage.

## Bottleneck Analysis

### If CNN Queue is Growing
- Increase `num_cnn_workers`
- CNN processing is slow (check GPU/CPU)

### If Decoder Queue is Growing
- Increase `num_decoder_workers`
- Decoder is slow (check database retrieval)

### If DB Queue is Growing
- Increase `num_db_workers`
- Database I/O is slow (check disk/network)

### If Network Queue is Growing
- Attacker is sending faster than IDS can process
- Increase all worker counts
- Or reduce attacker rate limit

## Expected Results with Async Pipeline

### Before (Synchronous)
```
Attacker sent: 22,000 packets
IDS processed: 3,500 packets (16% throughput)
Validation accuracy: 98%
Time: 5 minutes
```

### After (Async)
```
Attacker sent: 22,000 packets
IDS processed: 18,000+ packets (82%+ throughput)
Validation accuracy: 98% (same)
Time: 5 minutes
```

## Implementation Details

### Thread Safety
- Each queue is thread-safe (Python's `queue.Queue`)
- Metrics are protected with locks
- No shared state between workers

### Error Handling
- Worker threads catch exceptions and continue
- Failed packets are logged but don't crash pipeline
- Graceful shutdown on KeyboardInterrupt

### Memory Management
- Queue sizes are limited (maxsize=1000)
- Prevents unbounded memory growth
- Backpressure when queues fill

## Limitations

1. **Database Bottleneck**: DB operations are still sequential
   - Solution: Use async database (e.g., async Pinecone)
   - Or: Increase `num_db_workers` (limited benefit)

2. **Validator Bottleneck**: Validator is single-threaded
   - Solution: Increase `num_validator_workers` (usually not needed)

3. **Network Bottleneck**: Packet capture is single-threaded
   - Solution: Use C++ backend (ids_bridge.cpp)
   - Or: Use multiple network interfaces

## Future Optimizations

1. **Async Database**: Use async Pinecone client
2. **GPU Acceleration**: Use CUDA for CNN/RNN
3. **C++ Backend**: Use eBPF for packet capture
4. **Distributed Pipeline**: Run workers on multiple machines
5. **Smart Batching**: Process multiple packets in parallel

## Comparison with C++ Backend

| Metric | Async Python | C++ Backend |
|--------|--------------|------------|
| Throughput | 5-10K pps | 24,668 pps |
| Latency | 2-10ms | 2-7µs |
| CPU Usage | 80-90% | 10-20% |
| Memory | 500MB-1GB | 50-100MB |
| Development | Easy | Complex |
| Deployment | Python 3.9+ | C++17 compiler |

**Recommendation**: Use async Python for development/testing, C++ backend for production.

## Troubleshooting

### Pipeline is slow
1. Check queue depths (are they growing?)
2. Increase workers for bottleneck stage
3. Check CPU/memory usage
4. Profile with `python -m cProfile run_async.py`

### High latency
1. Check if queues are full
2. Reduce worker count (less context switching)
3. Check database performance
4. Use C++ backend

### Memory growing
1. Check queue sizes
2. Reduce `maxsize` parameter
3. Check for memory leaks in workers
4. Monitor with `memory_profiler`

### Validation accuracy drops
1. Async shouldn't affect accuracy
2. Check if packets are being dropped
3. Verify validator is running
4. Check database sync

## References

- `ai-architecture/async_pipeline.py` - Async pipeline implementation
- `ai-architecture/run_async.py` - Async runner script
- `ai-architecture/run.py` - Original synchronous runner
