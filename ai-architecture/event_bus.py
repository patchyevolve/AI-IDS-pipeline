"""
Event Bus — central pub/sub broker.
emit() is non-blocking: events are queued and dispatched on a
dedicated worker thread so capture/attacker threads are never stalled.

Pipeline events (network_event → cnn_features → rnn_context →
decoder_output → db_logged) are processed on a single ordered worker
so frame ordering is preserved. All other events (dashboard callbacks,
exports) are fire-and-forget on a second thread pool.
"""
import threading
import queue
import time
from collections import defaultdict, deque
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor


# Only network_event needs the ordered queue — the pipeline processes
# cnn_features / rnn_context / decoder_output / db_logged inline and
# emits them for dashboard subscribers only, so they go to the side pool.
_ORDERED = frozenset({
    "network_event",
})


class EventBus:
    def __init__(self, maxsize: int = 200):
        self._subscribers  = defaultdict(list)
        self._history      = deque(maxlen=200)
        self._queue        = queue.Queue(maxsize=maxsize)
        # Side-channel executor for non-ordered events (dashboard, exports)
        self._side_pool    = ThreadPoolExecutor(max_workers=2,
                                                thread_name_prefix="EventBus-side")
        self._worker       = threading.Thread(target=self._dispatch_loop,
                                              daemon=True, name="EventBus-pipeline")
        self._worker.start()

    def subscribe(self, event_type: str, callback):
        self._subscribers[event_type].append(callback)

    def emit(self, event_type: str, data: dict):
        """Non-blocking. Pipeline events go to ordered queue; others to thread pool."""
        if event_type in _ORDERED:
            try:
                self._queue.put_nowait((event_type, data))
            except queue.Full:
                # Drop oldest, retry once
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    pass
                try:
                    self._queue.put_nowait((event_type, data))
                except queue.Full:
                    pass
        else:
            # Non-ordered: dispatch immediately on side pool
            cbs = self._subscribers.get(event_type, [])
            if cbs:
                try:
                    # Give UI threads a tiny breather to acquire locks
                    time.sleep(0.0001)
                    self._side_pool.submit(self._call_all, event_type, data, cbs)
                except RuntimeError:
                    # Ignore if the executor is shutting down during program exit
                    pass

    def _call_all(self, event_type: str, data: dict, cbs: list):
        self._history.append({
            "event": event_type, "data": data,
            "at": datetime.now().isoformat(),
        })
        for cb in cbs:
            try:
                cb(data)
            except Exception as e:
                print(f"[EventBus] {event_type} callback error: {e}")

    def _dispatch_loop(self):
        while True:
            try:
                event_type, data = self._queue.get(timeout=0.05)
            except queue.Empty:
                continue
            self._history.append({
                "event": event_type, "data": data,
                "at": datetime.now().isoformat(),
            })
            for cb in self._subscribers.get(event_type, []):
                try:
                    cb(data)
                except RuntimeError as e:
                    if "cannot schedule new futures" in str(e):
                        pass # Ignore shutdown errors
                    else:
                        print(f"[EventBus] {event_type} pipeline error: {e}")
                except Exception as e:
                    print(f"[EventBus] {event_type} pipeline error: {e}")

    def get_history(self, limit: int = 100) -> list:
        return list(self._history)[-limit:]

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()
