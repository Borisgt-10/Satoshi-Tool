"""JobManager: jobs en memoria con cola SSE thread-safe."""

from __future__ import annotations

import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, Optional


@dataclass
class JobEvent:
    type: str          # 'kpi' | 'addr' | 'hit' | 'done' | 'error' | 'cancelled'
    payload: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)

    def as_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "payload": self.payload, "timestamp": self.timestamp}


@dataclass
class _Job:
    id: str
    queue: "queue.Queue[Optional[JobEvent]]"
    cancel_flag: threading.Event
    thread: threading.Thread
    finished_at: Optional[float] = None


RunnerFn = Callable[[Callable[[JobEvent], None], Callable[[], bool]], None]


class JobManager:
    """Mantiene jobs en memoria, lanza runners en threads daemon, consume eventos vía SSE."""

    def __init__(self, ttl_seconds: int = 60):
        self._jobs: Dict[str, _Job] = {}
        self._lock = threading.Lock()
        self._ttl = ttl_seconds

    def create(self, runner: RunnerFn) -> str:
        job_id = uuid.uuid4().hex
        q: queue.Queue = queue.Queue()
        cancel_flag = threading.Event()

        def emit(event: JobEvent):
            q.put(event)

        def is_cancelled() -> bool:
            return cancel_flag.is_set()

        def thread_target():
            try:
                runner(emit, is_cancelled)
            except Exception as e:
                q.put(JobEvent(type="error", payload={"message": str(e)}))
                q.put(JobEvent(type="done", payload={"reason": "error"}))
            finally:
                q.put(None)  # sentinel
                with self._lock:
                    if job_id in self._jobs:
                        self._jobs[job_id].finished_at = time.time()

        t = threading.Thread(target=thread_target, daemon=True, name=f"job-{job_id[:8]}")
        with self._lock:
            self._jobs[job_id] = _Job(id=job_id, queue=q, cancel_flag=cancel_flag, thread=t)
        t.start()
        return job_id

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
        if not job:
            return False
        job.cancel_flag.set()
        return True

    def iter_events(self, job_id: str, timeout: float = 30.0) -> Iterator[JobEvent]:
        """Bloquea consumiendo la cola del job. Termina cuando recibe sentinel (None)."""
        with self._lock:
            job = self._jobs.get(job_id)
        if not job:
            return
        try:
            while True:
                try:
                    ev = job.queue.get(timeout=timeout)
                except queue.Empty:
                    return
                if ev is None:
                    return
                yield ev
        finally:
            self.cleanup_finished()

    def cleanup_finished(self) -> None:
        """Elimina jobs cuyo finished_at es anterior a TTL."""
        cutoff = time.time() - self._ttl
        with self._lock:
            stale = [jid for jid, j in self._jobs.items()
                     if j.finished_at is not None and j.finished_at < cutoff]
            for jid in stale:
                del self._jobs[jid]


# Instancia global compartida por todos los routers que crean jobs.
job_manager = JobManager(ttl_seconds=60)
