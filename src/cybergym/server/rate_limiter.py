import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException


class RateLimiter:
    """Sliding-window rate limiter keyed by agent_id."""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._last_purge: float = 0.0

    def check(self, agent_id: str):
        """Raise HTTP 429 if the agent has exceeded the rate limit."""
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            if now - self._last_purge >= self.window_seconds:
                self._purge_stale(cutoff)
                self._last_purge = now

            q = self._requests[agent_id]
            # Evict expired entries
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= self.max_requests:
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded for agent {agent_id}. "
                    f"Max {self.max_requests} requests per {self.window_seconds}s.",
                )
            q.append(now)

    def _purge_stale(self, cutoff: float):
        """Remove agent buckets whose entries have all expired."""
        stale = [aid for aid, q in self._requests.items() if not q or q[-1] <= cutoff]
        for aid in stale:
            del self._requests[aid]
