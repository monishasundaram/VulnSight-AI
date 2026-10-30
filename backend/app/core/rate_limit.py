from __future__ import annotations

from collections import defaultdict, deque
from threading import Lock
from time import monotonic

from fastapi import HTTPException, Request


class SlidingWindowLimiter:
    """Process-local rate limiter; keyed on the peer address, never an untrusted forwarded header."""
    def __init__(self, max_keys: int = 20_000):
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()
        self._max_keys = max_keys

    def hit(self, key: str, limit: int, window_seconds: int) -> None:
        now = monotonic()
        with self._lock:
            if len(self._events) > self._max_keys:
                cutoff = now - max(window_seconds, 3600)
                for old_key in list(self._events)[: len(self._events) // 2]:
                    if not self._events[old_key] or self._events[old_key][-1] < cutoff:
                        self._events.pop(old_key, None)
            events = self._events[key]
            cutoff = now - window_seconds
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                retry_after = max(1, int(window_seconds - (now - events[0])))
                raise HTTPException(status_code=429, detail="Rate limit exceeded; retry later", headers={"Retry-After": str(retry_after)})
            events.append(now)


limiter = SlidingWindowLimiter()


def enforce_rate_limit(request: Request, bucket: str, limit: int, window_seconds: int) -> None:
    peer = request.client.host if request.client else "unknown"
    limiter.hit(f"{bucket}:{peer}", limit, window_seconds)
