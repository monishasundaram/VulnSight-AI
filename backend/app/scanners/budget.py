from __future__ import annotations

from threading import Lock


class ScanBudgetExceeded(RuntimeError):
    pass


class RequestBudget:
    def __init__(self, maximum_requests: int):
        if maximum_requests < 1 or maximum_requests > 32:
            raise ValueError("A scan request budget must be between 1 and 32")
        self.maximum_requests = maximum_requests
        self._used = 0
        self._lock = Lock()

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    @property
    def remaining(self) -> int:
        with self._lock:
            return self.maximum_requests - self._used

    def reserve(self) -> None:
        with self._lock:
            if self._used >= self.maximum_requests:
                raise ScanBudgetExceeded("The configured scan request limit has been reached")
            self._used += 1
