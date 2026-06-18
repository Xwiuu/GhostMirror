"""RateLimiter — simple rate limiter for safe payload execution."""

from __future__ import annotations

import time
from collections import defaultdict


class RateLimiter:
    """Simple token-bucket-like rate limiter for payload execution.

    Defaults:
    - max_requests_per_second: 2
    - max_payloads_per_target: 25
    """

    def __init__(
        self,
        max_requests_per_second: int = 2,
        max_payloads_per_target: int = 25,
    ) -> None:
        self.max_requests_per_second = max_requests_per_second
        self.max_payloads_per_target = max_payloads_per_target
        self._target_counts: dict[str, int] = defaultdict(int)
        self._last_request_time: float = 0.0
        self._min_interval: float = 1.0 / max_requests_per_second

    def acquire(self, target: str) -> bool:
        """Acquire permission to send a request.

        Returns True if allowed, False if rate-limited.
        """
        if self._target_counts[target] >= self.max_payloads_per_target:
            return False

        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)

        self._last_request_time = time.monotonic()
        self._target_counts[target] += 1
        return True

    def can_acquire(self, target: str) -> bool:
        """Check if a request would be allowed without actually acquiring."""
        return self._target_counts[target] < self.max_payloads_per_target

    def reset(self, target: str | None = None) -> None:
        """Reset counters for a specific target or all targets."""
        if target:
            self._target_counts[target] = 0
        else:
            self._target_counts.clear()

    def remaining_for_target(self, target: str) -> int:
        """Return how many more payloads are allowed for a target."""
        return max(0, self.max_payloads_per_target - self._target_counts[target])
