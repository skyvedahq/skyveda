"""Small, provider-neutral retry helper with exponential backoff and server-directed delays."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 5
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 60.0

    def backoff(self, attempt: int) -> float:
        """Delay before the retry that follows failed attempt number ``attempt`` (1-based)."""
        return min(self.max_delay_seconds, self.base_delay_seconds * 2.0 ** (attempt - 1))


@dataclass(frozen=True, slots=True)
class Retry:
    """Classifier verdict: the error is transient; optionally wait the server-specified delay."""

    after_seconds: float | None = None
    throttled: bool = False
    """The service is limiting the request rate (HTTP 429): expected on big scans, so it is
    logged at INFO (shown with -v) rather than as a warning."""


Classifier = Callable[[Exception], Retry | None]


def call_with_retry[T](
    fn: Callable[[], T],
    *,
    classify: Classifier,
    policy: RetryPolicy | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    """Call ``fn``, retrying while ``classify`` says the error is transient."""
    policy = policy or RetryPolicy()
    attempt = 1
    while True:
        try:
            return fn()
        except Exception as exc:
            decision = classify(exc)
            if decision is None or attempt >= policy.max_attempts:
                raise
            delay = _delay_for(decision, policy, attempt)
            if decision.throttled:
                log.info("Azure is limiting the request rate; waiting %.1fs", delay)
            else:
                log.warning(
                    "Temporary service error (%s); retrying in %.1fs (attempt %d of %d)",
                    type(exc).__name__,
                    delay,
                    attempt + 1,
                    policy.max_attempts,
                )
            sleep(delay)
            attempt += 1


def _delay_for(decision: Retry, policy: RetryPolicy, attempt: int) -> float:
    if decision.after_seconds is not None:
        return min(policy.max_delay_seconds, max(0.0, decision.after_seconds))
    return policy.backoff(attempt)
