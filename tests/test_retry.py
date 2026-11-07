from __future__ import annotations

import logging

import pytest

from skyveda.core.retry import Retry, RetryPolicy, call_with_retry


class Flaky:
    def __init__(self, failures: int, error: Exception) -> None:
        self.failures = failures
        self.error = error
        self.calls = 0

    def __call__(self) -> str:
        self.calls += 1
        if self.calls <= self.failures:
            raise self.error
        return "ok"


def _always_retry(_: Exception) -> Retry:
    return Retry()


def test_retries_until_success_with_exponential_backoff() -> None:
    sleeps: list[float] = []
    fn = Flaky(failures=3, error=RuntimeError("boom"))
    result = call_with_retry(fn, classify=_always_retry, sleep=sleeps.append)
    assert result == "ok"
    assert sleeps == [1.0, 2.0, 4.0]


def test_honours_server_delay_capped_at_max() -> None:
    sleeps: list[float] = []
    fn = Flaky(failures=2, error=RuntimeError("throttled"))
    policy = RetryPolicy(max_delay_seconds=10)
    call_with_retry(
        fn, classify=lambda _: Retry(after_seconds=30), policy=policy, sleep=sleeps.append
    )
    assert sleeps == [10, 10]


def test_gives_up_after_max_attempts() -> None:
    fn = Flaky(failures=10, error=RuntimeError("down"))
    with pytest.raises(RuntimeError, match="down"):
        call_with_retry(
            fn, classify=_always_retry, policy=RetryPolicy(max_attempts=3), sleep=lambda _: None
        )
    assert fn.calls == 3


def test_non_retryable_error_raises_immediately() -> None:
    fn = Flaky(failures=1, error=ValueError("bad query"))
    with pytest.raises(ValueError, match="bad query"):
        call_with_retry(fn, classify=lambda _: None, sleep=lambda _: None)
    assert fn.calls == 1


@pytest.mark.parametrize(("throttled", "level"), [(True, logging.INFO), (False, logging.WARNING)])
def test_throttling_is_info_and_server_errors_are_warnings(
    caplog: pytest.LogCaptureFixture, throttled: bool, level: int
) -> None:
    fn = Flaky(failures=1, error=RuntimeError("busy"))
    with caplog.at_level(logging.INFO):
        call_with_retry(fn, classify=lambda _: Retry(throttled=throttled), sleep=lambda _: None)
    assert [record.levelno for record in caplog.records] == [level]
