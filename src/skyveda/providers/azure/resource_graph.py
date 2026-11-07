"""Azure Resource Graph (KQL) runner with paging, subscription batching and throttling retry.

Resource Graph is read-only by design. Limits handled here:
* at most 1000 rows per page; further pages are fetched with ``$skipToken``;
* subscriptions are sent in batches of 1000 per request;
* HTTP 429 / 5xx are retried, honouring ``Retry-After`` and the Resource Graph
  ``x-ms-user-quota-resets-after`` header.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence
from itertools import batched
from typing import Any

from azure.core.credentials import TokenCredential
from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import (
    QueryRequest,
    QueryRequestOptions,
    QueryResponse,
    ResultFormat,
    ResultTruncated,
)

from skyveda.core.errors import PermissionDeniedError, QueryError, SkyvedaError
from skyveda.core.models import Row
from skyveda.core.retry import Retry, RetryPolicy, call_with_retry

log = logging.getLogger(__name__)

PAGE_SIZE = 1000
SUBSCRIPTIONS_PER_REQUEST = 1000
RETRYABLE_STATUS_CODES = frozenset({408, 429, 500, 502, 503, 504})

PageFetcher = Callable[[QueryRequest], QueryResponse]


class ResourceGraphRunner:
    def __init__(
        self,
        fetch_page: PageFetcher,
        *,
        policy: RetryPolicy | None = None,
        sleep: Callable[[float], None] = time.sleep,
        on_close: Callable[[], None] | None = None,
    ) -> None:
        self._fetch_page = fetch_page
        self._policy = policy or RetryPolicy()
        self._sleep = sleep
        self._on_close = on_close

    @classmethod
    def from_credential(cls, credential: TokenCredential) -> ResourceGraphRunner:
        # SDK-level retries are disabled so the retry policy lives in exactly one place.
        client = ResourceGraphClient(credential, retry_total=0)
        return cls(lambda request: client.resources(request), on_close=client.close)

    def query(
        self,
        kql: str,
        *,
        subscriptions: Sequence[str] = (),
        management_groups: Sequence[str] = (),
    ) -> list[Row]:
        """Run ``kql`` over the given scopes (all accessible ones if both are empty)."""
        if subscriptions and management_groups:
            raise QueryError("Query either subscriptions or management groups, not both.")
        if not subscriptions:
            return self._all_pages(kql, subscriptions=None, management_groups=management_groups)
        rows: list[Row] = []
        for batch in batched(subscriptions, SUBSCRIPTIONS_PER_REQUEST):
            rows.extend(self._all_pages(kql, subscriptions=batch, management_groups=()))
        return rows

    def close(self) -> None:
        if self._on_close is not None:
            self._on_close()

    def _all_pages(
        self,
        kql: str,
        *,
        subscriptions: Sequence[str] | None,
        management_groups: Sequence[str],
    ) -> list[Row]:
        rows: list[Row] = []
        skip_token: str | None = None
        while True:
            request = _build_request(kql, subscriptions, management_groups, skip_token)
            response = self._fetch_with_retry(request)
            rows.extend(_rows_of(response))
            _warn_if_truncated(response)
            skip_token = response.skip_token
            if not skip_token:
                return rows

    def _fetch_with_retry(self, request: QueryRequest) -> QueryResponse:
        try:
            return call_with_retry(
                lambda: self._fetch_page(request),
                classify=classify_error,
                policy=self._policy,
                sleep=self._sleep,
            )
        except HttpResponseError as exc:
            raise translate_error(exc) from exc
        except (ServiceRequestError, ServiceResponseError) as exc:
            raise QueryError(f"Could not reach Azure Resource Graph: {exc.message}") from exc


def _build_request(
    kql: str,
    subscriptions: Sequence[str] | None,
    management_groups: Sequence[str],
    skip_token: str | None,
) -> QueryRequest:
    return QueryRequest(
        query=kql,
        subscriptions=list(subscriptions) if subscriptions else None,
        management_groups=list(management_groups) if management_groups else None,
        options=QueryRequestOptions(
            top=PAGE_SIZE,
            skip_token=skip_token,
            result_format=ResultFormat.OBJECT_ARRAY,
        ),
    )


def _rows_of(response: QueryResponse) -> list[Row]:
    data: Any = response.data
    if not isinstance(data, list) or not all(isinstance(row, dict) for row in data):
        raise QueryError("Resource Graph returned an unexpected result format.")
    return data


def _warn_if_truncated(response: QueryResponse) -> None:
    if response.result_truncated == ResultTruncated.TRUE:
        log.warning(
            "Resource Graph truncated the result set. Make sure the query projects the 'id' "
            "column so paging can return every row."
        )


def classify_error(exc: Exception) -> Retry | None:
    if isinstance(exc, ServiceRequestError | ServiceResponseError):
        return Retry()
    if isinstance(exc, HttpResponseError) and exc.status_code in RETRYABLE_STATUS_CODES:
        throttled = exc.status_code == 429
        return Retry(after_seconds=retry_after_seconds(exc), throttled=throttled)
    return None


def retry_after_seconds(exc: HttpResponseError) -> float | None:
    headers = getattr(exc.response, "headers", None) or {}
    retry_after = headers.get("Retry-After")
    if retry_after is not None and retry_after.strip().isdigit():
        return float(retry_after)
    resets_after = headers.get("x-ms-user-quota-resets-after")
    return _parse_hms(resets_after) if resets_after else None


def _parse_hms(value: str) -> float | None:
    """Parse ``hh:mm:ss`` (as sent in ``x-ms-user-quota-resets-after``) into seconds."""
    parts = value.strip().split(":")
    try:
        hours, minutes, seconds = (float(part) for part in parts)
    except ValueError:
        return None
    return hours * 3600 + minutes * 60 + seconds


def translate_error(exc: HttpResponseError) -> SkyvedaError:
    message = _first_line(exc.message)
    if exc.status_code in {401, 403}:
        return PermissionDeniedError(
            f"Resource Graph denied the query (HTTP {exc.status_code}). The identity needs the "
            f"'Reader' role on the scanned scope. Details: {message}"
        )
    codes = error_codes(exc)
    reason = f" Azure reports: {', '.join(codes)}." if codes else ""
    return QueryError(f"Resource Graph query failed (HTTP {exc.status_code}): {message}{reason}")


def error_codes(exc: HttpResponseError) -> list[str]:
    """The nested error codes (e.g. InvalidQuery, ParserFailure): the first line of the message
    is only a support reference, so without these a bad query is impossible to diagnose."""
    codes: list[str] = []
    pending = list(exc.error.details) if exc.error else []
    while pending:
        detail = pending.pop(0)
        if detail.code and detail.code not in codes:
            codes.append(detail.code)
        pending.extend(detail.details)
    return codes


def _first_line(text: str | None) -> str:
    return (text or "no details").strip().splitlines()[0]
