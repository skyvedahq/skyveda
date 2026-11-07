"""Read-only client for billed cost: the Azure Cost Management Query API (D-028).

The Query API takes its question as a POST body but only reads. This client can POST to one
path only, ``/subscriptions/{id}/providers/Microsoft.CostManagement/query``: `_query_url` is the
one place a URL is built, and pages follow ``nextLink`` only when it points at that same path on
management.azure.com (a guardrail test checks both). The ARM reader stays GET-only.

One query per subscription and batch of flagged resources asks for actual cost by day, grouped by
resource. Errors: 401/403 become PermissionDeniedError, 408/429/5xx are retried honouring the
Cost Management retry-after headers, anything else is a QueryError naming the error code.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from datetime import date, datetime
from typing import Any
from urllib.parse import urlsplit

from azure.core import PipelineClient
from azure.core.credentials import TokenCredential
from azure.core.exceptions import ServiceRequestError, ServiceResponseError
from azure.core.pipeline.policies import BearerTokenCredentialPolicy, UserAgentPolicy
from azure.core.rest import HttpRequest

from skyveda import __version__
from skyveda.core.billing import DailyCost
from skyveda.core.errors import PermissionDeniedError, QueryError
from skyveda.core.retry import RetryPolicy, call_with_retry
from skyveda.providers.azure.arm import (
    ARM_ENDPOINT,
    MAX_PAGES,
    RETRYABLE_STATUS_CODES,
    ArmResponse,
    TransientError,
    checked_next_link,
    classify_retry,
    retry_after,
)
from skyveda.providers.azure.auth import ARM_SCOPE

COST_API_VERSION = "2023-11-01"
BATCH_SIZE = 100
_QUERY_PATH = re.compile(
    r"^/subscriptions/[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}"
    r"/providers/microsoft\.costmanagement/query$",
    re.IGNORECASE,
)
_SUBSCRIPTION = re.compile(r"^/subscriptions/([0-9a-fA-F-]{36})/", re.IGNORECASE)
_RETRY_HEADERS = (
    "x-ms-ratelimit-microsoft.costmanagement-qpu-retry-after",
    "x-ms-ratelimit-microsoft.costmanagement-entity-retry-after",
    "x-ms-ratelimit-microsoft.costmanagement-tenant-retry-after",
)

Post = Callable[[str, dict[str, Any]], ArmResponse]
"""POSTs a JSON body to an absolute Cost Management query URL and returns the response."""


class CostReader:
    def __init__(
        self,
        post: Post,
        *,
        policy: RetryPolicy | None = None,
        sleep: Callable[[float], None] = time.sleep,
        on_close: Callable[[], None] | None = None,
    ) -> None:
        self._post = post
        self._policy = policy or RetryPolicy()
        self._sleep = sleep
        self._on_close = on_close

    @classmethod
    def from_credential(cls, credential: TokenCredential) -> CostReader:
        client: PipelineClient[HttpRequest, Any] = PipelineClient(
            base_url=ARM_ENDPOINT,
            policies=[
                UserAgentPolicy(f"skyveda-scan/{__version__}"),
                BearerTokenCredentialPolicy(credential, ARM_SCOPE),
            ],
        )

        def post(url: str, body: dict[str, Any]) -> ArmResponse:
            response = client.send_request(HttpRequest("POST", _checked_query_url(url), json=body))
            response.read()
            return response  # type: ignore[no-any-return]

        return cls(post, on_close=client.close)

    def daily_costs(self, resource_ids: Sequence[str], start: date, end: date) -> list[DailyCost]:
        """Actual cost per resource and day; IDs outside a subscription are ignored."""
        by_subscription: dict[str, list[str]] = {}
        for resource_id in resource_ids:
            match = _SUBSCRIPTION.match(resource_id)
            if match:
                by_subscription.setdefault(match.group(1).lower(), []).append(resource_id)
        costs: list[DailyCost] = []
        for subscription_id, ids in sorted(by_subscription.items()):
            for offset in range(0, len(ids), BATCH_SIZE):
                body = _query_body(ids[offset : offset + BATCH_SIZE], start, end)
                for page in self._pages(_query_url(subscription_id), body):
                    costs.extend(_parse(page))
        return costs

    def close(self) -> None:
        if self._on_close is not None:
            self._on_close()

    def _pages(self, url: str, body: dict[str, Any]) -> Iterator[dict[str, Any]]:
        for _ in range(MAX_PAGES):
            page = self._post_json(url, body)
            yield page
            properties = page.get("properties") or {}
            next_link = properties.get("nextLink") if isinstance(properties, dict) else None
            if not next_link:
                return
            url = _checked_query_url(checked_next_link(str(next_link)))
        raise QueryError(f"Cost Management returned more than {MAX_PAGES} pages.")

    def _post_json(self, url: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            response = call_with_retry(
                lambda: self._post_once(url, body),
                classify=classify_retry,
                policy=self._policy,
                sleep=self._sleep,
            )
        except TransientError as exc:
            raise QueryError(f"Cost Management kept failing (HTTP {exc.status}).") from exc
        except (ServiceRequestError, ServiceResponseError) as exc:
            raise QueryError(f"Could not reach Cost Management: {exc.message}") from exc
        try:
            result = response.json()
        except ValueError as exc:
            raise QueryError("Cost Management returned a result that is not JSON.") from exc
        if not isinstance(result, dict):
            raise QueryError("Cost Management returned an unexpected result format.")
        return result

    def _post_once(self, url: str, body: dict[str, Any]) -> ArmResponse:
        response = self._post(url, body)
        status = response.status_code
        if status == 200:
            return response
        if status in (401, 403):
            raise PermissionDeniedError(f"No read access to cost data (HTTP {status}).")
        if status in RETRYABLE_STATUS_CODES:
            raise TransientError(status, _retry_after(response.headers))
        raise QueryError(f"Cost Management refused the query (HTTP {status}{_code(response)})")


def _query_url(subscription_id: str) -> str:
    path = f"/subscriptions/{subscription_id}/providers/Microsoft.CostManagement/query"
    return _checked_query_url(f"{ARM_ENDPOINT}{path}?api-version={COST_API_VERSION}")


def _checked_query_url(url: str) -> str:
    """The only URL this client may POST to: a subscription's Cost Management query."""
    parts = urlsplit(url)
    host_ok = (
        parts.scheme == "https"
        and parts.hostname == urlsplit(ARM_ENDPOINT).hostname
        and parts.port in (None, 443)
        and not parts.username
        and not parts.password
    )
    if not host_ok or not _QUERY_PATH.fullmatch(parts.path):
        raise QueryError("Refusing to POST anywhere but a Cost Management query.")
    return url


def _query_body(resource_ids: Sequence[str], start: date, end: date) -> dict[str, Any]:
    return {
        "type": "ActualCost",
        "timeframe": "Custom",
        "timePeriod": {"from": f"{start}T00:00:00Z", "to": f"{end}T23:59:59Z"},
        "dataset": {
            "granularity": "Daily",
            "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}},
            "grouping": [{"type": "Dimension", "name": "ResourceId"}],
            "filter": {
                "dimensions": {"name": "ResourceId", "operator": "In", "values": list(resource_ids)}
            },
        },
    }


def _parse(page: dict[str, Any]) -> list[DailyCost]:
    properties = page.get("properties") or {}
    if not isinstance(properties, dict) or not isinstance(properties.get("rows") or [], list):
        raise QueryError("Cost Management returned an unexpected result format.")
    raw_columns = properties.get("columns") or []
    if not isinstance(raw_columns, list):
        raise QueryError("Cost Management returned an unexpected result format.")
    columns = [str(c.get("name")) for c in raw_columns if isinstance(c, dict)]
    cost_column = next((name for name in ("Cost", "PreTaxCost") if name in columns), None)
    needed = ("UsageDate", "ResourceId", "Currency")
    if cost_column is None or not all(name in columns for name in needed):
        raise QueryError(f"Cost Management returned unexpected columns: {', '.join(columns)}.")
    at = {name: columns.index(name) for name in (cost_column, *needed)}
    try:
        return [
            DailyCost(
                resource_id=str(row[at["ResourceId"]]),
                day=datetime.strptime(str(row[at["UsageDate"]]), "%Y%m%d").date(),
                amount=float(row[at[cost_column]]),
                currency=str(row[at["Currency"]]),
            )
            for row in properties.get("rows") or []
        ]
    except (IndexError, TypeError, ValueError) as exc:
        raise QueryError(f"Cost Management returned a malformed row ({exc}).") from exc


def _retry_after(headers: Mapping[str, str]) -> float | None:
    lowered = {key.lower(): value for key, value in headers.items()}
    waits = [
        retry_after({"Retry-After": lowered[name]}) for name in _RETRY_HEADERS if name in lowered
    ]
    waits.append(retry_after(headers))
    known = [wait for wait in waits if wait is not None]
    return max(known) if known else None


def _code(response: ArmResponse) -> str:
    try:
        error = response.json().get("error") or {}
        code = error.get("code") if isinstance(error, dict) else None
    except (AttributeError, ValueError):
        return ""
    return f": {code}" if code else ""
