from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

import pytest
from azure.core.exceptions import HttpResponseError, ODataV4Format, ServiceRequestError
from azure.mgmt.resourcegraph.models import QueryRequest, QueryResponse

from skyveda.core.errors import PermissionDeniedError, QueryError
from skyveda.core.retry import RetryPolicy
from skyveda.providers.azure.resource_graph import (
    SUBSCRIPTIONS_PER_REQUEST,
    ResourceGraphRunner,
    retry_after_seconds,
)
from tests.conftest import load_json


def page(raw: dict[str, Any]) -> QueryResponse:
    """Deserialise a REST response body exactly as the SDK would."""
    response: QueryResponse = QueryResponse.deserialize(raw)
    return response


def recorded_page(azure_fixtures: Path, name: str) -> QueryResponse:
    return page(load_json(azure_fixtures / "resource_graph" / name))


def http_error(status: int, headers: dict[str, str] | None = None) -> HttpResponseError:
    error = HttpResponseError(message=f"HTTP {status}\nsecond line")
    error.status_code = status
    error.response = cast(Any, type("FakeResponse", (), {"headers": headers or {}})())
    return error


class FakeGraph:
    """Replays a scripted sequence of responses/exceptions and records every request."""

    def __init__(self, script: list[QueryResponse | Exception]) -> None:
        self.script = list(script)
        self.requests: list[QueryRequest] = []

    def __call__(self, request: QueryRequest) -> QueryResponse:
        self.requests.append(request)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def runner_for(graph: FakeGraph, sleeps: list[float] | None = None) -> ResourceGraphRunner:
    return ResourceGraphRunner(
        graph,
        policy=RetryPolicy(max_attempts=3),
        sleep=(sleeps if sleeps is not None else []).append,
    )


def empty_page() -> QueryResponse:
    return page({"totalRecords": 0, "count": 0, "resultTruncated": "false", "data": []})


def test_follows_skip_token_across_pages(azure_fixtures: Path) -> None:
    graph = FakeGraph(
        [
            recorded_page(azure_fixtures, "subscriptions_page1.json"),
            recorded_page(azure_fixtures, "subscriptions_page2.json"),
        ]
    )
    rows = runner_for(graph).query("resourcecontainers")
    assert [row["name"] for row in rows] == [
        "skyveda-lab-dev",
        "skyveda-lab-prod",
        "skyveda-lab-shared",
    ]
    assert graph.requests[0].options is not None
    assert graph.requests[0].options.skip_token is None
    assert graph.requests[1].options is not None
    assert graph.requests[1].options.skip_token == "c2tpcC10b2tlbi0x"  # noqa: S105
    assert graph.requests[0].options.top == 1000


def test_batches_subscriptions() -> None:
    subscriptions = [f"sub-{i}" for i in range(SUBSCRIPTIONS_PER_REQUEST + 1)]
    graph = FakeGraph([empty_page(), empty_page()])
    runner_for(graph).query("resources", subscriptions=subscriptions)
    assert [len(r.subscriptions or []) for r in graph.requests] == [SUBSCRIPTIONS_PER_REQUEST, 1]


def test_management_groups_are_passed_through() -> None:
    graph = FakeGraph([empty_page()])
    runner_for(graph).query("resources", management_groups=["mg-prod"])
    assert graph.requests[0].management_groups == ["mg-prod"]
    assert graph.requests[0].subscriptions is None


def test_rejects_subscriptions_and_management_groups_together() -> None:
    with pytest.raises(QueryError):
        runner_for(FakeGraph([])).query("resources", subscriptions=["a"], management_groups=["b"])


def test_retries_throttling_using_retry_after(azure_fixtures: Path) -> None:
    sleeps: list[float] = []
    page = recorded_page(azure_fixtures, "subscriptions_page2.json")
    graph = FakeGraph([http_error(429, {"Retry-After": "7"}), page])
    rows = runner_for(graph, sleeps).query("resources")
    assert len(rows) == 1
    assert sleeps == [7.0]


def test_retries_connection_errors(azure_fixtures: Path) -> None:
    page = recorded_page(azure_fixtures, "subscriptions_page2.json")
    graph = FakeGraph([ServiceRequestError("reset"), page])
    assert len(runner_for(graph).query("resources")) == 1


def test_quota_reset_header_is_used_when_no_retry_after() -> None:
    error = http_error(429, {"x-ms-user-quota-resets-after": "00:00:04"})
    assert retry_after_seconds(error) == 4.0


def test_permission_denied_is_not_retried_and_is_translated() -> None:
    graph = FakeGraph([http_error(403)])
    with pytest.raises(PermissionDeniedError, match="Reader"):
        runner_for(graph).query("resources")
    assert len(graph.requests) == 1


def test_bad_query_becomes_query_error_with_first_line_only() -> None:
    with pytest.raises(QueryError) as caught:
        runner_for(FakeGraph([http_error(400)])).query("not kql")
    assert "second line" not in str(caught.value)


def test_bad_query_error_names_azures_nested_reason() -> None:
    error = http_error(400)
    error.error = ODataV4Format(
        {
            "code": "BadRequest",
            "message": "support reference",
            "details": [
                {
                    "code": "InvalidQuery",
                    "message": "Query is invalid.",
                    "details": [{"code": "ParserFailure", "message": "ParserFailure"}],
                }
            ],
        }
    )
    with pytest.raises(QueryError, match="Azure reports: InvalidQuery, ParserFailure"):
        runner_for(FakeGraph([error])).query("let x = 1; resources")


def test_persistent_throttling_eventually_fails() -> None:
    graph = FakeGraph([http_error(429)] * 3)
    with pytest.raises(QueryError, match="429"):
        runner_for(graph).query("resources")
    assert len(graph.requests) == 3


def test_warns_when_results_truncated(caplog: pytest.LogCaptureFixture) -> None:
    truncated = page(
        {"totalRecords": 1, "count": 1, "resultTruncated": "true", "data": [{"id": 1}]}
    )
    with caplog.at_level(logging.WARNING):
        runner_for(FakeGraph([truncated])).query("resources")
    assert "truncated" in caplog.text
