from __future__ import annotations

from datetime import date
from typing import Any

import pytest

from skyveda.core.billing import DailyCost
from skyveda.core.errors import PermissionDeniedError, QueryError
from skyveda.core.retry import RetryPolicy
from skyveda.providers.azure.arm import ARM_ENDPOINT
from skyveda.providers.azure.costs import BATCH_SIZE, CostReader, _checked_query_url
from tests.test_arm import FakeResponse

SUB = "00000000-0000-0000-0000-000000000001"
OTHER_SUB = "00000000-0000-0000-0000-000000000002"
QUERY = f"{ARM_ENDPOINT}/subscriptions/{SUB}/providers/Microsoft.CostManagement/query"
DISK = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Compute/disks/d1"
COLUMNS = [
    {"name": "Cost", "type": "Number"},
    {"name": "UsageDate", "type": "Number"},
    {"name": "ResourceId", "type": "String"},
    {"name": "Currency", "type": "String"},
]
START, END = date(2026, 10, 3), date(2026, 11, 1)


def page(rows: list[list[Any]], next_link: str | None = None, columns: Any = None) -> FakeResponse:
    body = {"properties": {"columns": columns or COLUMNS, "rows": rows, "nextLink": next_link}}
    return FakeResponse(200, body)


class FakePost:
    """Replays scripted responses and records every URL and body that was posted."""

    def __init__(self, *responses: FakeResponse) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, url: str, body: dict[str, Any]) -> FakeResponse:
        self.calls.append((url, body))
        return self.responses.pop(0)


def reader(fake: FakePost, sleeps: list[float] | None = None) -> CostReader:
    return CostReader(
        fake,
        policy=RetryPolicy(max_attempts=3),
        sleep=(sleeps if sleeps is not None else []).append,
    )


def test_asks_for_daily_actual_cost_of_the_flagged_resources_only() -> None:
    fake = FakePost(page([[12.5, 20261031, DISK.lower(), "INR"]]))
    costs = reader(fake).daily_costs([DISK], START, END)
    assert costs == [DailyCost(DISK.lower(), date(2026, 10, 31), 12.5, "INR")]
    url, body = fake.calls[0]
    assert url == f"{QUERY}?api-version=2023-11-01"
    assert body["type"] == "ActualCost"
    assert body["timePeriod"] == {"from": "2026-10-03T00:00:00Z", "to": "2026-11-01T23:59:59Z"}
    assert body["dataset"]["granularity"] == "Daily"
    assert body["dataset"]["filter"]["dimensions"]["values"] == [DISK]


def test_one_query_per_subscription_and_batch() -> None:
    disks = [f"{DISK}{n}" for n in range(BATCH_SIZE + 1)]
    other = DISK.replace(SUB, OTHER_SUB)
    fake = FakePost(page([]), page([]), page([]))
    reader(fake).daily_costs([*disks, other, "not-a-resource-id"], START, END)
    sizes = [
        (url.split("/")[4], len(body["dataset"]["filter"]["dimensions"]["values"]))
        for url, body in fake.calls
    ]
    assert sizes == [(SUB, BATCH_SIZE), (SUB, 1), (OTHER_SUB, 1)]


def test_follows_next_link_on_the_same_query_with_the_same_body() -> None:
    next_link = f"{QUERY}?api-version=2023-11-01&$skiptoken=abc"
    fake = FakePost(
        page([[1, 20261031, DISK, "INR"]], next_link), page([[2, 20261101, DISK, "INR"]])
    )
    assert len(reader(fake).daily_costs([DISK], START, END)) == 2
    assert fake.calls[1] == (next_link, fake.calls[0][1])


@pytest.mark.parametrize(
    "link",
    [
        "https://evil.example/subscriptions/x/providers/Microsoft.CostManagement/query",
        f"{ARM_ENDPOINT}/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Compute/disks/d1",
        f"http://management.azure.com/subscriptions/{SUB}/providers/Microsoft.CostManagement/query",
        f"https://management.azure.com:8443/subscriptions/{SUB}/providers/Microsoft.CostManagement/query",
        f"https://user@management.azure.com/subscriptions/{SUB}/providers/Microsoft.CostManagement/query",
    ],
)
def test_never_posts_anywhere_but_a_cost_query(link: str) -> None:
    fake = FakePost(page([], link))
    with pytest.raises(QueryError, match="Refusing"):
        reader(fake).daily_costs([DISK], START, END)
    assert len(fake.calls) == 1
    with pytest.raises(QueryError, match="Refusing"):
        _checked_query_url(link)


def test_reads_the_older_pre_tax_cost_column() -> None:
    columns = [
        {"name": "PreTaxCost"},
        {"name": "UsageDate"},
        {"name": "ResourceId"},
        {"name": "Currency"},
    ]
    fake = FakePost(page([[3, 20261031, DISK, "INR"]], columns=columns))
    assert reader(fake).daily_costs([DISK], START, END)[0].amount == 3.0


def test_unexpected_columns_are_an_error() -> None:
    fake = FakePost(page([], columns=[{"name": "Cost"}]))
    with pytest.raises(QueryError, match="unexpected columns"):
        reader(fake).daily_costs([DISK], START, END)


def test_no_access_is_a_permission_error() -> None:
    with pytest.raises(PermissionDeniedError):
        reader(FakePost(FakeResponse(403))).daily_costs([DISK], START, END)


def test_throttling_waits_for_the_cost_management_header() -> None:
    sleeps: list[float] = []
    throttled = FakeResponse(
        429, headers={"x-ms-ratelimit-microsoft.costmanagement-qpu-retry-after": "7"}
    )
    fake = FakePost(throttled, page([]))
    assert reader(fake, sleeps).daily_costs([DISK], START, END) == []
    assert sleeps == [7.0]


def test_a_refused_query_names_the_error_code() -> None:
    refused = FakeResponse(400, {"error": {"code": "BillingAccountNotSupported", "message": "x"}})
    with pytest.raises(QueryError, match="HTTP 400: BillingAccountNotSupported"):
        reader(FakePost(refused)).daily_costs([DISK], START, END)


class NotJson(FakeResponse):
    def json(self) -> Any:
        raise ValueError("Expecting value")


@pytest.mark.parametrize(
    "response",
    [
        NotJson(200),
        FakeResponse(200, {"properties": ["x"]}),
        FakeResponse(200, {"properties": {"rows": "x"}}),
    ],
)
def test_a_malformed_answer_is_a_query_error(response: FakeResponse) -> None:
    with pytest.raises(QueryError):
        reader(FakePost(response)).daily_costs([DISK], START, END)
