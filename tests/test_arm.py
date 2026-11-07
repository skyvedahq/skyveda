from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import pytest

from skyveda.core.errors import PermissionDeniedError, QueryError
from skyveda.core.retry import RetryPolicy
from skyveda.providers.azure.arm import ARM_ENDPOINT, ArmReader

SERVER = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Sql/servers/sql1"


@dataclass
class FakeResponse:
    status_code: int
    body: Any = None
    headers: Mapping[str, str] = field(default_factory=dict)

    def json(self) -> Any:
        return self.body

    def text(self) -> str:
        return str(self.body)


class FakeArm:
    """Replays scripted responses and records every URL that was sent."""

    def __init__(self, *responses: FakeResponse) -> None:
        self.responses = list(responses)
        self.urls: list[str] = []

    def __call__(self, url: str) -> FakeResponse:
        self.urls.append(url)
        return self.responses.pop(0)


def reader(fake: FakeArm, sleeps: list[float] | None = None) -> ArmReader:
    return ArmReader(
        fake,
        policy=RetryPolicy(max_attempts=3),
        sleep=(sleeps if sleeps is not None else []).append,
    )


def test_get_returns_the_object_and_pins_the_api_version() -> None:
    fake = FakeArm(FakeResponse(200, {"properties": {"minTlsVersion": "1.2"}}))
    assert reader(fake).get(f"{SERVER}/config/web", "2022-03-01") == {
        "properties": {"minTlsVersion": "1.2"}
    }
    assert fake.urls == [f"{ARM_ENDPOINT}{SERVER}/config/web?api-version=2022-03-01"]


def test_a_resource_gone_during_the_scan_is_none() -> None:
    assert reader(FakeArm(FakeResponse(404))).get(SERVER, "v") is None


@pytest.mark.parametrize("status", [401, 403])
def test_no_access_is_a_permission_error(status: int) -> None:
    with pytest.raises(PermissionDeniedError, match="Reader is enough"):
        reader(FakeArm(FakeResponse(status))).get(SERVER, "v")


def test_throttling_is_retried_after_the_servers_delay() -> None:
    sleeps: list[float] = []
    fake = FakeArm(FakeResponse(429, headers={"Retry-After": "7"}), FakeResponse(200, {"a": 1}))
    assert reader(fake, sleeps).get(SERVER, "v") == {"a": 1}
    assert sleeps == [7.0]


def test_persistent_server_errors_end_in_a_query_error() -> None:
    fake = FakeArm(FakeResponse(503), FakeResponse(503), FakeResponse(503))
    with pytest.raises(QueryError, match="HTTP 503"):
        reader(fake).get(SERVER, "v")
    assert len(fake.urls) == 3


def test_other_client_errors_are_not_retried() -> None:
    fake = FakeArm(FakeResponse(400))
    with pytest.raises(QueryError, match="HTTP 400"):
        reader(fake).get(SERVER, "v")
    assert len(fake.urls) == 1


def test_list_follows_next_links_on_arm() -> None:
    next_link = f"{ARM_ENDPOINT}{SERVER}/firewallRules?api-version=v&$skiptoken=2"
    fake = FakeArm(
        FakeResponse(200, {"value": [{"name": "a"}], "nextLink": next_link}),
        FakeResponse(200, {"value": [{"name": "b"}]}),
    )
    items = reader(fake).list(f"{SERVER}/firewallRules", "v")
    assert [item["name"] for item in items] == ["a", "b"]
    assert fake.urls[1] == next_link


@pytest.mark.parametrize(
    "next_link",
    [
        "https://attacker.example/steal",
        "http://management.azure.com/subscriptions/s1",  # not https
        "https://management.azure.com.attacker.example/x",
    ],
)
def test_list_never_sends_the_token_to_another_host(next_link: str) -> None:
    fake = FakeArm(FakeResponse(200, {"value": [], "nextLink": next_link}))
    with pytest.raises(QueryError, match="Refusing to follow"):
        reader(fake).list(SERVER, "v")
    assert len(fake.urls) == 1


def test_only_resource_paths_are_accepted() -> None:
    with pytest.raises(QueryError, match="Not an ARM resource path"):
        reader(FakeArm()).get("https://example.com/x", "v")


def test_unexpected_list_format_is_an_error() -> None:
    with pytest.raises(QueryError, match="unexpected list format"):
        reader(FakeArm(FakeResponse(200, {"value": "oops"}))).list(SERVER, "v")
