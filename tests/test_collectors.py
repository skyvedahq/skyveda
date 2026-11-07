from __future__ import annotations

from typing import Any

import pytest

from skyveda.core.checks import load_checks
from skyveda.core.errors import UnsupportedSourceError
from skyveda.core.models import Row, Scope, Source
from skyveda.core.provider import DataRequest, ProviderOptions
from skyveda.providers.azure.arm import ArmReader
from skyveda.providers.azure.collectors import (
    COLLECTORS,
    CollectorContext,
    sql_firewall_rules,
    web_site_config,
)
from skyveda.providers.azure.evaluators import (
    web_cors_any_origin,
    web_ftps,
    web_min_tls,
    web_remote_debugging,
)
from skyveda.providers.azure.provider import AzureProvider
from tests.test_arm import FakeArm, FakeResponse

SUB = "00000000-0000-0000-0000-000000000001"
SQL = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Sql/servers/sql1"
SITE = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Web/sites/app1"


class StubArm:
    """Stands in for ArmReader: canned objects and lists by path."""

    def __init__(self, objects: dict[str, Any], lists: dict[str, list[dict[str, Any]]]) -> None:
        self.objects = objects
        self.lists = lists
        self.calls: list[str] = []

    def get(self, path: str, api_version: str) -> dict[str, Any] | None:
        self.calls.append(path)
        found: dict[str, Any] | None = self.objects.get(path)
        return found

    def list(self, path: str, api_version: str) -> list[dict[str, Any]]:
        self.calls.append(path)
        return self.lists.get(path, [])

    def close(self) -> None: ...


def context(rows: list[Row], arm: StubArm) -> CollectorContext:
    return CollectorContext(graph=lambda kql: rows, arm=arm)  # type: ignore[arg-type]


def rule(name: str, start: str | None, end: str | None) -> dict[str, Any]:
    return {
        "id": f"{SQL}/firewallRules/{name}",
        "name": name,
        "properties": {"startIpAddress": start, "endIpAddress": end},
    }


def test_sql_firewall_rules_flag_only_the_whole_internet() -> None:
    server = {"id": SQL, "name": "sql1", "resourceGroup": "rg", "location": "centralindia"}
    arm = StubArm(
        {},
        {
            f"{SQL}/firewallRules": [
                rule("open", "0.0.0.0", "255.255.255.255"),  # noqa: S104
                rule("AllowAllWindowsAzureIps", "0.0.0.0", "0.0.0.0"),  # noqa: S104
                rule("office", "203.0.113.10", "203.0.113.10"),
                rule("unknown", None, None),
            ]
        },
    )
    rows = sql_firewall_rules(context([server], arm))
    verdicts = {row["name"]: row["compliant"] for row in rows}
    assert verdicts == {
        "open": False,
        "AllowAllWindowsAzureIps": True,
        "office": True,
        "unknown": False,  # missing addresses cannot be proven safe
    }
    assert {row["server"] for row in rows} == {"sql1"}


def test_web_site_config_reads_config_web_and_skips_vanished_apps() -> None:
    gone = SITE.replace("app1", "app2")
    sites = [
        {"id": SITE, "name": "app1", "resourceGroup": "rg", "location": "x", "appKind": "app"},
        {"id": gone, "name": "app2", "resourceGroup": "rg", "location": "x", "appKind": "app"},
    ]
    config = {
        "properties": {
            "minTlsVersion": "1.0",
            "ftpsState": "AllAllowed",
            "cors": {"allowedOrigins": ["*"], "supportCredentials": False},
        }
    }
    arm = StubArm({f"{SITE}/config/web": config}, {})
    rows = web_site_config(context(sites, arm))
    assert [row["name"] for row in rows] == ["app1"]
    assert rows[0]["minTlsVersion"] == "1.0"
    assert rows[0]["remoteDebuggingEnabled"] is None
    assert rows[0]["corsAllowedOrigins"] == ["*"]


def test_cors_fails_only_a_wildcard_origin() -> None:
    rows: list[Row] = [
        {"id": "/a", "name": "listed", "corsAllowedOrigins": ["https://www.example.com"]},
        {"id": "/b", "name": "wildcard", "corsAllowedOrigins": ["https://x.example", " * "]},
        {"id": "/c", "name": "no-cors", "corsAllowedOrigins": []},
        {"id": "/d", "name": "unrecorded"},
    ]
    verdicts = {row["name"]: row["compliant"] for row in web_cors_any_origin(rows, {})}
    assert verdicts == {"listed": True, "wildcard": False, "no-cors": True, "unrecorded": False}


def test_web_site_config_records_no_cors_as_an_empty_list() -> None:
    sites = [{"id": SITE, "name": "app1", "resourceGroup": "rg", "location": "x", "appKind": "app"}]
    arm = StubArm({f"{SITE}/config/web": {"properties": {"minTlsVersion": "1.2"}}}, {})
    assert web_site_config(context(sites, arm))[0]["corsAllowedOrigins"] == []


SITE_ROWS: list[Row] = [
    {"id": "/a", "name": "ok", "minTlsVersion": "1.3", "ftpsState": "Disabled",
     "remoteDebuggingEnabled": False},
    {"id": "/b", "name": "weak", "minTlsVersion": "1.1", "ftpsState": "AllAllowed",
     "remoteDebuggingEnabled": True},
    {"id": "/c", "name": "unknown"},
]  # fmt: skip


@pytest.mark.parametrize("evaluator", [web_min_tls, web_ftps, web_remote_debugging])
def test_web_evaluators_pass_only_known_safe_settings(evaluator: Any) -> None:
    verdicts = {row["name"]: row["compliant"] for row in evaluator(SITE_ROWS, {})}
    assert verdicts == {"ok": True, "weak": False, "unknown": False}


def test_every_collector_named_by_a_check_is_registered() -> None:
    named = {c.source.collector for c in load_checks("azure") if c.source.collector is not None}
    assert named
    assert named <= set(COLLECTORS)


def arm_request(collector: str) -> DataRequest:
    return DataRequest(
        key="x",
        source=Source(type="arm", collector=collector),
        scopes=(Scope(kind="subscription", id=SUB),),
    )


class OneShotGraph:
    def __init__(self, rows: list[Row]) -> None:
        self.rows = rows
        self.queries = 0

    def query(self, kql: str, **_: Any) -> list[Row]:
        self.queries += 1
        return self.rows

    def close(self) -> None: ...


def test_provider_runs_a_shared_collector_once_per_scan() -> None:
    sites = [{"id": SITE, "name": "app1", "resourceGroup": "rg", "location": "x"}]
    graph = OneShotGraph(sites)
    arm = FakeArm(FakeResponse(200, {"properties": {"minTlsVersion": "1.2"}}))
    provider = AzureProvider(
        ProviderOptions(),
        credential=object(),  # type: ignore[arg-type]
        runner=graph,  # type: ignore[arg-type]
        arm=ArmReader(arm),
    )
    name = "skyveda.providers.azure.collectors.web_site_config"
    first = provider.fetch(arm_request(name))
    second = provider.fetch(arm_request(name))
    assert first == second
    assert first[0]["minTlsVersion"] == "1.2"
    assert len(arm.urls) == 1
    assert graph.queries == 1


def test_provider_refuses_an_unregistered_collector() -> None:
    provider = AzureProvider(
        ProviderOptions(),
        credential=object(),  # type: ignore[arg-type]
        runner=OneShotGraph([]),  # type: ignore[arg-type]
        arm=object(),  # type: ignore[arg-type]
    )
    with pytest.raises(UnsupportedSourceError, match="Unknown collector"):
        provider.fetch(arm_request("skyveda.providers.azure.collectors.os_system"))
