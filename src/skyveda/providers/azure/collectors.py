"""Collectors: Python data fetchers for settings Resource Graph does not index.

A check names a collector in ``source.collector``; only the functions in COLLECTORS can run, so
a check file can never point at arbitrary code. Each collector finds resources with Resource
Graph, then reads one ARM object per resource with read-only GETs (a few at a time). Rows are
recorded for offline runs exactly as a collector returns them.

API versions are pinned and stable; each was checked against live Azure in the lab.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from skyveda.core.models import Row
from skyveda.providers.azure.arm import ArmReader

SQL_API_VERSION = "2021-11-01"
WEB_API_VERSION = "2022-03-01"
WORKERS = 8
_ALL_INTERNET = ("0.0.0.0", "255.255.255.255")  # noqa: S104 - the range we flag, not a bind


@dataclass(frozen=True, slots=True)
class CollectorContext:
    graph: Callable[[str], list[Row]]
    """Runs a Resource Graph query over the scan's subscriptions."""
    arm: ArmReader


Collector = Callable[[CollectorContext], list[Row]]

_SQL_SERVERS = """
resources
| where type =~ 'microsoft.sql/servers'
| project id, name, resourceGroup, location
"""

_WEB_SITES = """
resources
| where type =~ 'microsoft.web/sites'
| project id, name, resourceGroup, location, appKind = tostring(kind)
"""


def sql_firewall_rules(ctx: CollectorContext) -> list[Row]:
    """One row per SQL server firewall rule; flags 0.0.0.0-255.255.255.255.

    "Allow Azure services" (0.0.0.0-0.0.0.0) is a different setting and is not flagged here.
    Missing addresses cannot be proven safe, so they count as the open range.
    """

    def rules(server: Row) -> list[Row]:
        found = ctx.arm.list(f"{server['id']}/firewallRules", SQL_API_VERSION)
        return [_firewall_row(server, rule) for rule in found]

    return _flatten(_each(ctx.graph(_SQL_SERVERS), rules))


def web_site_config(ctx: CollectorContext) -> list[Row]:
    """One row per App Service app with its site configuration (``config/web``)."""

    def config(site: Row) -> list[Row]:
        found = ctx.arm.get(f"{site['id']}/config/web", WEB_API_VERSION)
        if found is None:
            return []
        props: dict[str, Any] = found.get("properties") or {}
        cors: dict[str, Any] = props.get("cors") or {}
        return [
            {
                **site,
                "minTlsVersion": props.get("minTlsVersion"),
                "scmMinTlsVersion": props.get("scmMinTlsVersion"),
                "ftpsState": props.get("ftpsState"),
                "remoteDebuggingEnabled": props.get("remoteDebuggingEnabled"),
                # No CORS list means browsers allow same-origin requests only.
                "corsAllowedOrigins": cors.get("allowedOrigins") or [],
            }
        ]

    return _flatten(_each(ctx.graph(_WEB_SITES), config))


COLLECTORS: dict[str, Collector] = {
    "skyveda.providers.azure.collectors.sql_firewall_rules": sql_firewall_rules,
    "skyveda.providers.azure.collectors.web_site_config": web_site_config,
}


def _firewall_row(server: Row, rule: dict[str, Any]) -> Row:
    props: dict[str, Any] = rule.get("properties") or {}
    start = str(props.get("startIpAddress") or _ALL_INTERNET[0])
    end = str(props.get("endIpAddress") or _ALL_INTERNET[1])
    return {
        "id": rule.get("id"),
        "name": rule.get("name"),
        "resourceGroup": server.get("resourceGroup"),
        "location": server.get("location"),
        "server": server.get("name"),
        "startIp": start,
        "endIp": end,
        "compliant": (start, end) != _ALL_INTERNET,
    }


def _each(items: Sequence[Row], fn: Callable[[Row], list[Row]]) -> list[list[Row]]:
    if len(items) <= 1:
        return [fn(item) for item in items]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        return list(pool.map(fn, items))


def _flatten(groups: Iterable[list[Row]]) -> list[Row]:
    return [row for group in groups for row in group]
