"""Azure-specific row transforms for checks whose logic a KQL query cannot express cleanly.

Each function takes the rows a check's query returned plus the check's parameters and returns
one row per resource with ``id``, ``name``, ``compliant`` and evidence columns, which the
default rows evaluator then judges.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from skyveda.core.models import ParameterValue, Row

INTERNET_SOURCES = frozenset({"*", "internet", "any", "0.0.0.0/0", "::/0"})
DEFAULT_PORTS = ("22", "3389")


def nsg_open_management_ports(
    rows: Sequence[Row], parameters: Mapping[str, ParameterValue]
) -> list[Row]:
    """Flag NSGs with an inbound Allow rule from the Internet to SSH, RDP or other given ports.

    Expects rows with ``id``, ``name`` and ``rules`` (the NSG's ``properties.securityRules``).
    """
    ports = _ports(parameters.get("ports", list(DEFAULT_PORTS)))
    result: list[Row] = []
    for row in rows:
        exposed = [str(rule.get("name", "?")) for rule in _rules(row) if _exposes(rule, ports)]
        result.append(
            {
                "id": row.get("id"),
                "name": row.get("name"),
                "resourceGroup": row.get("resourceGroup"),
                "compliant": not exposed,
                "exposedRules": exposed,
                "checkedPorts": sorted(ports),
            }
        )
    return result


def _ports(value: ParameterValue) -> set[int]:
    items = value if isinstance(value, list) else [str(value)]
    return {int(item) for item in items}


def _rules(row: Row) -> list[Mapping[str, Any]]:
    rules = row.get("rules")
    return [rule for rule in rules if isinstance(rule, Mapping)] if isinstance(rules, list) else []


def _exposes(rule: Mapping[str, Any], ports: set[int]) -> bool:
    props = rule.get("properties")
    if not isinstance(props, Mapping):
        return False
    return (
        str(props.get("access", "")).lower() == "allow"
        and str(props.get("direction", "")).lower() == "inbound"
        and str(props.get("protocol", "*")).lower() in {"*", "tcp"}
        and _from_internet(props)
        and _covers_any(props, ports)
    )


def _from_internet(props: Mapping[str, Any]) -> bool:
    sources = _values(props, "sourceAddressPrefix", "sourceAddressPrefixes")
    return any(source.lower() in INTERNET_SOURCES for source in sources)


def _covers_any(props: Mapping[str, Any], ports: set[int]) -> bool:
    ranges = _values(props, "destinationPortRange", "destinationPortRanges")
    return any(_in_range(text, port) for text in ranges for port in ports)


def _in_range(text: str, port: int) -> bool:
    text = text.strip()
    if text == "*":
        return True
    low, _, high = text.partition("-")
    try:
        return int(low) <= port <= int(high or low)
    except ValueError:
        return False


def _values(props: Mapping[str, Any], single: str, plural: str) -> list[str]:
    values = [str(props[single])] if props.get(single) else []
    many = props.get(plural)
    if isinstance(many, list):
        values += [str(item) for item in many]
    return values


# --- App Service site configuration (rows from collectors.web_site_config) -----------------

_SITE_COLUMNS = ("id", "name", "resourceGroup", "location", "appKind")
_MODERN_TLS = frozenset({"1.2", "1.3"})
_SAFE_FTPS = frozenset({"ftpsonly", "disabled"})


def web_min_tls(rows: Sequence[Row], parameters: Mapping[str, ParameterValue]) -> list[Row]:
    """Apps must require TLS 1.2 or later; an unknown version fails."""
    return [
        _site(row, minTlsVersion=row.get("minTlsVersion"))
        | {"compliant": str(row.get("minTlsVersion")) in _MODERN_TLS}
        for row in rows
    ]


def web_ftps(rows: Sequence[Row], parameters: Mapping[str, ParameterValue]) -> list[Row]:
    """FTP must be off or FTPS-only; AllAllowed (plain FTP) or an unknown state fails."""
    return [
        _site(row, ftpsState=row.get("ftpsState"))
        | {"compliant": str(row.get("ftpsState")).lower() in _SAFE_FTPS}
        for row in rows
    ]


def web_remote_debugging(
    rows: Sequence[Row], parameters: Mapping[str, ParameterValue]
) -> list[Row]:
    """Remote debugging must be off; an unknown setting fails."""
    return [
        _site(row, remoteDebuggingEnabled=row.get("remoteDebuggingEnabled"))
        | {"compliant": row.get("remoteDebuggingEnabled") is False}
        for row in rows
    ]


def web_cors_any_origin(rows: Sequence[Row], parameters: Mapping[str, ParameterValue]) -> list[Row]:
    """CORS must not allow every origin. An empty list (no CORS) allows same-origin only and
    passes; a row without the setting at all cannot be proven safe and fails."""
    result: list[Row] = []
    for row in rows:
        origins = row.get("corsAllowedOrigins")
        listed = [str(item) for item in origins] if isinstance(origins, list) else []
        safe = isinstance(origins, list) and not any(item.strip() == "*" for item in listed)
        result.append(_site(row, corsAllowedOrigins=origins) | {"compliant": safe})
    return result


def _site(row: Row, **evidence: Any) -> Row:
    return {column: row.get(column) for column in _SITE_COLUMNS} | evidence
