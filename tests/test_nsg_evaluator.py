from __future__ import annotations

from typing import Any

import pytest

from skyveda.providers.azure.evaluators import nsg_open_management_ports


def nsg(*rules: dict[str, Any]) -> dict[str, Any]:
    return {"id": "/nsg/1", "name": "nsg-1", "resourceGroup": "rg", "rules": list(rules)}


def rule(name: str = "r", **props: Any) -> dict[str, Any]:
    base = {
        "access": "Allow",
        "direction": "Inbound",
        "protocol": "Tcp",
        "sourceAddressPrefix": "Internet",
        "destinationPortRange": "22",
    }
    return {"name": name, "properties": base | props}


def judge(*rules: dict[str, Any], ports: list[str] | None = None) -> dict[str, Any]:
    parameters: dict[str, Any] = {} if ports is None else {"ports": ports}
    return nsg_open_management_ports([nsg(*rules)], parameters)[0]


@pytest.mark.parametrize(
    "props",
    [
        {},
        {"destinationPortRange": "3389"},
        {"destinationPortRange": "*"},
        {"destinationPortRange": "20-25"},
        {"sourceAddressPrefix": "*"},
        {"sourceAddressPrefix": "0.0.0.0/0"},
        {"protocol": "*"},
        {"destinationPortRange": None, "destinationPortRanges": ["80", "3380-3390"]},
        {"sourceAddressPrefix": None, "sourceAddressPrefixes": ["10.0.0.0/8", "Internet"]},
    ],
)
def test_exposed_rules_fail(props: dict[str, Any]) -> None:
    result = judge(rule("open", **props))
    assert result["compliant"] is False
    assert result["exposedRules"] == ["open"]


@pytest.mark.parametrize(
    "props",
    [
        {"access": "Deny"},
        {"direction": "Outbound"},
        {"protocol": "Udp"},
        {"sourceAddressPrefix": "10.0.0.0/8"},
        {"sourceAddressPrefix": "AzureLoadBalancer"},
        {"destinationPortRange": "443"},
        {"destinationPortRange": "not-a-port"},
    ],
)
def test_safe_rules_pass(props: dict[str, Any]) -> None:
    assert judge(rule(**props))["compliant"] is True


def test_nsg_without_rules_passes() -> None:
    assert nsg_open_management_ports([{"id": "/nsg/2", "name": "n"}], {})[0]["compliant"] is True


def test_custom_ports_parameter() -> None:
    assert judge(rule(destinationPortRange="5432"), ports=["5432"])["compliant"] is False
    assert judge(rule(), ports=["5432"])["compliant"] is True
