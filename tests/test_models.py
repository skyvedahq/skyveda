from __future__ import annotations

from datetime import UTC, datetime

import pytest
import yaml
from pydantic import ValidationError

from skyveda.core.models import (
    AffectedResource,
    Area,
    Check,
    CheckResult,
    Finding,
    Fix,
    PythonEvaluator,
    RowsEvaluator,
    ScanResult,
    Severity,
    Source,
    Status,
)

CHECK_YAML = """
id: AZ-AKS-001
title: Kubernetes version is within Azure support
provider: azure
area: kubernetes
severity: high
source:
  type: resource_graph
  query: |
    resources
    | where type =~ 'microsoft.containerservice/managedclusters'
evaluate:
  type: python
  function: skyveda.providers.azure.evaluators.aks.version_supported
why: Unsupported versions stop receiving security patches.
fix:
  summary: Upgrade the cluster.
  cli: az aks upgrade -g <rg> -n <cluster> --kubernetes-version <version>
references:
  - https://learn.microsoft.com/azure/aks/supported-kubernetes-versions
"""


def _finding(area: Area = Area.SECURITY, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        check_id="AZ-SEC-001",
        title="t",
        provider="azure",
        area=area,
        severity=severity,
        resources=[AffectedResource(id="/subscriptions/x/r1", evidence={"tls": "TLS1_0"})],
        why="w",
        fix=Fix(summary="f"),
    )


def test_check_parses_from_yaml() -> None:
    check = Check.model_validate(yaml.safe_load(CHECK_YAML))
    assert check.area is Area.KUBERNETES
    assert isinstance(check.evaluate, PythonEvaluator)
    assert check.tier.value == "free"


def test_check_defaults_to_rows_evaluator() -> None:
    data = yaml.safe_load(CHECK_YAML)
    del data["evaluate"]
    assert isinstance(Check.model_validate(data).evaluate, RowsEvaluator)


@pytest.mark.parametrize("bad_id", ["AZ-AKS-1", "az-aks-001", "AKS-001"])
def test_check_rejects_malformed_ids(bad_id: str) -> None:
    data = yaml.safe_load(CHECK_YAML) | {"id": bad_id}
    with pytest.raises(ValidationError):
        Check.model_validate(data)


def test_check_rejects_unknown_fields() -> None:
    data = yaml.safe_load(CHECK_YAML) | {"severty": "low"}
    with pytest.raises(ValidationError):
        Check.model_validate(data)


def test_source_needs_exactly_one_of_query_or_collector() -> None:
    with pytest.raises(ValidationError):
        Source(type="resource_graph")
    with pytest.raises(ValidationError):
        Source(type="collector", query="q", collector="azure.aks.versions")
    assert Source(type="collector", collector="azure.aks.versions").collector


def test_severity_ordering() -> None:
    assert Severity.CRITICAL.at_least(Severity.HIGH)
    assert not Severity.LOW.at_least(Severity.MEDIUM)


def test_finding_exposes_resource_ids_in_json() -> None:
    assert _finding().model_dump(mode="json")["resource_ids"] == ["/subscriptions/x/r1"]


def test_waste_is_only_allowed_on_cost_findings() -> None:
    def with_waste(finding: Finding) -> Finding:
        data = finding.model_dump(exclude={"resource_ids"}) | {"est_monthly_waste_inr": 100}
        return Finding.model_validate(data)

    with pytest.raises(ValidationError):
        with_waste(_finding(area=Area.SECURITY))
    assert with_waste(_finding(area=Area.COST)).est_monthly_waste_inr == 100


def test_check_result_requires_finding_only_when_failed() -> None:
    with pytest.raises(ValidationError):
        CheckResult(
            check_id="AZ-SEC-001",
            title="t",
            area=Area.SECURITY,
            severity=Severity.HIGH,
            status=Status.FAIL,
        )
    with pytest.raises(ValidationError):
        CheckResult(
            check_id="AZ-SEC-001",
            title="t",
            area=Area.SECURITY,
            severity=Severity.HIGH,
            status=Status.PASS,
            finding=_finding(),
        )


def test_scan_result_sorts_findings_by_severity_then_area() -> None:
    low = _finding(area=Area.NETWORK, severity=Severity.LOW)
    critical = _finding(area=Area.SECURITY, severity=Severity.CRITICAL)
    high_identity = _finding(area=Area.IDENTITY, severity=Severity.HIGH)
    results = [
        CheckResult(
            check_id=f.check_id,
            title=f.title,
            area=f.area,
            severity=f.severity,
            status=Status.FAIL,
            finding=f,
        )
        for f in (low, critical, high_identity)
    ]
    now = datetime.now(UTC)
    scan = ScanResult(
        tool_version="0",
        provider="azure",
        scopes=[],
        started_at=now,
        finished_at=now,
        results=results,
    )
    assert [f.severity for f in scan.findings] == [Severity.CRITICAL, Severity.HIGH, Severity.LOW]
    assert scan.has_findings_at_or_above(Severity.CRITICAL)
    assert scan.count_by_status()[Status.FAIL] == 3
