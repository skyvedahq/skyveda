from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from skyveda.core.checks import load_checks
from skyveda.core.engine import FINDINGS_FILE, nothing_ran, run_check, run_scan, write_findings
from skyveda.core.errors import PermissionDeniedError, QueryError, UnsupportedSourceError
from skyveda.core.models import Check, Row, Scope, Severity, Status
from skyveda.core.offline import OfflineProvider
from skyveda.core.provider import DataRequest

FIXED = datetime(2026, 10, 17, tzinfo=UTC)


class RaisingProvider:
    name = "azure"
    identity = None

    def __init__(self, error: Exception) -> None:
        self.error = error

    def authenticate(self) -> None: ...

    def list_scopes(self) -> list[Scope]:
        return []

    def fetch(self, request: DataRequest) -> list[Row]:
        raise self.error

    def close(self) -> None: ...


@pytest.fixture
def checks() -> list[Check]:
    return load_checks("azure")


def scan(azure_fixtures: Path, checks: list[Check]) -> dict[str, Status]:
    provider = OfflineProvider("azure", azure_fixtures)
    result = run_scan(provider, checks, provider.list_scopes(), offline=True, clock=lambda: FIXED)
    return {item.check_id: item.status for item in result.results}


def test_offline_scan_gives_the_expected_verdicts(
    azure_fixtures: Path, checks: list[Check]
) -> None:
    assert scan(azure_fixtures, checks) == {
        "AZ-ACR-001": Status.FAIL,
        "AZ-ACR-002": Status.FAIL,
        "AZ-ACR-003": Status.FAIL,
        "AZ-AI-001": Status.FAIL,
        "AZ-AKS-002": Status.NOT_APPLICABLE,
        "AZ-AKS-003": Status.FAIL,
        "AZ-AKS-004": Status.FAIL,
        "AZ-AKS-005": Status.FAIL,
        "AZ-AKS-006": Status.FAIL,
        "AZ-AKS-007": Status.FAIL,
        "AZ-AKS-008": Status.FAIL,
        "AZ-AKS-009": Status.FAIL,
        "AZ-AKS-010": Status.FAIL,
        "AZ-COSMOS-001": Status.FAIL,
        "AZ-COSMOS-002": Status.FAIL,
        "AZ-COST-001": Status.FAIL,
        "AZ-COST-002": Status.FAIL,
        "AZ-COST-003": Status.FAIL,
        "AZ-COST-004": Status.FAIL,
        "AZ-COST-005": Status.NOT_APPLICABLE,
        "AZ-COST-006": Status.FAIL,
        "AZ-COST-007": Status.FAIL,
        "AZ-COST-008": Status.FAIL,
        "AZ-KV-001": Status.PASS,
        "AZ-KV-002": Status.FAIL,
        "AZ-KV-003": Status.FAIL,
        "AZ-MSG-001": Status.FAIL,
        "AZ-NET-001": Status.FAIL,
        "AZ-NET-002": Status.FAIL,
        "AZ-NET-003": Status.FAIL,
        "AZ-NET-004": Status.FAIL,
        "AZ-NET-005": Status.FAIL,
        "AZ-NET-006": Status.FAIL,
        "AZ-NET-007": Status.FAIL,
        "AZ-NET-008": Status.FAIL,
        "AZ-PGSQL-001": Status.FAIL,
        "AZ-REDIS-001": Status.FAIL,
        "AZ-REDIS-002": Status.FAIL,
        "AZ-REL-001": Status.FAIL,
        "AZ-REL-002": Status.FAIL,
        "AZ-REL-003": Status.FAIL,
        "AZ-SQL-001": Status.FAIL,
        "AZ-SQL-002": Status.FAIL,
        "AZ-SQL-003": Status.FAIL,
        "AZ-SQL-004": Status.FAIL,
        "AZ-STG-001": Status.FAIL,
        "AZ-STG-002": Status.FAIL,
        "AZ-STG-003": Status.FAIL,
        "AZ-STG-004": Status.FAIL,
        "AZ-STG-005": Status.FAIL,
        "AZ-VM-001": Status.FAIL,
        "AZ-VM-002": Status.FAIL,
        "AZ-VM-003": Status.FAIL,
        "AZ-VM-004": Status.FAIL,
        "AZ-WEB-001": Status.FAIL,
        "AZ-WEB-002": Status.FAIL,
        "AZ-WEB-003": Status.FAIL,
        "AZ-WEB-004": Status.FAIL,
        "AZ-WEB-005": Status.FAIL,
        "AZ-WEB-006": Status.FAIL,
    }


def test_cost_findings_carry_waste_and_others_do_not(
    azure_fixtures: Path, checks: list[Check]
) -> None:
    provider = OfflineProvider("azure", azure_fixtures)
    result = run_scan(provider, checks, provider.list_scopes(), offline=True, clock=lambda: FIXED)
    waste = {f.check_id: f.est_monthly_waste_inr for f in result.findings}
    assert waste["AZ-COST-001"] == 4224  # 3328 + 896; the attached disk is not counted
    assert waste["AZ-COST-002"] == 320
    assert waste["AZ-COST-004"] == 563
    assert waste["AZ-COST-006"] == 2800
    assert waste["AZ-COST-007"] == 7680  # (256 + 1024) GB at INR 6 a GB-month
    assert waste["AZ-COST-008"] == 42  # the zone without a network link
    assert waste["AZ-COST-003"] is None  # needs billed cost (MVP)
    assert waste["AZ-NET-001"] is None


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (PermissionDeniedError("no Reader role"), Status.SKIPPED),
        (UnsupportedSourceError("collectors later"), Status.SKIPPED),
        (QueryError("bad query\nsecond line"), Status.ERROR),
    ],
)
def test_a_failing_check_is_isolated(error: Exception, status: Status, checks: list[Check]) -> None:
    result = run_check(RaisingProvider(error), checks[0], [])
    assert result.status is status
    assert result.message is not None
    assert "second line" not in result.message


def test_nothing_ran_when_every_check_errors(checks: list[Check]) -> None:
    result = run_scan(RaisingProvider(QueryError("down")), checks, [], clock=lambda: FIXED)
    assert nothing_ran(result)


def test_findings_file_is_versioned_json(
    tmp_path: Path, azure_fixtures: Path, checks: list[Check]
) -> None:
    provider = OfflineProvider("azure", azure_fixtures)
    result = run_scan(provider, checks, provider.list_scopes(), offline=True, clock=lambda: FIXED)
    path = write_findings(result, tmp_path / "out")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert path.name == FINDINGS_FILE
    assert data["schema_version"] == 1
    assert data["offline"] is True
    assert result.has_findings_at_or_above(Severity.CRITICAL)
