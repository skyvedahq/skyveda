from __future__ import annotations

import json
import shutil
from collections.abc import Sequence
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from skyveda.core.billing import DailyCost, apply_billed_costs, billing_period, run_rates
from skyveda.core.checks import load_checks
from skyveda.core.engine import run_scan
from skyveda.core.errors import PermissionDeniedError, QueryError
from skyveda.core.models import AffectedResource, CheckResult, CostBasis, ScanResult
from skyveda.core.offline import OfflineProvider
from skyveda.core.waivers import apply_waivers
from skyveda.report import render_report
from skyveda.report.summary import finding_waste, resource_cost, waste_basis
from tests.test_waivers import waiver

TODAY = date(2026, 11, 3)
RG = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups"
OLD_DISK = f"{RG}/rg-old/providers/Microsoft.Compute/disks/disk-old-vm"
SCRATCH = f"{RG}/rg-old/providers/Microsoft.Compute/disks/disk-scratch"
VM_BATCH = f"{RG}/rg-web/providers/Microsoft.Compute/virtualMachines/vm-batch"
OFF_OS = f"{RG}/rg-old/providers/Microsoft.Compute/disks/disk-off-os"


def daily(
    resource_id: str, monthly: float, days: int = 30, currency: str = "INR"
) -> list[dict[str, object]]:
    """Rows for ``days`` full days ending 1 Nov, plus a half first day before them."""
    first = date(2026, 11, 1) - timedelta(days=days)
    rows = [{"resourceId": resource_id.lower(), "date": str(first), "cost": monthly / 60}]
    rows += [
        {
            "resourceId": resource_id.lower(),
            "date": str(first + timedelta(days=n)),
            "cost": monthly / 30,
        }
        for n in range(1, days + 1)
    ]
    return [{**row, "currency": currency} for row in rows]


def scan(fixtures: Path, billed: list[dict[str, object]] | None) -> ScanResult:
    if billed is not None:
        (fixtures / "billed_costs.json").write_text(json.dumps({"rows": billed}), encoding="utf-8")
    provider = OfflineProvider("azure", fixtures)
    return run_scan(
        provider,
        load_checks("azure"),
        provider.list_scopes(),
        offline=True,
        billed_cost=True,
        clock=lambda: datetime(2026, 11, 3, 9, tzinfo=UTC),
    )


@pytest.fixture
def fixtures(azure_fixtures: Path, tmp_path: Path) -> Path:
    target = tmp_path / "fixtures"
    shutil.copytree(azure_fixtures, target)
    return target


def check(result: ScanResult, check_id: str) -> CheckResult:
    return next(item for item in result.results if item.check_id == check_id)


def test_the_period_is_30_days_ending_the_day_before_yesterday() -> None:
    assert billing_period(TODAY) == (date(2026, 10, 3), date(2026, 11, 1))


def test_run_rate_leaves_out_the_partial_first_day() -> None:
    costs = [
        DailyCost("/X", date(2026, 10, 30), 1.0, "INR"),
        DailyCost("/x", date(2026, 10, 31), 10.0, "INR"),
        DailyCost("/x", date(2026, 10, 31), 2.0, "INR"),
        DailyCost("/x", date(2026, 11, 1), 12.0, "INR"),
    ]
    assert run_rates(costs).monthly == {"/x": pytest.approx(360.0)}


def test_a_single_billed_day_is_used_as_it_is() -> None:
    assert run_rates([DailyCost("/x", TODAY, 3.0, "INR")]).monthly == {"/x": pytest.approx(90.0)}


def test_another_currency_is_never_converted() -> None:
    rates = run_rates([DailyCost("/x", TODAY, 3.0, "USD"), DailyCost("/x", TODAY, 1.0, "INR")])
    assert rates.monthly == {}
    assert rates.other_currency == {"/x"}


def test_billed_cost_replaces_the_estimate_and_ignores_case(fixtures: Path) -> None:
    result = scan(fixtures, daily(OLD_DISK, 3000) + daily(VM_BATCH, 4500))
    finding = check(result, "AZ-COST-001").finding
    assert finding is not None
    by_name = {r.name: r for r in finding.resources}
    assert by_name["disk-old-vm"].est_monthly_waste_inr == pytest.approx(3000)
    assert by_name["disk-old-vm"].cost_basis is CostBasis.BILLED
    assert by_name["disk-scratch"].est_monthly_waste_inr == 896.0  # no billed rows: estimate kept
    assert by_name["disk-scratch"].cost_basis is CostBasis.ESTIMATE
    assert (finding.est_monthly_waste_inr, finding.billed_monthly_waste_inr) == (3896, 3000)
    assert result.billing is not None
    assert (result.billing.period_start, result.billing.period_end) == billing_period(TODAY)
    assert result.billing.notes == [
        "5 resource(s) have no billed cost in the period yet and keep their list-price estimate, "
        "or show no figure where a check has none."
    ]


def test_a_check_without_list_prices_is_priced_from_billing_only(fixtures: Path) -> None:
    unpriced = check(scan(fixtures, []), "AZ-COST-003").finding
    assert unpriced is not None
    assert unpriced.est_monthly_waste_inr is None  # unknown, never ₹0
    assert unpriced.resources[0].cost_basis is CostBasis.UNKNOWN
    assert resource_cost(unpriced.resources[0]) == "₹ not known: no list price, and no billed cost"
    priced = check(scan(fixtures, daily(VM_BATCH, 4500)), "AZ-COST-003").finding
    assert priced is not None
    assert (priced.est_monthly_waste_inr, priced.billed_monthly_waste_inr) == (4500, 4500)


def test_a_price_gap_check_keeps_its_estimate(fixtures: Path) -> None:
    finding = check(scan(fixtures, daily(OFF_OS, 9999)), "AZ-COST-007").finding
    assert finding is not None
    assert finding.billed_monthly_waste_inr is None
    assert {r.cost_basis for r in finding.resources} == {CostBasis.ESTIMATE}


def test_no_billing_data_keeps_every_estimate_with_a_note(fixtures: Path) -> None:
    result = scan(fixtures, None)
    assert check(result, "AZ-COST-001").finding.est_monthly_waste_inr == 4224  # type: ignore[union-attr]
    assert result.billing is not None
    assert result.billing.period_start is None
    assert "no billed costs were recorded" in result.billing.notes[0]


class Refusing:
    def __init__(self, error: Exception) -> None:
        self.error = error

    def daily_costs(self, resource_ids: Sequence[str], start: date, end: date) -> list[DailyCost]:
        raise self.error


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (PermissionDeniedError("HTTP 403"), "this sign-in cannot read cost data"),
        (QueryError("Cost Management refused the query (HTTP 400: Unsupported)."), "HTTP 400"),
    ],
)
def test_a_refused_read_never_fails_the_scan(fixtures: Path, error: Exception, reason: str) -> None:
    unbilled = scan(fixtures, None)
    result = apply_billed_costs(unbilled, load_checks("azure"), Refusing(error), TODAY)
    assert result.results == unbilled.results
    assert result.billing is not None
    assert reason in result.billing.notes[0]


def test_a_provider_without_billing_says_so(fixtures: Path) -> None:
    result = apply_billed_costs(scan(fixtures, None), load_checks("azure"), object(), TODAY)
    assert result.billing is not None
    assert "azure cannot report billed cost" in result.billing.notes[0]


def test_waivers_take_billed_cost_off_both_totals(fixtures: Path) -> None:
    result = scan(fixtures, daily(OLD_DISK, 3000))
    waived = apply_waivers(result, [waiver("AZ-COST-001", SCRATCH)], TODAY).result
    finding = check(waived, "AZ-COST-001").finding
    assert finding is not None
    assert (finding.est_monthly_waste_inr, finding.billed_monthly_waste_inr) == (3000, 3000)
    waived = apply_waivers(result, [waiver("AZ-COST-001", OLD_DISK)], TODAY).result
    finding = check(waived, "AZ-COST-001").finding
    assert finding is not None
    assert (finding.est_monthly_waste_inr, finding.billed_monthly_waste_inr) == (896, None)


def test_the_report_labels_billed_and_estimated_figures(fixtures: Path) -> None:
    result = scan(fixtures, daily(OLD_DISK, 3000))
    html = render_report(result, result.model_dump_json())
    assert "₹3,896 a month, ₹3,000 billed, ₹896 list-price estimate" in html
    assert "₹3,000 a month, billed" in html
    assert "₹896 a month, list-price estimate" in html
    assert "from 03 Oct to 01 Nov 2026" in html


def test_findings_json_round_trips_with_billing(fixtures: Path) -> None:
    result = scan(fixtures, daily(OLD_DISK, 3000))
    assert ScanResult.model_validate_json(result.model_dump_json()) == result


def test_resources_with_no_figure_are_counted_not_hidden(fixtures: Path) -> None:
    finding = check(scan(fixtures, []), "AZ-COST-003").finding
    assert finding is not None
    assert finding_waste(finding) == "₹ not known: 1 resource(s) with no figure"


def test_the_label_follows_each_resource_not_rounded_totals() -> None:
    def resource(amount: float, basis: CostBasis) -> AffectedResource:
        return AffectedResource(id="/x", est_monthly_waste_inr=amount, cost_basis=basis)

    tiny_estimate = [resource(1000, CostBasis.BILLED), resource(0.4, CostBasis.ESTIMATE)]
    assert waste_basis(tiny_estimate) == "₹1,000 billed, ₹0 list-price estimate"
    legacy = [AffectedResource(id="/x", est_monthly_waste_inr=320)]  # findings.json before D-028
    assert waste_basis(legacy) == "list-price estimate"
    assert waste_basis([resource(5, CostBasis.UNKNOWN)]) == "1 resource(s) with no figure"


def test_other_currency_and_zero_bills_get_notes(fixtures: Path) -> None:
    result = scan(fixtures, daily(OLD_DISK, 3000, currency="USD") + daily(SCRATCH, 0))
    finding = check(result, "AZ-COST-001").finding
    assert finding is not None
    assert {r.name: r.cost_basis for r in finding.resources} == {
        "disk-old-vm": CostBasis.ESTIMATE,
        "disk-scratch": CostBasis.BILLED,
    }
    assert result.billing is not None
    notes = " ".join(result.billing.notes)
    assert "1 resource(s) are billed in a currency other than INR" in notes
    assert "1 resource(s) were billed ₹0 in the period" in notes


def test_an_unexpected_error_still_never_fails_the_scan(fixtures: Path) -> None:
    result = apply_billed_costs(
        scan(fixtures, None), load_checks("azure"), Refusing(ValueError("boom")), TODAY
    )
    assert result.billing is not None
    assert "an unexpected error" in result.billing.notes[0]


def test_a_findings_json_from_before_billing_still_renders(fixtures: Path) -> None:
    data = json.loads(scan(fixtures, None).model_dump_json())
    data.pop("billing")
    for item in data["results"]:
        for resource in (item.get("finding") or {}).get("resources", []):
            resource.pop("cost_basis")
        if item.get("finding"):
            item["finding"].pop("billed_monthly_waste_inr")
    old = ScanResult.model_validate(data)
    html = render_report(old, json.dumps(data))
    assert "₹4,224 a month, list-price estimate" in html
    assert "List-price estimates are per resource" in html
    assert apply_waivers(old, [waiver("AZ-COST-001", SCRATCH)], TODAY).result is not None


def test_a_billed_resource_never_shows_its_list_price_too(fixtures: Path) -> None:
    result = scan(fixtures, daily(OLD_DISK, 3000))
    html = render_report(result, result.model_dump_json())
    assert "estMonthlyWasteInr" not in html
