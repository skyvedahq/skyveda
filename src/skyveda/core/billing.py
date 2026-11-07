"""Billed cost for cost findings (D-028).

After the checks run, the resources flagged by cost checks whose waste is their whole bill are
priced from the cloud's own billing data instead of list prices. A provider opts in by
implementing ``BilledCostSource``. Anything that goes wrong here leaves the list-price estimates
in place with a note saying why: billed cost improves a report, it never fails a scan.

The monthly figure is the average billed day times 30, over the 30 days ending the day before
yesterday (clouds post usage up to a day late). A resource's first billed day is left out when
it has others, since it was rarely billed for all of that day.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Protocol, runtime_checkable

from skyveda.core.errors import PermissionDeniedError, SkyvedaError
from skyveda.core.evaluators import billed_waste, total_waste
from skyveda.core.models import (
    AffectedResource,
    Billing,
    Check,
    CheckResult,
    CostBasis,
    ScanResult,
)

log = logging.getLogger(__name__)

CURRENCY = "INR"
PERIOD_DAYS = 30
SETTLE_DAYS = 2
_ESTIMATES_KEPT = "keep their list-price estimate, or show no figure where a check has none"


@dataclass(frozen=True, slots=True)
class DailyCost:
    """One resource's billed cost for one day, in the billing currency."""

    resource_id: str
    day: date
    amount: float
    currency: str


@runtime_checkable
class BilledCostSource(Protocol):
    def daily_costs(self, resource_ids: Sequence[str], start: date, end: date) -> list[DailyCost]:
        """Billed cost per resource and day from ``start`` to ``end`` inclusive."""
        ...


@dataclass(frozen=True, slots=True)
class RunRates:
    monthly: dict[str, float]
    """Monthly ₹ per lower-cased resource ID."""
    other_currency: frozenset[str]


def billing_period(today: date) -> tuple[date, date]:
    end = today - timedelta(days=SETTLE_DAYS)
    return end - timedelta(days=PERIOD_DAYS - 1), end


def run_rates(costs: Sequence[DailyCost]) -> RunRates:
    by_resource: dict[str, dict[date, float]] = defaultdict(lambda: defaultdict(float))
    other: set[str] = set()
    for cost in costs:
        key = cost.resource_id.lower()
        if cost.currency.upper() != CURRENCY:
            other.add(key)
        by_resource[key][cost.day] += cost.amount
    monthly = {}
    for key, days in by_resource.items():
        if key in other:
            continue
        kept = sorted(days)[1:] if len(days) > 1 else list(days)
        monthly[key] = max(sum(days[day] for day in kept), 0.0) / len(kept) * PERIOD_DAYS
    return RunRates(monthly=monthly, other_currency=frozenset(other))


def apply_billed_costs(
    result: ScanResult, checks: Sequence[Check], provider: object, today: date
) -> ScanResult:
    """Replace list-price estimates with billed cost where the provider reports it."""
    billable = {check.id for check in checks if check.cost is not None and check.cost.billed}
    targets = [item for item in result.results if item.finding and item.check_id in billable]
    ids = sorted({r.id.lower() for item in targets if item.finding for r in item.finding.resources})
    if not ids:
        return result.model_copy(update={"billing": Billing()})
    if not isinstance(provider, BilledCostSource):
        return _estimates_only(result, f"{result.provider} cannot report billed cost")
    start, end = billing_period(today)
    try:
        costs = provider.daily_costs(ids, start, end)
    except PermissionDeniedError:
        log.debug("Billed cost refused", exc_info=True)
        return _estimates_only(result, "this sign-in cannot read cost data")
    except SkyvedaError as exc:
        log.debug("Billed cost failed", exc_info=True)
        return _estimates_only(result, str(exc).splitlines()[0].rstrip("."))
    except Exception:  # billed cost is optional (D-028): never fail the scan
        log.debug("Billed cost failed unexpectedly", exc_info=True)
        return _estimates_only(result, "an unexpected error; run with -v for details")
    rates = run_rates(costs)
    notes = []
    if foreign := [i for i in ids if i in rates.other_currency]:
        notes.append(
            f"{len(foreign)} resource(s) are billed in a currency other than INR and "
            f"{_ESTIMATES_KEPT}."
        )
    if missing := [i for i in ids if i not in rates.monthly and i not in rates.other_currency]:
        notes.append(
            f"{len(missing)} resource(s) have no billed cost in the period yet and "
            f"{_ESTIMATES_KEPT}."
        )
    if free := [i for i in ids if round(rates.monthly.get(i, 1.0)) == 0]:
        notes.append(
            f"{len(free)} resource(s) were billed ₹0 in the period, for example under a "
            "reservation or a free allowance; removing them may still free capacity paid for "
            "elsewhere."
        )
    results = [
        _priced(item, rates.monthly) if item.check_id in billable else item
        for item in result.results
    ]
    billing = Billing(period_start=start, period_end=end, notes=notes)
    return result.model_copy(update={"results": results, "billing": billing})


def _estimates_only(result: ScanResult, reason: str) -> ScanResult:
    note = (
        f"Billed cost could not be read ({reason}), so cost figures are list-price estimates, "
        "or missing where a check has no list price."
    )
    return result.model_copy(update={"billing": Billing(notes=[note])})


def _priced(item: CheckResult, monthly: dict[str, float]) -> CheckResult:
    finding = item.finding
    if finding is None:
        return item
    resources = [
        _billed(resource, monthly.get(resource.id.lower())) for resource in finding.resources
    ]
    update = {
        "resources": resources,
        "est_monthly_waste_inr": total_waste(True, resources),
        "billed_monthly_waste_inr": billed_waste(resources),
    }
    return item.model_copy(update={"finding": finding.model_copy(update=update)})


def _billed(resource: AffectedResource, monthly: float | None) -> AffectedResource:
    if monthly is None:
        return resource
    update = {"est_monthly_waste_inr": round(monthly, 2), "cost_basis": CostBasis.BILLED}
    return resource.model_copy(update=update)
