"""Turn the rows a check's source returned into a CheckResult.

The default ``rows`` evaluator expects one row per in-scope resource with a boolean compliance
column. A ``python`` evaluator first reshapes the raw rows into that form with a named function,
for logic a query language cannot express; the result is then judged the same way.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from importlib import import_module
from typing import cast

from skyveda.core.errors import CheckLoadError, EvaluationError
from skyveda.core.models import (
    AffectedResource,
    Check,
    CheckResult,
    CostBasis,
    Finding,
    ParameterValue,
    PythonEvaluator,
    Row,
    RowsEvaluator,
    Status,
)

RowTransform = Callable[[Sequence[Row], Mapping[str, ParameterValue]], list[Row]]

# Only Skyveda's own code may run as an evaluator: a check file from --checks-dir is data and must
# not be able to import arbitrary modules.
TRUSTED_PREFIX = "skyveda."
_COMPLIANCE = RowsEvaluator()


def resolve_transform(function: str) -> RowTransform:
    """Import the dotted ``function`` path; raise CheckLoadError if it is untrusted or missing."""
    if not function.startswith(TRUSTED_PREFIX):
        raise CheckLoadError(f"Evaluator '{function}' is outside the skyveda package.")
    module_name, _, attribute = function.rpartition(".")
    try:
        target = getattr(import_module(module_name), attribute)
    except (ImportError, AttributeError) as exc:
        raise CheckLoadError(f"Evaluator '{function}' does not exist.") from exc
    if not callable(target):
        raise CheckLoadError(f"Evaluator '{function}' is not callable.")
    return cast(RowTransform, target)


def evaluate(check: Check, rows: Sequence[Row]) -> CheckResult:
    """Judge ``rows`` for ``check``. Raises EvaluationError if the rows lack required columns."""
    spec = check.evaluate
    if isinstance(spec, PythonEvaluator):
        rows = resolve_transform(spec.function)(rows, check.parameters)
        spec = _COMPLIANCE
    if not rows:
        return _result(check, Status.NOT_APPLICABLE, evaluated=0)
    failing = [row for row in rows if not _is_compliant(row, spec)]
    if not failing:
        return _result(check, Status.PASS, evaluated=len(rows))
    resources = [_affected(row, spec, check, _row_waste(check, row)) for row in failing]
    finding = _finding(check, resources, total_waste(check.cost is not None, resources))
    return _result(check, Status.FAIL, evaluated=len(rows), finding=finding)


def total_waste(is_cost: bool, resources: Sequence[AffectedResource]) -> int | None:
    """Sum the per-resource ₹ of a finding's resources; None for non-cost checks, or when no
    resource has a figure (never ₹0 for an unknown cost)."""
    known = [r.est_monthly_waste_inr for r in resources if r.est_monthly_waste_inr is not None]
    if not is_cost or not known:
        return None
    return round(sum(known))


def billed_waste(resources: Sequence[AffectedResource]) -> int | None:
    """Sum the billed part of a cost finding's waste; None when no resource is billed."""
    billed = [r for r in resources if r.cost_basis is CostBasis.BILLED]
    if not billed:
        return None
    return round(sum(resource.est_monthly_waste_inr or 0.0 for resource in billed))


def _row_waste(check: Check, row: Row) -> float | None:
    if check.cost is None or check.cost.field is None:
        return None
    value = row.get(check.cost.field)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise EvaluationError(f"A failing row has no numeric '{check.cost.field}' value.")
    return float(max(value, 0))


def _is_compliant(row: Row, spec: RowsEvaluator) -> bool:
    if spec.compliant_field not in row:
        raise EvaluationError(f"A row is missing the '{spec.compliant_field}' column.")
    value = row[spec.compliant_field]
    # Azure Resource Graph returns KQL booleans as 1 and 0, so exactly 1 means true too.
    # Unknown compliance (null) counts as a failure: a check must never pass by accident.
    if value is True or (type(value) is int and value == 1):
        return True
    return isinstance(value, str) and value.lower() == "true"


def _affected(row: Row, spec: RowsEvaluator, check: Check, waste: float | None) -> AffectedResource:
    if not row.get(spec.resource_id_field):
        raise EvaluationError(f"A failing row has no '{spec.resource_id_field}' value.")
    hidden = {spec.resource_id_field, spec.name_field, spec.compliant_field}
    name = row.get(spec.name_field)
    return AffectedResource(
        id=str(row[spec.resource_id_field]),
        name=None if name is None else str(name),
        evidence={key: value for key, value in row.items() if key not in hidden},
        est_monthly_waste_inr=waste,
        cost_basis=_basis(check, waste),
    )


def _basis(check: Check, waste: float | None) -> CostBasis | None:
    if check.cost is None:
        return None
    return CostBasis.UNKNOWN if waste is None else CostBasis.ESTIMATE


def _finding(check: Check, resources: list[AffectedResource], waste: int | None) -> Finding:
    return Finding(
        est_monthly_waste_inr=waste,
        check_id=check.id,
        title=check.title,
        provider=check.provider,
        area=check.area,
        severity=check.severity,
        resources=resources,
        why=check.why,
        fix=check.fix,
        references=list(check.references),
        frameworks=dict(check.frameworks),
    )


def _result(
    check: Check, status: Status, *, evaluated: int, finding: Finding | None = None
) -> CheckResult:
    return CheckResult(
        check_id=check.id,
        title=check.title,
        area=check.area,
        severity=check.severity,
        status=status,
        frameworks=dict(check.frameworks),
        resources_evaluated=evaluated,
        finding=finding,
    )
