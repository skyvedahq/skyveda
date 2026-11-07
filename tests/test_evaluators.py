from __future__ import annotations

from typing import Any

import pytest
import yaml

from skyveda.core.errors import CheckLoadError, EvaluationError
from skyveda.core.evaluators import evaluate, resolve_transform
from skyveda.core.models import Check, Status

CHECK = {
    "id": "AZ-TST-001",
    "title": "Test check",
    "provider": "azure",
    "area": "security",
    "severity": "high",
    "source": {"type": "resource_graph", "query": "resources"},
    "why": "w",
    "fix": {"summary": "f"},
}


def check(**changes: Any) -> Check:
    return Check.model_validate(CHECK | changes)


def row(name: str, compliant: Any, **extra: Any) -> dict[str, Any]:
    return {"id": f"/subscriptions/x/{name}", "name": name, "compliant": compliant, **extra}


def test_no_rows_is_not_applicable() -> None:
    assert evaluate(check(), []).status is Status.NOT_APPLICABLE


def test_all_compliant_passes_and_counts_resources() -> None:
    # Resource Graph returns KQL booleans as 1 and 0 (seen on the first live lab scan).
    result = evaluate(check(), [row("a", True), row("b", "true"), row("c", 1)])
    assert result.status is Status.PASS
    assert result.resources_evaluated == 3


def test_resource_graph_zero_is_a_failure() -> None:
    assert evaluate(check(), [row("a", 1), row("b", 0)]).status is Status.FAIL


def test_failing_rows_become_one_finding_with_evidence() -> None:
    result = evaluate(check(), [row("a", True), row("b", False, tls="TLS1_0")])
    assert result.status is Status.FAIL
    assert result.finding is not None
    assert result.finding.resource_ids == ["/subscriptions/x/b"]
    assert result.finding.resources[0].evidence == {"tls": "TLS1_0"}


@pytest.mark.parametrize("unknown", [None, "maybe", 2, 1.0])
def test_unknown_compliance_counts_as_failure(unknown: Any) -> None:
    assert evaluate(check(), [row("a", unknown)]).status is Status.FAIL


def test_missing_compliance_column_is_an_evaluation_error() -> None:
    with pytest.raises(EvaluationError, match="compliant"):
        evaluate(check(), [{"id": "x", "name": "x"}])


def test_failing_row_without_id_is_an_evaluation_error() -> None:
    with pytest.raises(EvaluationError, match="id"):
        evaluate(check(), [{"name": "x", "compliant": False}])


def test_python_evaluator_reshapes_rows_first() -> None:
    nsg = check(
        evaluate={
            "type": "python",
            "function": "skyveda.providers.azure.evaluators.nsg_open_management_ports",
        }
    )
    assert evaluate(nsg, [{"id": "n1", "name": "n1", "rules": []}]).status is Status.PASS


@pytest.mark.parametrize(
    "function", ["os.system", "skyveda.core.nope.missing", "skyveda.core.engine.FINDINGS_FILE"]
)
def test_untrusted_missing_or_uncallable_evaluators_are_rejected(function: str) -> None:
    with pytest.raises(CheckLoadError):
        resolve_transform(function)


def cost_check() -> Check:
    return check(area="cost", cost={"field": "waste"})


def test_waste_sums_failing_rows_and_rounds() -> None:
    rows = [row("a", False, waste=100.4), row("b", False, waste=50.3), row("c", True, waste=999)]
    result = evaluate(cost_check(), rows)
    assert result.finding is not None
    assert result.finding.est_monthly_waste_inr == 151


@pytest.mark.parametrize("bad", [None, "100", True])
def test_failing_cost_row_needs_a_numeric_waste(bad: Any) -> None:
    with pytest.raises(EvaluationError, match="waste"):
        evaluate(cost_check(), [row("a", False, waste=bad)])


def test_cost_block_only_on_cost_checks() -> None:
    with pytest.raises(ValueError, match="cost-area"):
        check(cost={"field": "waste"})


def test_check_yaml_round_trips_into_the_model() -> None:
    assert check().id == Check.model_validate(yaml.safe_load(yaml.safe_dump(CHECK))).id
