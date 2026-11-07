from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import JsonValue, ValidationError

from skyveda.core.checks import load_checks
from skyveda.core.engine import run_scan
from skyveda.core.errors import CheckLoadError, RemedyError
from skyveda.core.models import Check, Downtime, Remedy, RemedyRisk, ScanResult
from skyveda.core.offline import OfflineProvider
from skyveda.core.remedy import (
    ALWAYS,
    placeholders,
    projected_columns,
    render,
    resource_values,
    subscription_of,
    used_fields,
)

REMEDY_CHECKS = {
    "AZ-COST-001",
    "AZ-COST-002",
    "AZ-COST-003",
    "AZ-COST-004",
    "AZ-NET-001",
    "AZ-STG-001",
}
BASE = """
id: AZ-TST-001
title: Test check
provider: azure
area: security
severity: low
source:
  type: resource_graph
  query: "resources | project id, name, resourceGroup, compliant = true"
why: w
fix: {summary: f}
"""
REMEDY = """
remedy:
  risk: low
  downtime: none
  before: Ask the owner.
  az: az thing delete -g {resourceGroup} -n {name}
  rollback: az thing create -g {resourceGroup} -n {name}
  verify: az thing show -g {resourceGroup} -n {name}
"""


def write(folder: Path, text: str) -> None:
    (folder / "check.yaml").write_text(text, encoding="utf-8")


@pytest.fixture(scope="module")
def scanned() -> ScanResult:
    fixtures = Path(__file__).parent / "fixtures" / "azure"
    provider = OfflineProvider("azure", fixtures)
    return run_scan(provider, load_checks("azure"), provider.list_scopes(), offline=True)


def remedy_dict(**changes: object) -> dict[str, object]:
    base: dict[str, object] = {
        "risk": "low",
        "downtime": "none",
        "before": "b",
        "az": "a",
        "rollback": "r",
        "verify": "v",
    }
    return {**base, **changes}


# ----------------------------------------------------------------------- the model


def test_remedy_accepts_a_full_block_and_an_unrendered_terraform_key() -> None:
    remedy = Remedy.model_validate(remedy_dict(terraform="# remove the resource"))
    assert remedy.risk is RemedyRisk.LOW
    assert remedy.downtime is Downtime.NONE
    assert remedy.terraform == "# remove the resource"


@pytest.mark.parametrize(
    "change",
    [{"risk": "tiny"}, {"downtime": "forever"}, {"az": ""}, {"surprise": 1}],
)
def test_remedy_rejects_bad_values_and_unknown_keys(change: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Remedy.model_validate(remedy_dict(**change))


def test_remedy_is_optional_on_a_check(tmp_path: Path) -> None:
    write(tmp_path, BASE)
    check = next(c for c in load_checks("azure", [tmp_path]) if c.id == "AZ-TST-001")
    assert check.remedy is None


# ----------------------------------------------------------------------- placeholders


def test_a_template_may_use_projected_columns(tmp_path: Path) -> None:
    write(tmp_path, BASE + REMEDY)
    check = next(c for c in load_checks("azure", [tmp_path]) if c.id == "AZ-TST-001")
    assert check.remedy is not None
    assert used_fields(check.remedy) == {"resourceGroup", "name"}


def test_a_template_using_a_field_the_query_does_not_project_is_rejected(tmp_path: Path) -> None:
    write(tmp_path, BASE + REMEDY.replace("{name}-x", "").replace("show -g", "show -l {region} -g"))
    with pytest.raises(CheckLoadError, match=r"\{region\} not projected"):
        load_checks("azure", [tmp_path])


def test_the_compliance_column_is_not_a_usable_field(tmp_path: Path) -> None:
    write(tmp_path, BASE + REMEDY.replace("Ask the owner.", "Value is {compliant}."))
    with pytest.raises(CheckLoadError, match=r"\{compliant\}"):
        load_checks("azure", [tmp_path])


def test_the_subscription_comes_from_the_id() -> None:
    assert subscription_of("/subscriptions/abc-1/resourceGroups/rg") == "abc-1"
    assert subscription_of("/not/an/id") is None


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("resources | project id, name, a, b = tostring(x.y)", {"id", "name", "a", "b"}),
        ("resources\n// note, with comma\n| project id, c = case(x, 1, 2)", {"id", "c"}),
        ("resources | project id, tostring(x)", None),  # unnamed expression
        ("resources | project id, properties.x", None),
        ("resources | where a == 'x|y'", None),
        ("resources | project-away foo", None),
    ],
)
def test_projected_columns_reads_only_what_it_can_be_sure_of(
    query: str, expected: set[str] | None
) -> None:
    assert projected_columns(query) == expected


def test_placeholders_ignore_shell_and_query_braces() -> None:
    text = 'echo "$x" {a} {b_1} --query "{k:v,w:z}" ${HOME}'
    assert placeholders(text) == {"a", "b_1", "HOME"}


def test_every_remedy_renders_for_every_failing_fixture_resource(scanned: ScanResult) -> None:
    """A template may only use fields the check's own fixture evidence provides."""
    checks = {check.id: check for check in load_checks("azure")}
    with_remedy = {check_id for check_id, check in checks.items() if check.remedy}
    assert with_remedy == REMEDY_CHECKS
    for finding in scanned.findings:
        remedy = checks[finding.check_id].remedy
        if remedy is None:
            continue
        for resource in finding.resources:
            values = resource_values(resource)
            assert used_fields(remedy) <= set(values) | ALWAYS, finding.check_id
            for template in (remedy.before, remedy.az, remedy.rollback, remedy.verify):
                rendered = render(template, values)
                assert "{resourceGroup}" not in rendered
                assert "{name}" not in rendered
    failing = {finding.check_id for finding in scanned.findings}
    assert failing >= REMEDY_CHECKS, "each remedy check needs a failing fixture row"


def test_render_quotes_unsafe_values_and_joins_lists() -> None:
    values: dict[str, JsonValue] = {
        "name": "a b; rm -rf /",
        "rules": ["r1", "r 2"],
        "n": 3,
        "flag": True,
    }
    assert render("x {name}", values) == "x 'a b; rm -rf /'"
    assert render("{rules}", values) == "r1 'r 2'"
    assert render("{n} {flag}", values) == "3 true"


@pytest.mark.parametrize("values", [{}, {"name": None}, {"name": ""}, {"name": []}, {"name": {}}])
def test_render_refuses_a_missing_or_empty_field(values: dict[str, JsonValue]) -> None:
    with pytest.raises(RemedyError):
        render("{name}", values)


def test_builtin_checks_are_all_still_valid(scanned: ScanResult) -> None:
    assert isinstance(load_checks("azure")[0], Check)
    assert scanned.findings
