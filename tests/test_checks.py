from __future__ import annotations

import re
from pathlib import Path

import pytest

from skyveda.core.checks import builtin_providers, load_checks
from skyveda.core.errors import CheckLoadError

VALID = """
id: AZ-TST-001
title: Test check
provider: azure
area: security
severity: low
source: {type: resource_graph, query: resources}
why: w
fix: {summary: f}
"""


def write(folder: Path, name: str, text: str) -> None:
    (folder / name).write_text(text, encoding="utf-8")


def test_builtin_azure_checks_load_and_are_sorted() -> None:
    ids = [check.id for check in load_checks("azure")]
    assert ids == sorted(ids)
    assert len(ids) == 60
    assert sum(1 for i in ids if i.startswith("AZ-COST-")) == 8


def test_builtin_providers_include_azure() -> None:
    assert "azure" in builtin_providers()


def test_extra_directory_adds_checks(tmp_path: Path) -> None:
    write(tmp_path, "extra.yaml", VALID)
    assert "AZ-TST-001" in {check.id for check in load_checks("azure", [tmp_path])}


def test_every_problem_is_reported_with_its_file(tmp_path: Path) -> None:
    write(tmp_path, "bad-yaml.yaml", "id: [unclosed")
    write(tmp_path, "bad-field.yaml", VALID.replace("severity: low", "severity: urgent"))
    with pytest.raises(CheckLoadError) as caught:
        load_checks("azure", [tmp_path])
    message = str(caught.value)
    assert "2 problem(s)" in message
    assert "bad-yaml.yaml" in message
    assert "bad-field.yaml" in message


def test_duplicate_ids_are_rejected(tmp_path: Path) -> None:
    write(tmp_path, "dup.yaml", VALID.replace("AZ-TST-001", "AZ-NET-001"))
    with pytest.raises(CheckLoadError, match="duplicate check id AZ-NET-001"):
        load_checks("azure", [tmp_path])


def test_untrusted_python_evaluator_is_rejected(tmp_path: Path) -> None:
    write(tmp_path, "evil.yaml", VALID + "evaluate: {type: python, function: os.path.exists}\n")
    with pytest.raises(CheckLoadError, match="outside the skyveda package"):
        load_checks("azure", [tmp_path])


def test_missing_directory_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(CheckLoadError, match="not found"):
        load_checks("azure", [tmp_path / "missing"])


def test_resource_graph_queries_avoid_let_statements() -> None:
    """Resource Graph rejects `let` with a bare ParserFailure (found on the first live scan)."""
    offenders = [
        check.id
        for check in load_checks("azure")
        if check.source.type == "resource_graph"
        and re.search(r"(?m)^\s*let\s", check.source.query or "")
    ]
    assert offenders == []
