from __future__ import annotations

import json
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from skyveda.cli import app
from skyveda.core.checks import load_checks
from skyveda.core.engine import run_scan
from skyveda.core.errors import RemedyError
from skyveda.core.models import ScanResult
from skyveda.core.offline import OfflineProvider
from skyveda.core.remedy import projected_columns
from skyveda.report.fixpack import build_plan, write_fix_pack

runner = CliRunner()
REMEDY_CHECKS = [
    "AZ-COST-001",
    "AZ-COST-002",
    "AZ-COST-003",
    "AZ-COST-004",
    "AZ-NET-001",
    "AZ-STG-001",
]
UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")


@pytest.fixture(scope="module")
def scanned() -> ScanResult:
    provider = OfflineProvider("azure", Path(__file__).parent / "fixtures" / "azure")
    return run_scan(provider, load_checks("azure"), provider.list_scopes(), offline=True)


def edited(
    scanned: ScanResult, check_id: str, change: Callable[[dict[str, Any]], None]
) -> ScanResult:
    data = json.loads(scanned.model_dump_json())
    for item in data["results"]:
        if item["check_id"] == check_id:
            change(item["finding"])
    return ScanResult.model_validate(data)


def live_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip() and not line.startswith("#")]


PRINTABLE = "x $(x) 'q' \"d\" | [l](u) `c` <b> &amp; # more"
CONTROL = "x\nrm -rf /\r\x0b\x1c\u2028curl evil\u202e#"


def markdown_is_clean(out: Path) -> None:
    for name in ("README.md", "PULL_REQUEST.md"):
        for line in (out / name).read_text(encoding="utf-8").splitlines():
            assert not line.startswith(("rm ", "curl", "#!")), (name, line)
            assert not any(ord(c) < 32 or c in "\u2028\u202e" for c in line), (name, line)
    table = [
        ln
        for ln in (out / "README.md").read_text(encoding="utf-8").splitlines()
        if ln.startswith("| ")
    ]
    assert table
    assert {len(UNESCAPED_PIPE.findall(row)) for row in table} == {9}


@pytest.mark.parametrize("check_id", REMEDY_CHECKS)
def test_printable_hostile_names_get_their_own_safe_script(
    scanned: ScanResult, tmp_path: Path, check_id: str
) -> None:
    def hostile(finding: dict[str, Any]) -> None:
        first = finding["resources"][0]
        first["id"] += "/" + PRINTABLE
        first["name"] = PRINTABLE

    plan = build_plan(edited(scanned, check_id, hostile), load_checks("azure"))
    own = [i for i in plan.items if i.check.id == check_id and PRINTABLE in i.resource.id]
    assert len(own) == 1
    assert live_lines(own[0].text) == ["set -euo pipefail"]
    out = tmp_path / "fixes"
    write_fix_pack(edited(scanned, check_id, hostile), load_checks("azure"), out)
    assert (out / own[0].script).is_file()
    for script in out.rglob("*.sh"):
        assert live_lines(script.read_text(encoding="utf-8")) == ["set -euo pipefail"]
    markdown_is_clean(out)


@pytest.mark.parametrize("check_id", REMEDY_CHECKS)
@pytest.mark.parametrize("field", ["id", "name"])
def test_control_or_bidi_characters_send_the_resource_to_the_manual_list(
    scanned: ScanResult, tmp_path: Path, check_id: str, field: str
) -> None:
    def hostile(finding: dict[str, Any]) -> None:
        first = finding["resources"][0]
        first[field] = first[field] + CONTROL

    broken = edited(scanned, check_id, hostile)
    plan = build_plan(broken, load_checks("azure"))
    clean_ids = {r.id for f in scanned.findings if f.check_id == check_id for r in f.resources}
    kept = {i.resource.id for i in plan.items if i.check.id == check_id}
    assert len(kept) == len(clean_ids) - 1
    assert any(m.check_id == check_id for m in plan.manual)
    out = tmp_path / "fixes"
    write_fix_pack(broken, load_checks("azure"), out)
    for script in out.rglob("*.sh"):
        assert live_lines(script.read_text(encoding="utf-8")) == ["set -euo pipefail"]
    markdown_is_clean(out)


def test_hostile_net_001_rule_names_go_to_the_manual_list(scanned: ScanResult) -> None:
    def hostile(finding: dict[str, Any]) -> None:
        finding["resources"][0]["evidence"]["exposedRules"] = ["ok", CONTROL]

    plan = build_plan(edited(scanned, "AZ-NET-001", hostile), load_checks("azure"))
    assert all(i.check.id != "AZ-NET-001" for i in plan.items)
    assert any(m.check_id == "AZ-NET-001" for m in plan.manual)


def test_multi_rule_net_001_names_are_quoted(scanned: ScanResult, tmp_path: Path) -> None:
    def rules(finding: dict[str, Any]) -> None:
        finding["resources"][0]["evidence"]["exposedRules"] = ["r 2", "$(x)", "ok"]

    plan = build_plan(edited(scanned, "AZ-NET-001", rules), load_checks("azure"))
    (item,) = (i for i in plan.items if i.check.id == "AZ-NET-001")
    assert "# for rule in 'r 2' '$(x)' ok; do" in item.text
    assert "'*'" in item.text


def test_values_that_look_like_options_go_to_the_manual_list(scanned: ScanResult) -> None:
    def dash(finding: dict[str, Any]) -> None:
        finding["resources"][0]["name"] = "--yes"

    plan = build_plan(edited(scanned, "AZ-COST-002", dash), load_checks("azure"))
    assert all(item.check.id != "AZ-COST-002" for item in plan.items)
    assert any(item.check_id == "AZ-COST-002" for item in plan.manual)


def test_windows_reserved_name_gets_a_safe_script_name(scanned: ScanResult) -> None:
    def reserved(finding: dict[str, Any]) -> None:
        finding["resources"][0]["name"] = "CON"

    plan = build_plan(edited(scanned, "AZ-COST-002", reserved), load_checks("azure"))
    assert [i.script for i in plan.items if i.check.id == "AZ-COST-002"] == ["AZ-COST-002/_CON.sh"]


def test_names_differing_only_in_case_get_distinct_scripts(scanned: ScanResult) -> None:
    def cases(finding: dict[str, Any]) -> None:
        first = finding["resources"][0]
        finding["resources"] = [
            {**first, "name": "Pip-A", "id": first["id"] + "A"},
            {**first, "name": "pip-a", "id": first["id"] + "B"},
        ]

    plan = build_plan(edited(scanned, "AZ-COST-002", cases), load_checks("azure"))
    scripts = [i.script for i in plan.items if i.check.id == "AZ-COST-002"]
    assert len({s.lower() for s in scripts}) == 2


def test_equal_severity_and_rupees_order_by_check_then_script(scanned: ScanResult) -> None:
    def tie(finding: dict[str, Any]) -> None:
        for resource in finding["resources"]:
            resource["est_monthly_waste_inr"] = 500.0

    plan = build_plan(edited(scanned, "AZ-COST-001", tie), load_checks("azure"))
    scripts = [i.script for i in plan.items if i.check.id == "AZ-COST-001"]
    assert scripts == sorted(scripts)
    again = build_plan(edited(scanned, "AZ-COST-001", tie), load_checks("azure"))
    assert [i.script for i in again.items] == [i.script for i in plan.items]


def test_duplicate_resources_appear_once(scanned: ScanResult) -> None:
    def dup(finding: dict[str, Any]) -> None:
        first = finding["resources"][0]
        finding["resources"].append({**first, "id": first["id"].upper()})

    plan = build_plan(edited(scanned, "AZ-COST-002", dup), load_checks("azure"))
    assert len([i for i in plan.items if i.check.id == "AZ-COST-002"]) == 1


def test_symlinked_check_folder_cannot_escape(scanned: ScanResult, tmp_path: Path) -> None:
    out = tmp_path / "fixes"
    outside = tmp_path / "outside"
    outside.mkdir()
    out.mkdir()
    try:
        (out / "AZ-COST-001").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks cannot be created here")
    with pytest.raises(RemedyError, match="outside"):
        write_fix_pack(scanned, load_checks("azure"), out, force=True)
    assert list(outside.iterdir()) == []
    assert not (out / "README.md").exists()  # paths are validated before anything is written


def test_non_empty_output_needs_force_and_force_removes_only_old_pack_files(
    scanned: ScanResult, tmp_path: Path
) -> None:
    out = tmp_path / "fixes"
    checks = load_checks("azure")
    write_fix_pack(scanned, checks, out)
    (out / "AZ-COST-001" / "stale.sh").write_text(
        "#!/usr/bin/env bash\n# Skyveda fix for AZ-COST-001: old\n", encoding="utf-8"
    )
    (out / "AZ-COST-001" / "notes.txt").write_text("mine", encoding="utf-8")
    (out / "keep.txt").write_text("mine", encoding="utf-8")
    with pytest.raises(RemedyError, match="--force"):
        write_fix_pack(scanned, checks, out)
    assert (out / "AZ-COST-001" / "stale.sh").exists()
    write_fix_pack(scanned, checks, out, force=True)
    assert not (out / "AZ-COST-001" / "stale.sh").exists()
    assert (out / "AZ-COST-001" / "notes.txt").read_text(encoding="utf-8") == "mine"
    assert (out / "keep.txt").exists()
    assert (out / "README.md").is_file()


def test_cli_refuses_a_non_empty_folder_without_force(scanned: ScanResult, tmp_path: Path) -> None:
    findings = tmp_path / "findings.json"
    findings.write_text(scanned.model_dump_json(), encoding="utf-8")
    out = tmp_path / "fixes"
    out.mkdir()
    (out / "something.txt").write_text("x", encoding="utf-8")
    refused = runner.invoke(app, ["fixes", str(findings), "--out", str(out)])
    assert refused.exit_code == 1
    assert "--force" in refused.output
    assert "Traceback" not in refused.output
    forced = runner.invoke(app, ["fixes", str(findings), "--out", str(out), "--force"])
    assert forced.exit_code == 0, forced.output


def test_write_errors_become_a_clean_error(scanned: ScanResult, tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    with pytest.raises(RemedyError):
        write_fix_pack(scanned, load_checks("azure"), blocker / "sub")
    findings = tmp_path / "findings.json"
    findings.write_text(scanned.model_dump_json(), encoding="utf-8")
    result = runner.invoke(app, ["fixes", str(findings), "--out", str(blocker / "sub")])
    assert result.exit_code == 1
    assert "Traceback" not in result.output


def test_waivers_end_to_end_through_the_cli(scanned: ScanResult, tmp_path: Path) -> None:
    findings = tmp_path / "findings.json"
    findings.write_text(scanned.model_dump_json(), encoding="utf-8")
    waivers = tmp_path / "waivers.yaml"
    waivers.write_text(
        "schema_version: 1\nwaivers:\n  - check: AZ-NET-001\n    reason: Vendor\n"
        "    approver: Lead\n    expires: 2999-01-01\n",
        encoding="utf-8",
    )
    out = tmp_path / "fixes"
    result = runner.invoke(
        app, ["fixes", str(findings), "--out", str(out), "--waivers", str(waivers)]
    )
    assert result.exit_code == 0, result.output
    assert "Waivers: 1 resource(s) waived" in result.output
    assert not (out / "AZ-NET-001").exists()
    assert "AZ-NET-001" not in (out / "README.md").read_text(encoding="utf-8").split("## Manual")[0]


def test_comment_stripping_ignores_slashes_inside_strings() -> None:
    query = (
        "resources\n| where url == 'https://x//y' // trailing note, with comma\n| project id, name"
    )
    assert projected_columns(query) == {"id", "name"}
    quoted = "resources | project id, name, u = iff(true, 'https://x//y', \"a//b\")"
    assert projected_columns(quoted) == {"id", "name", "u"}


def test_junctioned_check_folder_is_not_entered_by_force(
    scanned: ScanResult, tmp_path: Path
) -> None:
    if sys.platform != "win32":
        pytest.skip("junctions are a Windows feature")
    out = tmp_path / "fixes"
    outside = tmp_path / "outside"
    outside.mkdir()
    out.mkdir()
    victim = outside / "a.sh"
    victim.write_text("#!/usr/bin/env bash\n# Skyveda fix for AZ-COST-001: x\n", encoding="utf-8")
    link = out / "AZ-COST-001"
    made = subprocess.run(  # noqa: S603 - test only, fixed arguments
        ["cmd", "/c", "mklink", "/J", str(link), str(outside)],  # noqa: S607
        capture_output=True,
        check=False,
    )
    if made.returncode != 0:
        pytest.skip("cannot create a junction here")
    with pytest.raises(RemedyError):
        write_fix_pack(scanned, load_checks("azure"), out, force=True)
    assert victim.exists()
    assert [p.name for p in outside.iterdir()] == ["a.sh"]


def test_force_refuses_to_delete_files_skyveda_did_not_write(
    scanned: ScanResult, tmp_path: Path
) -> None:
    out = tmp_path / "fixes"
    out.mkdir()
    (out / "README.md").write_text("my own notes\n", encoding="utf-8")
    with pytest.raises(RemedyError, match="did not write"):
        write_fix_pack(scanned, load_checks("azure"), out, force=True)
    assert (out / "README.md").read_text(encoding="utf-8") == "my own notes\n"
    (out / "README.md").unlink()
    (out / "AZ-COST-001").mkdir()
    (out / "AZ-COST-001" / "mine.sh").write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    with pytest.raises(RemedyError, match="did not write"):
        write_fix_pack(scanned, load_checks("azure"), out, force=True)
    assert (out / "AZ-COST-001" / "mine.sh").exists()
    assert not (out / "README.md").exists()


def test_cli_reports_a_foreign_readme_cleanly(scanned: ScanResult, tmp_path: Path) -> None:
    findings = tmp_path / "findings.json"
    findings.write_text(scanned.model_dump_json(), encoding="utf-8")
    out = tmp_path / "fixes"
    out.mkdir()
    (out / "README.md").write_text("mine\n", encoding="utf-8")
    result = runner.invoke(app, ["fixes", str(findings), "--out", str(out), "--force"])
    assert result.exit_code == 1
    assert "did not write" in result.output
    assert "Traceback" not in result.output
    assert (out / "README.md").read_text(encoding="utf-8") == "mine\n"
