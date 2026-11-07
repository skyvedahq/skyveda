from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skyveda.cli import app
from skyveda.core.checks import load_checks
from skyveda.core.engine import run_scan
from skyveda.core.models import ScanResult
from skyveda.core.offline import OfflineProvider
from skyveda.report.fixpack import build_plan, safe_name, write_fix_pack

runner = CliRunner()
SUB_ID = "00000000-0000-0000-0000-000000000001"
OLD_DISK = (
    f"/subscriptions/{SUB_ID}/resourceGroups/rg-old/providers/Microsoft.Compute/disks/disk-old-vm"
)


@pytest.fixture
def findings_file(azure_fixtures: Path, tmp_path: Path) -> Path:
    provider = OfflineProvider("azure", azure_fixtures)
    result = run_scan(provider, load_checks("azure"), provider.list_scopes(), offline=True)
    path = tmp_path / "in" / "findings.json"
    path.parent.mkdir()
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return path


@pytest.fixture
def scanned(findings_file: Path) -> ScanResult:
    return ScanResult.model_validate_json(findings_file.read_text(encoding="utf-8"))


def run_fixes(findings: Path, out: Path, *extra: str) -> None:
    result = runner.invoke(app, ["fixes", str(findings), "--out", str(out), *extra])
    assert result.exit_code == 0, result.output


def edited(scanned: ScanResult, check_id: str, change: object) -> ScanResult:
    """A copy of the scan with ``change(finding_dict)`` applied to one check's finding."""
    data = json.loads(scanned.model_dump_json())
    for item in data["results"]:
        if item["check_id"] == check_id:
            change(item["finding"])  # type: ignore[operator]
    return ScanResult.model_validate(data)


def test_fixes_writes_readme_scripts_and_pull_request(findings_file: Path, tmp_path: Path) -> None:
    out = tmp_path / "fixes"
    run_fixes(findings_file, out)
    assert (out / "README.md").is_file()
    assert (out / "PULL_REQUEST.md").is_file()
    assert (out / "AZ-COST-001" / "disk-old-vm.sh").is_file()
    assert (out / "AZ-STG-001").is_dir()
    assert not (out / "AZ-ACR-001").exists()


def test_script_header_and_filled_commands(findings_file: Path, tmp_path: Path) -> None:
    run_fixes(findings_file, tmp_path / "fixes")
    text = (tmp_path / "fixes" / "AZ-COST-001" / "disk-old-vm.sh").read_text(encoding="utf-8")
    lines = text.splitlines()
    assert lines[0] == "#!/usr/bin/env bash"
    for header in ("# Risk: low", "# Downtime: none", "# Before you start:"):
        assert header in lines
    assert "# Rollback:" in lines
    assert "# Verify:" in lines
    assert "set -euo pipefail" in lines
    assert f"# az disk delete --subscription {SUB_ID} -g rg-old -n disk-old-vm --yes" in lines
    snapshot = f"# az snapshot create --subscription {SUB_ID} -g rg-old -n disk-old-vm-backup"
    assert any(line.startswith(snapshot) and line.endswith(OLD_DISK) for line in lines)
    assert "{subscriptionId}" not in text
    assert "{resourceGroup}" not in text


def test_every_command_in_every_script_is_commented_out(
    findings_file: Path, tmp_path: Path
) -> None:
    out = tmp_path / "fixes"
    run_fixes(findings_file, out)
    scripts = sorted(out.rglob("*.sh"))
    assert len(scripts) == 7
    for script in scripts:
        lines = script.read_text(encoding="utf-8").splitlines()
        body = [line for line in lines[lines.index("set -euo pipefail") + 1 :] if line.strip()]
        assert body, script
        assert all(line.startswith("# ") for line in body), script
        live = [line for line in lines if line and not line.startswith("#")]
        assert live == ["set -euo pipefail"], script


def test_net_001_script_loops_over_the_exposed_rule_names(
    findings_file: Path, tmp_path: Path
) -> None:
    run_fixes(findings_file, tmp_path / "fixes")
    text = (tmp_path / "fixes" / "AZ-NET-001" / "nsg-jump.sh").read_text(encoding="utf-8")
    assert "# for rule in allow-ssh-any; do" in text
    assert "--nsg-name nsg-jump" in text
    assert "<ALLOWED_CIDR>" in text  # the range is the client's choice, never invented


def test_readme_orders_by_severity_then_rupees_high_to_low(
    findings_file: Path, tmp_path: Path
) -> None:
    run_fixes(findings_file, tmp_path / "fixes")
    readme = (tmp_path / "fixes" / "README.md").read_text(encoding="utf-8")
    rows = [line for line in readme.splitlines() if line.startswith("| ") and "](" in line]
    cells = [[cell.strip() for cell in row.split("|")] for row in rows]
    assert [f"{c[3]}/{c[4]}" for c in cells] == [
        "AZ-NET-001/nsg-jump",  # critical
        "AZ-STG-001/stwebassets",  # high
        "AZ-COST-001/disk-old-vm",  # medium, 3,328
        "AZ-COST-001/disk-scratch",  # medium, 896
        "AZ-COST-003/vm-batch",  # medium, no figure
        "AZ-COST-004/snap-before-upgrade",  # low, 563
        "AZ-COST-002/pip-old",  # low, 320
    ]
    assert cells[0][5:7] == ["medium", "none"]
    assert "3,328" in cells[2][7]
    assert "(AZ-COST-001/disk-old-vm.sh)" in cells[2][8]


def test_readme_lists_checks_without_a_remedy_as_manual(
    findings_file: Path, tmp_path: Path
) -> None:
    run_fixes(findings_file, tmp_path / "fixes")
    readme = (tmp_path / "fixes" / "README.md").read_text(encoding="utf-8")
    manual = readme.split("## Manual fix: see report")[1]
    assert "AZ-ACR-001" in manual
    assert "AZ-COST-001" not in manual


def test_waived_resources_get_no_script(findings_file: Path, tmp_path: Path) -> None:
    waivers = tmp_path / "waivers.yaml"
    waivers.write_text(
        "schema_version: 1\nwaivers:\n"
        "  - check: AZ-COST-001\n"
        f"    resource: {OLD_DISK}\n"
        "    reason: Kept for audit\n"
        "    approver: Lead\n"
        "    expires: 2999-01-01\n"
        "  - check: AZ-STG-001\n"
        "    reason: Public site\n"
        "    approver: Lead\n"
        "    expires: 2999-01-01\n",
        encoding="utf-8",
    )
    out = tmp_path / "fixes"
    run_fixes(findings_file, out, "--waivers", str(waivers))
    assert not (out / "AZ-COST-001" / "disk-old-vm.sh").exists()
    assert (out / "AZ-COST-001" / "disk-scratch.sh").is_file()
    assert not (out / "AZ-STG-001").exists()
    assert "disk-old-vm" not in (out / "README.md").read_text(encoding="utf-8")


def test_input_findings_are_never_changed(findings_file: Path, tmp_path: Path) -> None:
    before = findings_file.read_bytes()
    run_fixes(findings_file, tmp_path / "fixes")
    assert findings_file.read_bytes() == before


def test_pull_request_summarises_changes_and_risks(findings_file: Path, tmp_path: Path) -> None:
    run_fixes(findings_file, tmp_path / "fixes")
    text = (tmp_path / "fixes" / "PULL_REQUEST.md").read_text(encoding="utf-8")
    assert "Draft, needs review" in text
    assert "7 resource(s) across 6 check(s)" in text
    assert "**AZ-COST-001**" in text
    assert "Highest risk in this change: medium." in text
    assert "AZ-NET-001 nsg-jump" in text


@pytest.mark.parametrize(
    ("raw", "safe"),
    [
        ("disk-old_vm.1", "disk-old_vm.1"),
        ("../../etc/passwd", "etc_passwd"),
        ("a b/c\\d:e*f", "a_b_c_d_e_f"),
        ("..", "resource"),
        ("", "resource"),
        ("CON", "_CON"),
        ("x" * 300, "x" * 80),
    ],
)
def test_safe_name_removes_anything_that_could_leave_the_folder(raw: str, safe: str) -> None:
    assert safe_name(raw) == safe


def test_hostile_names_stay_inside_the_output_folder(scanned: ScanResult, tmp_path: Path) -> None:
    def hostile(finding: dict[str, list[dict[str, str]]]) -> None:
        first = finding["resources"][0]
        first["name"] = "../../outside"
        finding["resources"].append({**first, "id": first["id"] + "2"})

    out = tmp_path / "a" / "fixes"
    write_fix_pack(edited(scanned, "AZ-COST-002", hostile), load_checks("azure"), out)
    scripts = sorted(path.name for path in (out / "AZ-COST-002").glob("*.sh"))
    assert len(scripts) == 2  # same safe name twice: the second gets an id hash suffix
    assert all(name.startswith("outside") for name in scripts)
    assert [path.name for path in (tmp_path / "a").iterdir()] == ["fixes"]


def test_a_resource_missing_a_needed_field_goes_to_manual(scanned: ScanResult) -> None:
    def drop(finding: dict[str, list[dict[str, dict[str, str]]]]) -> None:
        finding["resources"][0]["evidence"].pop("resourceGroup")

    plan = build_plan(edited(scanned, "AZ-COST-002", drop), load_checks("azure"))
    assert all(item.check.id != "AZ-COST-002" for item in plan.items)
    assert any(item.check_id == "AZ-COST-002" for item in plan.manual)


def test_fixes_rejects_a_file_that_is_not_findings(tmp_path: Path) -> None:
    bogus = tmp_path / "x.json"
    bogus.write_text('{"hello": 1}', encoding="utf-8")
    assert runner.invoke(app, ["fixes", str(bogus), "--out", str(tmp_path / "o")]).exit_code == 1


def test_before_text_never_splits_a_resource_name() -> None:
    from skyveda.report.fixpack import _wrapped

    name = "nsg-skyveda-flawlab-lab-cin-001"
    lines = _wrapped(("word " * 12) + f"--nsg-name {name} and more text after it " * 3)
    assert any(name in line for line in lines)
    assert all(not line.rstrip().endswith("-") for line in lines)
