from __future__ import annotations

import shutil
from pathlib import Path

from typer.testing import CliRunner

from skyveda import __version__
from skyveda.cli import ExitCode, app
from skyveda.core.provider import available_providers

runner = CliRunner()


def test_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("scan", "scopes", "list-checks", "report"):
        assert command in result.output


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_azure_provider_is_registered() -> None:
    assert "azure" in available_providers()


def test_scopes_offline(azure_fixtures: Path) -> None:
    result = runner.invoke(app, ["scopes", "--offline", str(azure_fixtures)])
    assert result.exit_code == 0, result.output
    assert "skyveda-lab-prod" in result.output


def test_offline_scan_writes_findings_and_exits_2_on_critical(
    azure_fixtures: Path, tmp_path: Path
) -> None:
    result = runner.invoke(app, ["scan", "--offline", str(azure_fixtures), "--out", str(tmp_path)])
    assert result.exit_code == 2, result.output
    assert (tmp_path / "findings.json").is_file()
    assert "AZ-NET-001" in result.output


def test_fail_on_threshold(azure_fixtures: Path, tmp_path: Path) -> None:
    fixtures = tmp_path / "fixtures"
    shutil.copytree(azure_fixtures, fixtures)
    for critical in ("AZ-NET-001", "AZ-SQL-002"):
        (fixtures / f"{critical}.json").write_text('{"rows": []}', encoding="utf-8")
    args = ["scan", "--offline", str(fixtures), "--out", str(tmp_path / "out")]
    assert runner.invoke(app, args).exit_code == 0  # only high/medium findings remain
    assert runner.invoke(app, [*args, "--fail-on", "high"]).exit_code == 2


def test_console_output_is_ascii_safe_for_legacy_windows_consoles(
    azure_fixtures: Path, tmp_path: Path
) -> None:
    result = runner.invoke(app, ["scan", "--offline", str(azure_fixtures), "--out", str(tmp_path)])
    assert "INR 15,629 a month" in result.output
    assert "₹" not in result.output  # Rich falls back to ASCII boxes; the rupee sign has none


def test_list_and_validate_checks() -> None:
    listed = runner.invoke(app, ["list-checks"])
    assert listed.exit_code == 0
    assert "AZ-STG-002" in listed.output
    validated = runner.invoke(app, ["validate-checks"])
    assert validated.exit_code == 0
    assert "valid" in validated.output


def test_unknown_provider_is_a_clean_error() -> None:
    result = runner.invoke(app, ["scopes", "--provider", "nimbus"])
    assert result.exit_code == ExitCode.ERROR
    assert "Unknown provider" in result.output


def test_invalid_subscription_is_a_clean_error() -> None:
    result = runner.invoke(app, ["scopes", "--subscription", "nope"])
    assert result.exit_code == ExitCode.ERROR
    assert "GUID expected" in result.output


def test_scan_writes_report_and_report_command_rerenders(
    azure_fixtures: Path, tmp_path: Path
) -> None:
    runner.invoke(app, ["scan", "--offline", str(azure_fixtures), "--out", str(tmp_path)])
    assert (tmp_path / "report.html").is_file()
    again = tmp_path / "again"
    result = runner.invoke(app, ["report", str(tmp_path / "findings.json"), "--out", str(again)])
    assert result.exit_code == 0, result.output
    assert (again / "report.html").read_text(encoding="utf-8").startswith("<!doctype html>")


def test_report_rejects_a_file_that_is_not_findings(tmp_path: Path) -> None:
    bogus = tmp_path / "x.json"
    bogus.write_text('{"hello": 1}', encoding="utf-8")
    assert runner.invoke(app, ["report", str(bogus), "--out", str(tmp_path)]).exit_code == 1


def test_demo_estate_runs_every_check_and_labels_the_report(tmp_path: Path) -> None:
    demo = Path(__file__).resolve().parents[1] / "demo" / "azure"
    args = ["scan", "--offline", str(demo), "--out", str(tmp_path), "--label", "Sample report"]
    result = runner.invoke(app, args)
    assert result.exit_code == 2  # the demo estate has a critical finding
    assert "pass: 18  fail: 42" in result.output  # every check judged; none missing or in error
    html = (tmp_path / "report.html").read_text("utf-8")
    assert '<p class="label-line">Sample report</p>' in html
