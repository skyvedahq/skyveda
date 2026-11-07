from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skyveda.cli import app
from skyveda.core.checks import load_checks
from skyveda.core.engine import run_scan
from skyveda.core.errors import WaiverApplyError, WaiverLoadError
from skyveda.core.models import CheckResult, ScanResult, Severity, Status, Waiver, WaiverKind
from skyveda.core.offline import OfflineProvider
from skyveda.core.scoring import score
from skyveda.core.waivers import apply_waivers, load_waivers
from skyveda.report import render_report

TODAY = date(2026, 11, 2)
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups"
OLD_DISK = f"{SUB}/rg-old/providers/Microsoft.Compute/disks/disk-old-vm"
runner = CliRunner()


@pytest.fixture
def scanned(azure_fixtures: Path) -> ScanResult:
    provider = OfflineProvider("azure", azure_fixtures)
    return run_scan(
        provider,
        load_checks("azure"),
        provider.list_scopes(),
        offline=True,
        clock=lambda: datetime(2026, 11, 2, tzinfo=UTC),
    )


def waiver(check: str, resource: str | None = None, expires: date = date(2027, 3, 31)) -> Waiver:
    return Waiver(
        check=check, resource=resource, reason="Agreed on call", approver="Lead", expires=expires
    )


def result_for(result: ScanResult, check_id: str) -> CheckResult:
    return next(item for item in result.results if item.check_id == check_id)


def test_load_waivers_reads_a_valid_file(tmp_path: Path) -> None:
    path = tmp_path / "waivers.yaml"
    path.write_text(
        "schema_version: 1\n"
        "waivers:\n"
        "  - check: AZ-NET-001\n"
        "    kind: false_positive\n"
        "    reason: Rule is shadowed by a deny at the firewall\n"
        "    approver: Platform lead\n"
        "    expires: 2027-03-31\n",
        encoding="utf-8",
    )
    (loaded,) = load_waivers(path)
    assert loaded.kind is WaiverKind.FALSE_POSITIVE
    assert loaded.resource is None
    assert loaded.expires == date(2027, 3, 31)


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ("waivers:\n  - check: AZ-NET-001\n    approver: x\n    expires: 2027-01-01\n", "reason"),
        (
            "waivers:\n  - check: NET-1\n    reason: r\n    approver: x\n    expires: 2027-01-01\n",
            "check",
        ),
        ("waivers: [unclosed\n", "not valid YAML"),
    ],
)
def test_load_waivers_names_the_problem(tmp_path: Path, text: str, problem: str) -> None:
    path = tmp_path / "waivers.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(WaiverLoadError, match=problem):
        load_waivers(path)


def test_a_resource_waiver_trims_the_finding_and_its_waste(scanned: ScanResult) -> None:
    before = result_for(scanned, "AZ-COST-001").finding
    assert before is not None
    assert before.est_monthly_waste_inr == 4224

    outcome = apply_waivers(scanned, [waiver("AZ-COST-001", OLD_DISK.upper())], TODAY)

    after = result_for(outcome.result, "AZ-COST-001")
    assert after.status is Status.FAIL
    assert after.finding is not None
    assert [r.name for r in after.finding.resources] == ["disk-scratch"]
    assert after.finding.est_monthly_waste_inr == 896  # 4224 less the waived 3328
    assert [w.resource.name for w in after.waived] == ["disk-old-vm"]
    assert outcome.unused == ()
    assert outcome.expired == ()


def test_waiving_every_resource_passes_the_check_and_lifts_the_score(
    scanned: ScanResult,
) -> None:
    outcome = apply_waivers(scanned, [waiver("AZ-NET-001")], TODAY)

    net = result_for(outcome.result, "AZ-NET-001")
    assert net.status is Status.PASS
    assert net.finding is None
    assert len(net.waived) == 1
    assert "AZ-NET-001" not in [f.check_id for f in outcome.result.findings]
    assert outcome.result.has_findings_at_or_above(Severity.CRITICAL)  # the open SQL firewall
    assert score(outcome.result).overall > score(scanned).overall  # type: ignore[operator]


def test_expired_and_unmatched_waivers_are_reported_not_applied(scanned: ScanResult) -> None:
    expired = waiver("AZ-NET-001", expires=date(2026, 11, 1))
    unmatched = waiver("AZ-KV-001")  # the Key Vault check passes in the fixtures
    outcome = apply_waivers(scanned, [expired, unmatched], TODAY)

    assert result_for(outcome.result, "AZ-NET-001").status is Status.FAIL
    assert outcome.expired == (expired,)
    assert outcome.unused == (unmatched,)


def test_a_waiver_applies_on_its_expiry_date(scanned: ScanResult) -> None:
    outcome = apply_waivers(scanned, [waiver("AZ-NET-001", expires=TODAY)], TODAY)
    assert result_for(outcome.result, "AZ-NET-001").status is Status.PASS


def test_waived_results_round_trip_through_findings_json(scanned: ScanResult) -> None:
    waived = apply_waivers(scanned, [waiver("AZ-COST-001", OLD_DISK)], TODAY).result
    assert ScanResult.model_validate_json(waived.model_dump_json()) == waived


def test_report_lists_waivers_and_escapes_their_text(scanned: ScanResult) -> None:
    hostile = Waiver(
        check="AZ-NET-001", reason="<script>x</script>", approver="Lead", expires=date(2027, 1, 1)
    )
    html = render_report(apply_waivers(scanned, [hostile], TODAY).result, "{}")
    assert "Appendix D · Waived" in html
    assert "&lt;script&gt;x&lt;/script&gt;" in html
    assert "<script>x</script>" not in html


def write_waivers(path: Path) -> Path:
    path.write_text(
        "waivers:\n"
        "  - check: AZ-NET-001\n"
        "    reason: Jump host behind a vendor firewall\n"
        "    approver: Platform lead\n"
        "    expires: 2099-12-31\n"
        "  - check: AZ-SQL-002\n"
        "    reason: Temporary rule for a data migration\n"
        "    approver: Platform lead\n"
        "    expires: 2099-12-31\n",
        encoding="utf-8",
    )
    return path


def test_scan_with_waivers_drops_the_waived_critical(azure_fixtures: Path, tmp_path: Path) -> None:
    waivers = write_waivers(tmp_path / "waivers.yaml")
    args = ["scan", "--offline", str(azure_fixtures), "--out", str(tmp_path / "out")]
    assert runner.invoke(app, args).exit_code == 2
    result = runner.invoke(app, [*args, "--waivers", str(waivers)])
    assert result.exit_code == 0, result.output
    assert "2 resource(s) waived" in result.output


def test_report_applies_waivers_to_a_received_findings_json(
    azure_fixtures: Path, tmp_path: Path
) -> None:
    received = tmp_path / "received"
    runner.invoke(app, ["scan", "--offline", str(azure_fixtures), "--out", str(received)])
    original = (received / "findings.json").read_bytes()
    waivers = write_waivers(tmp_path / "waivers.yaml")
    findings = str(received / "findings.json")

    refused = runner.invoke(
        app, ["report", findings, "--waivers", str(waivers), "--out", str(received)]
    )
    assert refused.exit_code == 1
    assert (received / "findings.json").read_bytes() == original

    final = tmp_path / "final"
    done = runner.invoke(app, ["report", findings, "--waivers", str(waivers), "--out", str(final)])
    assert done.exit_code == 0, done.output
    waived = ScanResult.model_validate_json((final / "findings.json").read_text("utf-8"))
    assert result_for(waived, "AZ-NET-001").status is Status.PASS
    assert "Jump host behind a vendor firewall" in (final / "report.html").read_text("utf-8")
    assert (received / "findings.json").read_bytes() == original


def test_a_resource_waiver_wins_over_a_whole_check_waiver(scanned: ScanResult) -> None:
    broad = waiver("AZ-COST-001")
    specific = Waiver(
        check="AZ-COST-001",
        resource=OLD_DISK,
        reason="Kept for audit",
        approver="Finance",
        expires=date(2027, 3, 31),
    )
    outcome = apply_waivers(scanned, [broad, specific], TODAY)
    reasons = {
        w.resource.name: w.waiver.reason for w in result_for(outcome.result, "AZ-COST-001").waived
    }
    assert reasons == {"disk-old-vm": "Kept for audit", "disk-scratch": "Agreed on call"}
    assert outcome.unused == ()


def test_waivers_are_not_reapplied_to_a_waived_result(scanned: ScanResult) -> None:
    once = apply_waivers(scanned, [waiver("AZ-NET-001")], TODAY).result
    with pytest.raises(WaiverApplyError, match="already has waivers"):
        apply_waivers(once, [waiver("AZ-NET-001")], TODAY)


def test_waivers_refuse_a_findings_json_without_per_resource_waste(scanned: ScanResult) -> None:
    item = result_for(scanned, "AZ-COST-001")
    assert item.finding is not None
    legacy_resources = [
        r.model_copy(update={"est_monthly_waste_inr": None}) for r in item.finding.resources
    ]
    legacy = item.model_copy(
        update={"finding": item.finding.model_copy(update={"resources": legacy_resources})}
    )
    old = scanned.model_copy(
        update={"results": [legacy if r is item else r for r in scanned.results]}
    )
    with pytest.raises(WaiverApplyError, match="re-run the scan"):
        apply_waivers(old, [waiver("AZ-COST-001", OLD_DISK)], TODAY)
