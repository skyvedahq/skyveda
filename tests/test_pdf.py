from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime
from io import BytesIO
from pathlib import Path

import pytest
from pypdf import PdfReader
from reportlab.platypus import LayoutError
from typer.testing import CliRunner

import skyveda.report.pdf as pdf_module
from skyveda.cli import app
from skyveda.core.checks import load_checks
from skyveda.core.engine import run_scan
from skyveda.core.models import AffectedResource, ScanResult, Waiver
from skyveda.core.offline import OfflineProvider
from skyveda.core.waivers import apply_waivers
from skyveda.report.pdf import MAX_RESOURCES, render_pdf

runner = CliRunner()
HOSTILE = '<b>bold</b> & <font size="40">big</font> <unclosed'


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


def text_of(pdf: bytes) -> str:
    return "\n".join(page.extract_text() for page in PdfReader(BytesIO(pdf)).pages)


def test_pdf_has_the_report_content_and_the_findings_hash(scanned: ScanResult) -> None:
    findings_json = scanned.model_dump_json(indent=2)
    pdf = render_pdf(scanned, findings_json, label="Prepared for cust-001")
    assert pdf.startswith(b"%PDF")

    text = text_of(pdf)
    digest = hashlib.sha256(findings_json.encode()).hexdigest()
    assert "Prepared for cust-001" in text
    assert "Failed: No SSH or RDP open to the Internet" in text
    assert "₹15,629" in text  # the rupee sign survives: the bundled font has the glyph
    assert digest in text.replace("\n", "")
    assert "not affiliated with or endorsed by Microsoft" in " ".join(text.split())
    assert "skyvedahq@gmail.com" in " ".join(text.split())
    metadata = PdfReader(BytesIO(pdf)).metadata
    assert metadata is not None
    assert metadata.subject == f"findings.json SHA-256: {digest}"


def test_untrusted_text_is_printed_literally_not_as_markup(scanned: ScanResult) -> None:
    finding = scanned.findings[0]
    patched_finding = finding.model_copy(
        update={"resources": [AffectedResource(id="/r", name=HOSTILE, evidence={"tag": HOSTILE})]}
    )
    first = next(r for r in scanned.results if r.check_id == finding.check_id)
    patched = scanned.model_copy(
        update={
            "results": [
                r.model_copy(update={"finding": patched_finding}) if r is first else r
                for r in scanned.results
            ]
        }
    )
    reason = Waiver(check="AZ-STG-001", reason=HOSTILE, approver="Lead", expires=date(2099, 1, 1))
    waived = apply_waivers(patched, [reason], date(2026, 11, 2)).result

    text = text_of(render_pdf(waived, "{}", label=HOSTILE)).replace("\n", " ")
    assert "<b>bold</b>" in text
    assert "<unclosed" in text


def test_long_resource_lists_are_capped_with_a_count(scanned: ScanResult) -> None:
    finding = scanned.findings[0]
    many = [AffectedResource(id=f"/r/{n}", name=f"res-{n:03d}") for n in range(MAX_RESOURCES + 5)]
    first = next(r for r in scanned.results if r.check_id == finding.check_id)
    patched = scanned.model_copy(
        update={
            "results": [
                r.model_copy(update={"finding": finding.model_copy(update={"resources": many})})
                if r is first
                else r
                for r in scanned.results
            ]
        }
    )
    text = text_of(render_pdf(patched, "{}"))
    assert f"res-{MAX_RESOURCES - 1:03d}" in text
    assert f"res-{MAX_RESOURCES:03d}" not in text
    assert "and 5 more resource(s), listed in findings.json" in text


def test_scan_and_report_write_a_pdf_only_when_asked(azure_fixtures: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    runner.invoke(app, ["scan", "--offline", str(azure_fixtures), "--out", str(out)])
    assert not (out / "report.pdf").exists()

    runner.invoke(app, ["scan", "--offline", str(azure_fixtures), "--out", str(out), "--pdf"])
    assert (out / "report.pdf").read_bytes().startswith(b"%PDF")

    again = tmp_path / "again"
    result = runner.invoke(
        app, ["report", str(out / "findings.json"), "--out", str(again), "--pdf"]
    )
    assert result.exit_code == 0, result.output
    assert (again / "report.pdf").is_file()


def test_config_can_turn_the_pdf_on(azure_fixtures: Path, tmp_path: Path) -> None:
    config = tmp_path / "skyveda.toml"
    config.write_text('[scan]\nout = "out"\npdf = true\n', encoding="utf-8")
    runner.invoke(app, ["scan", "--offline", str(azure_fixtures), "--config", str(config)])
    assert (tmp_path / "out" / "report.pdf").is_file()


def with_first_finding(result: ScanResult, **changes: object) -> ScanResult:
    finding = result.findings[0]
    first = next(r for r in result.results if r.check_id == finding.check_id)
    patched = finding.model_copy(update=changes)
    return result.model_copy(
        update={
            "results": [
                r.model_copy(update={"finding": patched}) if r is first else r
                for r in result.results
            ]
        }
    )


def test_hostile_check_ids_and_references_do_not_break_the_pdf(scanned: ScanResult) -> None:
    hostile = with_first_finding(
        scanned,
        check_id='A<b>"',
        references=['https://x" onclick="a', "javascript:alert(1)", "https://learn.microsoft.com/"],
    )
    text = text_of(render_pdf(hostile, "{}"))
    assert 'A<b>"' in text
    assert "javascript:alert(1)" in text  # printed, not linked


def test_oversized_values_are_cut_instead_of_failing_the_layout(scanned: ScanResult) -> None:
    huge = AffectedResource(
        id="/r/huge",
        name="huge",
        evidence={"blob": "x" * 20_000, "items": list(range(6_000))},
    )
    fix = scanned.findings[0].fix.model_copy(update={"cli": "\n".join(["az x"] * 400)})
    text = text_of(render_pdf(with_first_finding(scanned, resources=[huge], fix=fix), "{}"))
    assert "full value in findings.json" in text
    assert "360 more line(s) in findings.json" in text


def test_empty_results_render(scanned: ScanResult) -> None:
    empty = scanned.model_copy(update={"results": [], "scopes": []})
    text = text_of(render_pdf(empty, "{}"))
    assert "-/100" in text
    assert "No findings" in text


def test_a_pdf_failure_warns_and_keeps_the_scan_result(
    azure_fixtures: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_: object, **__: object) -> bytes:
        raise LayoutError("Flowable too large")

    monkeypatch.setattr(pdf_module, "render_pdf", broken)
    out = tmp_path / "out"
    result = runner.invoke(
        app, ["scan", "--offline", str(azure_fixtures), "--out", str(out), "--pdf"]
    )
    assert result.exit_code == 2  # the critical finding still decides the exit code
    assert "Could not lay out report.pdf" in result.output
    assert (out / "report.html").is_file()
    assert not (out / "report.pdf").exists()
