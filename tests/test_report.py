from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from skyveda.core.checks import load_checks
from skyveda.core.engine import run_scan
from skyveda.core.models import (
    AffectedResource,
    Area,
    CheckResult,
    Finding,
    Fix,
    ScanResult,
    Severity,
    Status,
)
from skyveda.core.offline import OfflineProvider
from skyveda.core.scoring import score
from skyveda.report import render_report

NOW = datetime(2026, 10, 17, tzinfo=UTC)


def result_of(*items: tuple[Area, Severity, Status]) -> ScanResult:
    results = []
    for n, (area, severity, status) in enumerate(items):
        finding = None
        if status is Status.FAIL:
            finding = Finding(
                check_id=f"AZ-T-{n:03d}",
                title="t",
                provider="azure",
                area=area,
                severity=severity,
                resources=[AffectedResource(id="/r")],
                why="w",
                fix=Fix(summary="f"),
            )
        results.append(
            CheckResult(
                check_id=f"AZ-T-{n:03d}",
                title="t",
                area=area,
                severity=severity,
                status=status,
                finding=finding,
            )
        )
    return ScanResult(
        tool_version="0",
        provider="azure",
        scopes=[],
        started_at=NOW,
        finished_at=NOW,
        results=results,
    )


def test_area_score_is_weighted_by_severity() -> None:
    scores = score(
        result_of(
            (Area.SECURITY, Severity.CRITICAL, Status.PASS),  # 10 earned
            (Area.SECURITY, Severity.HIGH, Status.FAIL),  # 5 lost
            (Area.SECURITY, Severity.LOW, Status.NOT_APPLICABLE),  # ignored
        )
    )
    assert scores.areas[0].score == 67  # 100 * 10 / 15
    assert scores.overall == 67


def test_overall_is_the_mean_of_areas_and_skips_unjudged_areas() -> None:
    scores = score(
        result_of(
            (Area.SECURITY, Severity.HIGH, Status.PASS),
            (Area.COST, Severity.HIGH, Status.FAIL),
            (Area.NETWORK, Severity.HIGH, Status.ERROR),
        )
    )
    assert [(a.area, a.score) for a in scores.areas] == [(Area.SECURITY, 100), (Area.COST, 0)]
    assert scores.overall == 50


def test_no_judged_checks_means_no_overall_score() -> None:
    assert score(result_of((Area.COST, Severity.LOW, Status.SKIPPED))).overall is None


@pytest.fixture
def offline_result(azure_fixtures: Path) -> ScanResult:
    provider = OfflineProvider("azure", azure_fixtures)
    return run_scan(
        provider, load_checks("azure"), provider.list_scopes(), offline=True, clock=lambda: NOW
    )


def test_report_shows_scores_findings_waste_and_hash(offline_result: ScanResult) -> None:
    text = offline_result.model_dump_json(indent=2)
    html = render_report(offline_result, text)
    assert "Failed: No SSH or RDP open to the Internet" in html
    assert "₹15,629" in html
    assert "Appendix A · Passed checks" in html
    assert hashlib.sha256(text.encode()).hexdigest() in html
    assert html.index("AZ-NET-001") < html.index("AZ-COST-001")  # critical before medium
    assert "Skyveda is not affiliated with or endorsed by Microsoft." in html
    assert "Want help fixing what this report found?" in html


def test_report_shows_an_escaped_label_only_when_given(offline_result: ScanResult) -> None:
    assert 'label-line"' not in render_report(offline_result, "{}")
    html = render_report(offline_result, "{}", label="Sample <b>report</b>")
    assert '<p class="label-line">Sample &lt;b&gt;report&lt;/b&gt;</p>' in html


def test_report_escapes_values_from_the_cloud(offline_result: ScanResult) -> None:
    hostile = '<script>alert("x")</script>'
    finding = offline_result.findings[0].model_copy(
        update={"resources": [AffectedResource(id="/r", name=hostile, evidence={"tag": hostile})]}
    )
    first = next(r for r in offline_result.results if r.finding is not None)
    patched = offline_result.model_copy(
        update={
            "results": [
                r.model_copy(update={"finding": finding}) if r is first else r
                for r in offline_result.results
            ]
        }
    )
    html = render_report(patched, "{}")
    assert hostile not in html
    assert "&lt;script&gt;" in html
