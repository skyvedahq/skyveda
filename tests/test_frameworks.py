from __future__ import annotations

import csv
import re
from html import unescape
from io import BytesIO
from pathlib import Path

import pytest
from pypdf import PdfReader

from skyveda.core.checks import load_checks
from skyveda.core.engine import run_scan
from skyveda.core.errors import CheckLoadError
from skyveda.core.models import ScanResult, framework_problem
from skyveda.core.offline import OfflineProvider
from skyveda.report import render_report
from skyveda.report.pdf import render_pdf
from skyveda.report.summary import FRAMEWORK_NOTE, maps_to, summarise

from .test_checks import VALID, write

REQUIRED_NOTE = (
    "MCSB control IDs are from the Microsoft cloud security benchmark v2 (preview); the same IDs "
    "exist in v1, the default in Microsoft Defender for Cloud. Well-Architected IDs are Skyveda's "
    "mapping to Microsoft's published checklists. Skyveda maps to these frameworks; it does not "
    "certify compliance."
)

EXPECTED = Path(__file__).parent / "fixtures" / "framework_mapping.csv"
BASE = {"waf_pillar": ["Security"]}


def _split(cell: str) -> list[str]:
    return [item for item in cell.split(";") if item]


def test_all_60_checks_match_the_verified_mapping() -> None:
    rows = list(csv.DictReader(EXPECTED.open(encoding="utf-8", newline="")))
    expected = {
        row["check_id"]: {
            key: value
            for key, value in {
                "mcsb": _split(row["mcsb_controls"]),
                "waf_pillar": _split(row["waf_pillar"]),
                "waf": _split(row["waf_recommendations"]),
            }.items()
            if value
        }
        for row in rows
    }
    actual = {check.id: check.frameworks for check in load_checks("azure")}
    assert len(expected) == 60
    assert actual == expected


@pytest.mark.parametrize(
    "frameworks",
    [
        {},
        BASE,
        {"mcsb": ["NS-2", "AI-1"], "waf_pillar": ["Reliability", "Security"], "waf": ["SE:06"]},
    ],
)
def test_valid_framework_blocks(frameworks: dict[str, list[str]]) -> None:
    assert framework_problem(frameworks) is None


@pytest.mark.parametrize(
    ("frameworks", "message"),
    [
        ({"mcsb": ["NS-1"]}, "waf_pillar is required"),
        ({"waf_pillar": ["Sustainability"]}, "unknown pillar"),
        ({**BASE, "mcsb": ["XX-1"]}, "bad MCSB"),
        ({**BASE, "mcsb": ["NS-"]}, "bad MCSB"),
        ({**BASE, "waf": ["SE:6"]}, "bad Well-Architected"),
        ({**BASE, "waf": ["RE:01"]}, "not in the pillar"),
        ({**BASE, "cis": ["1.1"]}, "unknown key"),
    ],
)
def test_invalid_framework_blocks(frameworks: dict[str, list[str]], message: str) -> None:
    assert message in (framework_problem(frameworks) or "")


def test_loading_rejects_a_bad_framework_id(tmp_path: Path) -> None:
    bad = VALID + "frameworks:\n  waf_pillar: [Security]\n  mcsb: [NS-x]\n"
    write(tmp_path, "bad.yaml", bad)
    with pytest.raises(CheckLoadError, match="bad MCSB control ID"):
        load_checks("azure", [tmp_path])


def test_maps_to_line() -> None:
    assert maps_to({}) is None
    assert (
        maps_to({"mcsb": ["NS-1"], "waf_pillar": ["Security"], "waf": ["SE:06"]})
        == "MCSB NS-1 · WAF SE:06 (Security)"
    )
    assert maps_to({"waf_pillar": ["Cost Optimization"]}) == "WAF pillar Cost Optimization"


@pytest.fixture
def scanned(azure_fixtures: Path) -> ScanResult:
    provider = OfflineProvider("azure", azure_fixtures)
    return run_scan(provider, load_checks("azure"), provider.list_scopes(), offline=True)


def test_findings_json_carries_frameworks_and_round_trips(scanned: ScanResult) -> None:
    again = ScanResult.model_validate_json(scanned.model_dump_json())
    assert scanned.findings
    assert all("waf_pillar" in f.frameworks for f in again.findings)
    assert all(r.frameworks for r in again.results)


def test_summary_counts_match_the_results(scanned: ScanResult) -> None:
    data = summarise(scanned, "{}")
    judged = [r for r in scanned.results if r.status.value in ("pass", "fail")]
    for row in data.pillar_summary:
        in_pillar = [r for r in judged if row.label in r.frameworks["waf_pillar"]]
        assert row.passed + row.failed == len(in_pillar)
        assert row.failed == sum(r.status.value == "fail" for r in in_pillar)
    assert [r.label for r in data.mcsb_summary] == sorted(
        (r.label for r in data.mcsb_summary), key=lambda c: (c.split("-")[0], int(c.split("-")[1]))
    )


def test_html_report_shows_mapping_summary_and_note(scanned: ScanResult) -> None:
    html = render_report(scanned, "{}")
    text = unescape(re.sub(r"<[^>]+>", " ", html))
    assert "Framework summary" in html
    assert re.search(r"Maps to: MCSB [A-Z]{2}-\d+", text)
    assert FRAMEWORK_NOTE in text
    assert FRAMEWORK_NOTE == REQUIRED_NOTE  # the exact wording from D-037


def test_pdf_report_shows_mapping_summary_and_note(scanned: ScanResult) -> None:
    pdf = render_pdf(scanned, "{}")
    text = " ".join(" ".join(p.extract_text().split()) for p in PdfReader(BytesIO(pdf)).pages)
    assert "Framework summary" in text
    assert "Maps to: MCSB" in text
    assert "does not certify compliance." in text


def test_pdf_survives_markup_in_framework_labels(scanned: ScanResult) -> None:
    """An edited findings.json can carry any text in frameworks; the PDF must still render."""
    from skyveda.report.pdf import render_pdf

    data = scanned.model_dump(mode="json")
    for result in data["results"]:
        result["frameworks"] = {"mcsb": ["<b>NS-1 & co"], "waf_pillar": ["Security"]}
    hostile = ScanResult.model_validate(data)
    assert render_pdf(hostile, "{}").startswith(b"%PDF")
