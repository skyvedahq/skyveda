"""Render a self-contained report.html from a ScanResult.

The page has no external assets, so it can be emailed or opened offline. Every value from the
cloud is escaped by Jinja's autoescape: resource names and tags are untrusted data.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from skyveda.core.models import ScanResult
from skyveda.report.summary import (
    AREA_LABELS,
    FRAMEWORK_NOTE,
    HELP_NOTE,
    TRADEMARK_NOTE,
    finding_waste,
    maps_to,
    resource_cost,
    shown_evidence,
    summarise,
)

REPORT_FILE = "report.html"

_env = Environment(
    loader=PackageLoader("skyveda.report", "templates"),
    autoescape=select_autoescape(["html", "j2"]),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_report(result: ScanResult, findings_json: str, label: str | None = None) -> str:
    """Render the report; ``findings_json`` is hashed so the report can be matched to its data.

    ``label`` is shown under the title, e.g. who the report is for or that it is a sample.
    """
    data = summarise(result, findings_json, label)
    return _env.get_template("report.html.j2").render(
        result=result,
        label=label,
        scores=data.scores,
        findings=data.findings,
        waste=data.waste,
        waste_basis=data.waste_basis,
        cost_notes=data.cost_notes,
        trademark_note=TRADEMARK_NOTE,
        help_note=HELP_NOTE,
        framework_note=FRAMEWORK_NOTE,
        maps_to=maps_to,
        mcsb_summary=data.mcsb_summary,
        pillar_summary=data.pillar_summary,
        finding_waste=finding_waste,
        resource_cost=resource_cost,
        shown_evidence=shown_evidence,
        counts=data.counts,
        passed=data.passed,
        others=data.others,
        area_label=AREA_LABELS,
        findings_sha256=data.findings_sha256,
        waived=data.waived,
        waived_by_check=data.waived_by_check,
    )


def write_report(
    result: ScanResult, findings_json: str, out_dir: Path, label: str | None = None
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / REPORT_FILE
    path.write_text(render_report(result, findings_json, label), encoding="utf-8")
    return path
