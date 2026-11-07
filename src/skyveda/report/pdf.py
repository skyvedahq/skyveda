"""Render report.pdf: the same content as report.html, laid out for A4 and for forwarding.

ReportLab paragraphs read a small XML markup, so every value from the cloud (resource names,
tags, evidence) and from a waivers file is XML-escaped before it reaches one. The ₹ sign needs
the bundled DejaVu Sans font; the built-in PDF fonts do not have it. The findings.json hash is
printed on the last page and stored in the document's metadata.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from io import BytesIO
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    Flowable,
    KeepTogether,
    LayoutError,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from skyveda.core.errors import ReportError
from skyveda.core.models import Finding, ScanResult, Severity, Status
from skyveda.report.summary import (
    AREA_LABELS,
    FRAMEWORK_NOTE,
    HELP_NOTE,
    TRADEMARK_NOTE,
    ReportData,
    finding_waste,
    maps_to,
    resource_cost,
    shown_evidence,
    summarise,
)

PDF_FILE = "report.pdf"
MAX_RESOURCES = 40
"""Affected resources listed per finding; the rest are counted and stay in findings.json."""
MAX_CELL_CHARS = 300
"""Longest value printed in one table cell; ReportLab cannot split a cell across pages."""
MAX_CODE_LINES = 40
KEEP_TOGETHER_RESOURCES = 8
"""Findings with this many resources or fewer are kept on one page with their table."""

_FONT_DIR = Path(__file__).parent / "fonts"
_SANS, _BOLD, _MONO = "SkyvedaSans", "SkyvedaSans-Bold", "Courier"

_INK = colors.HexColor("#15202b")
_MUTED = colors.HexColor("#5a6876")
_RULE = colors.HexColor("#d9e0e7")
_SOFT = colors.HexColor("#f4f6f8")
_ACCENT = colors.HexColor("#1f5f8b")
_SEVERITY_COLOUR = {
    Severity.CRITICAL: colors.HexColor("#b3261e"),
    Severity.HIGH: colors.HexColor("#b4532a"),
    Severity.MEDIUM: colors.HexColor("#9a6b00"),
    Severity.LOW: colors.HexColor("#55607a"),
}


def _register_fonts() -> None:
    if _SANS not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(_SANS, str(_FONT_DIR / "DejaVuSans.ttf")))
        pdfmetrics.registerFont(TTFont(_BOLD, str(_FONT_DIR / "DejaVuSans-Bold.ttf")))
        pdfmetrics.registerFontFamily(_SANS, normal=_SANS, bold=_BOLD)


def _style(name: str, size: float, **extra: Any) -> ParagraphStyle:
    base: dict[str, Any] = {
        "fontName": _SANS,
        "fontSize": size,
        "leading": size * 1.35,
        "textColor": _INK,
        "alignment": TA_LEFT,
    }
    return ParagraphStyle(name, **(base | extra))


_TITLE = _style("title", 20, fontName=_BOLD, spaceAfter=4)
_H2 = _style("h2", 13, fontName=_BOLD, spaceBefore=12, spaceAfter=6)
_H3 = _style("h3", 10.5, fontName=_BOLD)
_BODY = _style("body", 9, spaceAfter=3)
_META = _style("meta", 8, textColor=_MUTED, spaceAfter=2)
_SMALL = _style("small", 7.5)
_CODE = _style("code", 7.5, fontName=_MONO)
_LABEL = _style("label", 9.5, fontName=_BOLD, textColor=_ACCENT, spaceAfter=4)
_BIG = _style("big", 20, fontName=_BOLD, leading=24)


def _hex(colour: colors.Color) -> str:
    return "#" + colour.hexval()[2:]


def _text(value: object, limit: int | None = None) -> str:
    """Escape any value for paragraph markup; with ``limit``, cut it to that many characters.

    Cutting matters: ReportLab cannot split one table cell across pages, so an oversized value
    would make the whole PDF fail to lay out.
    """
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    if limit is not None and len(text) > limit:
        text = f"{text[:limit]}… (cut; full value in findings.json)"
    return escape(text)


def _link(url: str) -> str:
    """A clickable https link; anything else is printed as plain text."""
    if not url.startswith("https://"):
        return _text(url, MAX_CELL_CHARS)
    return f'<link href="{escape(url, {chr(34): "&quot;"})}">{_text(url, MAX_CELL_CHARS)}</link>'


def _para(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(text, style)


def _code(text: str, width: float) -> Table:
    """A shaded code block; only indentation is kept as non-breaking, so long lines still wrap."""
    lines = []
    all_lines = text.rstrip().splitlines()
    for line in all_lines[:MAX_CODE_LINES]:
        stripped = line.lstrip(" ")
        lines.append("&nbsp;" * (len(line) - len(stripped)) + _text(stripped, MAX_CELL_CHARS))
    if len(all_lines) > MAX_CODE_LINES:
        lines.append(f"… {len(all_lines) - MAX_CODE_LINES} more line(s) in findings.json")
    box = Table([[Paragraph("<br/>".join(lines), _CODE)]], colWidths=[width])
    box.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), _SOFT),
                ("BOX", (0, 0), (-1, -1), 0.4, _RULE),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return box


def _table(
    rows: Sequence[Sequence[object]], widths: Sequence[float], *, header: bool = True
) -> Table:
    table = Table(
        [list(row) for row in rows], colWidths=list(widths), repeatRows=1 if header else 0
    )
    commands: list[Any] = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, _RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        commands.append(("BACKGROUND", (0, 0), (-1, 0), _SOFT))
    table.setStyle(TableStyle(commands))
    return table


def _cells(texts: Iterable[str], style: ParagraphStyle = _SMALL) -> list[Paragraph]:
    return [_para(text, style) for text in texts]


def _heading_cells(*titles: str) -> list[Paragraph]:
    return _cells(
        (f"<b>{title.upper()}</b>" for title in titles), _style("th", 7, textColor=_MUTED)
    )


class _Report:
    def __init__(self, data: ReportData, width: float) -> None:
        self.data = data
        self.width = width

    def story(self) -> list[Flowable]:
        return [
            *self._header(),
            *self._summary(),
            *self._findings(),
            *self._appendices(),
            *self._closing_notes(),
        ]

    def _header(self) -> list[Flowable]:
        result = self.data.result
        meta = (
            f"{_text(result.provider.upper())} · {len(result.scopes)} scope(s) · scanned "
            f"{result.started_at.strftime('%d %b %Y, %H:%M UTC')} · Skyveda "
            f"{_text(result.tool_version)}" + (" · <b>offline data</b>" if result.offline else "")
        )
        parts: list[Flowable] = [_para("Skyveda Health Report", _TITLE)]
        if self.data.label:
            parts.append(_para(_text(self.data.label), _LABEL))
        parts += [
            _para(meta, _META),
            _para(
                "Read-only scan: nothing in the environment was created, changed or deleted.", _META
            ),
        ]
        return parts

    def _summary(self) -> list[Flowable]:
        data = self.data
        overall = data.scores.overall
        severities = " · ".join(
            f'<font color="{_hex(_SEVERITY_COLOUR[s])}">{n} {s.value}</font>'
            for s, n in data.severity_counts()
        )
        waived = f" · {len(data.waived)} waived" if data.waived else ""
        cards = [
            ("OVERALL SCORE", f"{overall if overall is not None else '-'}/100", ""),
            ("FINDINGS", str(len(data.findings)), severities),
            (
                "WASTE",
                f"₹{data.waste:,}",
                " · ".join(["a month", *filter(None, [_text(data.waste_basis)])]),
            ),
            (
                "CHECKS",
                str(len(data.result.results)),
                f"{data.counts[Status.PASS]} passed · {data.counts[Status.FAIL]} failed · "
                f"{len(data.others)} not scored{waived}",
            ),
        ]
        card_cells = [
            [_para(label, _style("cl", 7, textColor=_MUTED)), _para(big, _BIG), _para(note, _SMALL)]
            for label, big, note in cards
        ]
        summary = Table([card_cells], colWidths=[self.width / 4] * 4)
        summary.setStyle(
            TableStyle(
                [
                    ("BOX", (0, 0), (-1, -1), 0.4, _RULE),
                    ("INNERGRID", (0, 0), (-1, -1), 0.4, _RULE),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        area_rows: list[list[Paragraph]] = [_heading_cells("Area", "Score", "Passed", "Failed")]
        for area in data.scores.areas:
            area_rows.append(
                _cells(
                    [
                        AREA_LABELS[area.area],
                        f"<b>{area.score}</b>",
                        str(area.passed),
                        str(area.failed),
                    ]
                )
            )
        return [
            _para("Summary", _H2),
            summary,
            _para("Scores by area", _H2),
            _table(area_rows, [self.width * f for f in (0.46, 0.18, 0.18, 0.18)]),
            *self._framework_summary(),
        ]

    def _framework_summary(self) -> list[Flowable]:
        data = self.data
        if not (data.mcsb_summary or data.pillar_summary):
            return []
        widths = [self.width * f for f in (0.6, 0.2, 0.2)]
        parts: list[Flowable] = [
            _para("Framework summary", _H2),
            _para(
                "Checks passed and failed against each Well-Architected pillar and each "
                "Microsoft cloud security benchmark (MCSB) control. Checks not scored are "
                "left out.",
                _META,
            ),
        ]
        for heading, rows in (
            ("Well-Architected pillar", data.pillar_summary),
            ("MCSB control", data.mcsb_summary),
        ):
            table = [_heading_cells(heading, "Passed", "Failed")]
            table += [_cells([_text(r.label, 80), str(r.passed), str(r.failed)]) for r in rows]
            parts += [Spacer(1, 6), _table(table, widths)]
        return parts

    def _findings(self) -> list[Flowable]:
        parts: list[Flowable] = [_para("Findings", _H2)]
        if not self.data.findings:
            parts.append(_para("No findings. Every applicable check passed.", _BODY))
        for finding in self.data.findings:
            parts += self._finding(finding)
        return parts

    def _finding(self, finding: Finding) -> list[Flowable]:
        colour = _hex(_SEVERITY_COLOUR[finding.severity])
        count = len(finding.resources)
        meta = f"{_text(finding.check_id)} · {AREA_LABELS[finding.area]} · {count} resource(s)"
        if waste := finding_waste(finding):
            meta += f' · <font color="#b4532a"><b>{_text(waste)}</b></font>'
        if self.data.waived_by_check.get(finding.check_id):
            meta += f" · {self.data.waived_by_check[finding.check_id]} more waived (Appendix D)"
        head: list[Flowable] = [
            _para(
                f'<font color="{colour}"><b>{finding.severity.value.upper()}</b></font>'
                f"&nbsp;&nbsp;Failed: {_text(finding.title)}",
                _H3,
            ),
            _para(meta, _META),
            *([_para(f"Maps to: {_text(m)}", _META)] if (m := maps_to(finding.frameworks)) else []),
            _para(f"<b>Why it matters.</b> {_text(finding.why)}", _BODY),
            _para(f"<b>Fix.</b> {_text(finding.fix.summary)}", _BODY),
        ]
        head += [
            _para(f"{n}. {_text(step)}", _style("step", 9, leftIndent=10, spaceAfter=1))
            for n, step in enumerate(finding.fix.steps, start=1)
        ]
        if finding.fix.cli:
            head.append(_code(finding.fix.cli, self.width))
        table = self._resources(finding)
        if len(finding.resources) <= KEEP_TOGETHER_RESOURCES:
            parts: list[Flowable] = [KeepTogether([*head, Spacer(1, 4), table])]
        else:
            parts = [KeepTogether(head), Spacer(1, 4), table]
        if finding.references:
            refs = " · ".join(_link(r) for r in finding.references)
            parts.append(_para(f"Reference: {refs}", _META))
        parts.append(Spacer(1, 10))
        return parts

    def _resources(self, finding: Finding) -> Table:
        rows: list[list[Paragraph]] = [_heading_cells("Name", "Evidence", "Resource ID")]
        for resource in finding.resources[:MAX_RESOURCES]:
            lines = [
                f"<b>{_text(key, 80)}</b>: {_text(value, MAX_CELL_CHARS)}"
                for key, value in shown_evidence(resource).items()
            ]
            if cost := resource_cost(resource):
                lines.insert(0, f"<b>{_text(cost)}</b>")
            evidence = "<br/>".join(lines)
            rows.append(
                [
                    _para(_text(resource.name or "", MAX_CELL_CHARS), _SMALL),
                    _para(evidence, _SMALL),
                    _para(_text(resource.id, MAX_CELL_CHARS), _style("rid", 6.5, fontName=_MONO)),
                ]
            )
        hidden = len(finding.resources) - MAX_RESOURCES
        if hidden > 0:
            note = f"… and {hidden} more resource(s), listed in findings.json."
            rows.append([_para(note, _META), _para("", _SMALL), _para("", _SMALL)])
        table = _table(rows, [self.width * f for f in (0.2, 0.38, 0.42)])
        if hidden > 0:
            table.setStyle(TableStyle([("SPAN", (0, -1), (-1, -1))]))
        return table

    def _appendices(self) -> list[Flowable]:
        data = self.data
        w = self.width
        parts: list[Flowable] = [_para("Appendix A · Passed checks", _H2)]
        if data.passed:
            rows = [_heading_cells("Check", "Title", "Area", "Resources")]
            for r in data.passed:
                count = f"{r.resources_evaluated}" + (
                    f" ({len(r.waived)} waived)" if r.waived else ""
                )
                rows.append(_cells([_text(r.check_id), _text(r.title), AREA_LABELS[r.area], count]))
            parts.append(_table(rows, [w * f for f in (0.16, 0.5, 0.18, 0.16)]))
        else:
            parts.append(_para("None.", _META))

        parts.append(_para("Appendix B · Not scored", _H2))
        if data.others:
            rows = [_heading_cells("Check", "Title", "Status", "Reason")]
            for r in data.others:
                reason = r.message or (
                    "No matching resources in scope." if r.status.value == "not_applicable" else ""
                )
                status = r.status.value.replace("_", " ")
                rows.append(_cells([_text(r.check_id), _text(r.title), status, _text(reason)]))
            parts.append(_table(rows, [w * f for f in (0.16, 0.38, 0.14, 0.32)]))
        else:
            parts.append(_para("None.", _META))

        parts.append(_para("Appendix C · Scopes scanned", _H2))
        rows = [_heading_cells("Kind", "ID", "Name")]
        for scope in data.result.scopes:
            rows.append(_cells([_text(scope.kind), _text(scope.id), _text(scope.name or "")]))
        parts.append(_table(rows, [w * f for f in (0.18, 0.47, 0.35)]))

        parts.append(_para("Appendix D · Waived", _H2))
        if data.waived:
            parts.append(
                _para(
                    "Resources taken out of the findings and the scores: risks the client "
                    "accepted, or findings shown to be wrong. Each applies until its expiry date.",
                    _META,
                )
            )
            rows = [_heading_cells("Check", "Resource", "Kind", "Reason", "Approver", "Expires")]
            for check_id, item in data.waived:
                waiver = item.waiver
                rows.append(
                    _cells(
                        [
                            _text(check_id),
                            _text(item.resource.name or item.resource.id, MAX_CELL_CHARS),
                            waiver.kind.value.replace("_", " "),
                            _text(waiver.reason, MAX_CELL_CHARS),
                            _text(waiver.approver),
                            waiver.expires.strftime("%d %b %Y"),
                        ]
                    )
                )
            parts.append(_table(rows, [w * f for f in (0.13, 0.19, 0.11, 0.31, 0.14, 0.12)]))
        else:
            parts.append(_para("None.", _META))
        return parts

    def _closing_notes(self) -> list[Flowable]:
        return [
            Spacer(1, 14),
            _para(
                "Scores: 100 × weight of passed checks ÷ weight of checks that passed or failed, "  # noqa: RUF001
                "per area; overall is the average of areas. Weights: critical 10, high 5, "
                "medium 3, low 1.",
                _META,
            ),
            *(_para(_text(note), _META) for note in self.data.cost_notes),
            _para(
                f"findings.json SHA-256: {self.data.findings_sha256}",
                _style("hash", 7, fontName=_MONO, textColor=_MUTED),
            ),
            _para(FRAMEWORK_NOTE, _META),
            _para(HELP_NOTE, _META),
            _para(TRADEMARK_NOTE, _META),
        ]


def render_pdf(result: ScanResult, findings_json: str, label: str | None = None) -> bytes:
    """Render the PDF report in memory."""
    _register_fonts()
    data = summarise(result, findings_json, label)
    buffer = BytesIO()
    footer_text = "Skyveda Health Report" + (f" · {label}" if label else "")

    def footer(canvas: Canvas, doc: SimpleDocTemplate) -> None:
        canvas.saveState()
        canvas.setFont(_SANS, 7)
        canvas.setFillColor(_MUTED)
        canvas.drawString(doc.leftMargin, 10 * mm, footer_text)
        canvas.drawRightString(A4[0] - doc.rightMargin, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
        title="Skyveda Health Report",
        author=f"Skyveda Scan {result.tool_version}",
        subject=f"findings.json SHA-256: {data.findings_sha256}",
        creator="Skyveda Scan",
    )
    doc.build(_Report(data, doc.width).story(), onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def write_pdf(
    result: ScanResult, findings_json: str, out_dir: Path, label: str | None = None
) -> Path:
    """Write report.pdf; raise ReportError if the content cannot be laid out."""
    try:
        pdf = render_pdf(result, findings_json, label)
    except (LayoutError, ValueError) as exc:
        message = str(exc).splitlines()[0][:200]
        raise ReportError(f"Could not lay out report.pdf: {message}") from exc
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / PDF_FILE
    path.write_bytes(pdf)
    return path
