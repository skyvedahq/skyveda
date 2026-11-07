"""Figures shared by the HTML and PDF reports, computed once so the two can never disagree."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from pydantic import JsonValue

from skyveda.core.models import (
    AffectedResource,
    Area,
    CheckResult,
    CostBasis,
    Finding,
    ScanResult,
    Severity,
    Status,
    WaivedResource,
)
from skyveda.core.scoring import Scores, score

AREA_LABELS = {
    Area.KUBERNETES: "Kubernetes (AKS)",
    Area.NETWORK: "Network",
    Area.IDENTITY: "Identity",
    Area.SECURITY: "Security",
    Area.RELIABILITY: "Reliability",
    Area.OBSERVABILITY: "Observability",
    Area.COST: "Cost",
}
NOT_JUDGED = (Status.NOT_APPLICABLE, Status.ERROR, Status.SKIPPED)


@dataclass(frozen=True, slots=True)
class FrameworkRow:
    label: str
    passed: int
    failed: int


@dataclass(frozen=True, slots=True)
class ReportData:
    result: ScanResult
    label: str | None
    scores: Scores
    findings: list[Finding]
    waste: int
    billed: int
    waste_basis: str
    """Under the waste total: what it is made of, e.g. "₹1,200 billed, ₹300 list-price estimate".
    Empty when no finding has a cost figure."""
    cost_notes: list[str]
    """The report's closing notes on how ₹ figures were found."""
    counts: dict[Status, int]
    passed: list[CheckResult]
    others: list[CheckResult]
    waived: list[tuple[str, WaivedResource]]
    waived_by_check: dict[str, int]
    findings_sha256: str
    mcsb_summary: list[FrameworkRow]
    """Passed and failed checks per MCSB control, in control order."""
    pillar_summary: list[FrameworkRow]
    """Passed and failed checks per Well-Architected pillar."""

    def severity_counts(self) -> list[tuple[Severity, int]]:
        """(severity, number of findings) for each severity that has findings, worst first."""
        counts = [(s, sum(f.severity is s for f in self.findings)) for s in Severity]
        return [(severity, n) for severity, n in counts if n]


def summarise(result: ScanResult, findings_json: str, label: str | None = None) -> ReportData:
    """``findings_json`` is hashed so a report can be matched to the data it was made from."""
    findings = result.findings
    waste = sum(f.est_monthly_waste_inr or 0 for f in findings)
    billed = sum(f.billed_monthly_waste_inr or 0 for f in findings)
    resources = [r for f in findings for r in f.resources]
    return ReportData(
        result=result,
        label=label,
        scores=score(result),
        findings=findings,
        waste=waste,
        billed=billed,
        waste_basis=waste_basis(resources),
        cost_notes=_cost_notes(result, resources),
        counts=result.count_by_status(),
        passed=[r for r in result.results if r.status is Status.PASS],
        others=[r for r in result.results if r.status in NOT_JUDGED],
        waived=[(r.check_id, w) for r in result.results for w in r.waived],
        waived_by_check={r.check_id: len(r.waived) for r in result.results},
        findings_sha256=hashlib.sha256(findings_json.encode("utf-8")).hexdigest(),
        mcsb_summary=_framework_rows(result, "mcsb", _control_order),
        pillar_summary=_framework_rows(result, "waf_pillar", _pillar_order),
    )


def maps_to(frameworks: dict[str, list[str]]) -> str | None:
    """A finding's one-line framework mapping, e.g. "MCSB NS-1 · WAF SE:06 (Security)"."""
    parts = []
    if frameworks.get("mcsb"):
        parts.append("MCSB " + ", ".join(frameworks["mcsb"]))
    pillars = ", ".join(frameworks.get("waf_pillar", []))
    if frameworks.get("waf"):
        parts.append("WAF " + ", ".join(frameworks["waf"]) + (f" ({pillars})" if pillars else ""))
    elif pillars:
        parts.append(f"WAF pillar {pillars}")
    return " · ".join(parts) or None


def _control_order(control: str) -> tuple[str, int]:
    family, _, number = control.partition("-")
    return family, int(number) if number.isdigit() else 0


def _pillar_order(pillar: str) -> tuple[str, int]:
    return pillar, 0


def _framework_rows(
    result: ScanResult, key: str, order: Callable[[str], tuple[str, int]]
) -> list[FrameworkRow]:
    """Count passed and failed checks per framework entry; checks not judged are left out."""
    tally: dict[str, list[int]] = {}
    for r in result.results:
        if r.status not in (Status.PASS, Status.FAIL):
            continue
        for entry in r.frameworks.get(key, []):
            counts = tally.setdefault(entry, [0, 0])
            counts[0 if r.status is Status.PASS else 1] += 1
    return [FrameworkRow(entry, *tally[entry]) for entry in sorted(tally, key=order)]


def finding_waste(finding: Finding) -> str | None:
    """A finding's ₹ line, e.g. "₹1,500 a month, billed"; None outside cost findings."""
    basis = waste_basis(finding.resources)
    if finding.est_monthly_waste_inr:
        return f"₹{finding.est_monthly_waste_inr:,} a month, {basis}"
    return f"₹ not known: {basis}" if _unknown(finding.resources) else None


def waste_basis(resources: Iterable[AffectedResource], currency: str = "₹") -> str:
    """What a waste figure is made of, judged per resource so rounding never relabels it:
    "billed", "list-price estimate", or both with amounts, plus resources with no figure."""
    billed = estimated = 0.0
    has_billed = has_estimate = False
    unknown = 0
    for resource in resources:
        basis, amount = _basis_of(resource), resource.est_monthly_waste_inr or 0.0
        if basis is CostBasis.BILLED:
            has_billed, billed = True, billed + amount
        elif basis is CostBasis.ESTIMATE:
            has_estimate, estimated = True, estimated + amount
        elif basis is CostBasis.UNKNOWN:
            unknown += 1
    parts = []
    if has_billed and has_estimate:
        billed_part = f"{currency}{round(billed):,} billed"
        parts.append(f"{billed_part}, {currency}{round(estimated):,} list-price estimate")
    elif has_billed or has_estimate:
        parts.append("billed" if has_billed else "list-price estimate")
    if unknown:
        parts.append(f"{unknown} resource(s) with no figure")
    return ", ".join(parts)


FRAMEWORK_NOTE = (
    "MCSB control IDs are from the Microsoft cloud security benchmark v2 (preview); the same IDs "
    "exist in v1, the default in Microsoft Defender for Cloud. Well-Architected IDs are "
    "Skyveda's mapping to Microsoft's published checklists. Skyveda maps to these frameworks; "
    "it does not certify compliance."
)

TRADEMARK_NOTE = (
    "Microsoft and Azure are trademarks of the Microsoft group of companies. "
    "Skyveda is not affiliated with or endorsed by Microsoft."
)

HELP_NOTE = (
    "Want help fixing what this report found? Skyveda offers cloud reviews, fixes and ongoing "
    "care in platform engineering, DevOps and reliability: skyvedahq@gmail.com · "
    "linkedin.com/company/skyveda"
)

LIST_PRICE_COLUMN = "estMonthlyWasteInr"


def shown_evidence(resource: AffectedResource) -> dict[str, JsonValue]:
    """Evidence as reports show it. In cost findings the labelled ₹ line replaces the raw
    list-price column, so a billed resource never shows two different amounts."""
    if resource.cost_basis is None:
        return dict(resource.evidence)
    return {key: value for key, value in resource.evidence.items() if key != LIST_PRICE_COLUMN}


def resource_cost(resource: AffectedResource) -> str | None:
    """A resource's ₹ line in a cost finding; None outside cost findings."""
    if resource.cost_basis is None:
        return None
    if resource.est_monthly_waste_inr is None or resource.cost_basis is CostBasis.UNKNOWN:
        return "₹ not known: no list price, and no billed cost"
    label = "billed" if resource.cost_basis is CostBasis.BILLED else "list-price estimate"
    return f"₹{round(resource.est_monthly_waste_inr):,} a month, {label}"


def _basis_of(resource: AffectedResource) -> CostBasis | None:
    """A findings.json from before D-028 has figures but no basis: those are estimates."""
    if resource.cost_basis is None and resource.est_monthly_waste_inr is not None:
        return CostBasis.ESTIMATE
    return resource.cost_basis


def _unknown(resources: Iterable[AffectedResource]) -> bool:
    return any(_basis_of(r) is CostBasis.UNKNOWN for r in resources)


def _cost_notes(result: ScanResult, resources: list[AffectedResource]) -> list[str]:
    billing = result.billing
    bases = {_basis_of(r) for r in resources}
    notes = []
    if billing and billing.period_start and billing.period_end and CostBasis.BILLED in bases:
        period = f"{billing.period_start:%d %b} to {billing.period_end:%d %b %Y}"
        notes.append(
            f"Billed ₹ are what was billed for each resource from {period}: the average billed "
            "day × 30."  # noqa: RUF001
        )
    notes += billing.notes if billing else []
    if CostBasis.ESTIMATE in bases:
        notes.append("List-price estimates are per resource and will differ from billed cost.")
    return notes
