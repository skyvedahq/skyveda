"""Provider-neutral domain models: checks (loaded from YAML), findings and scan results.

Nothing in this module may mention a specific cloud. Provider-specific meaning lives in the
``source`` block of a check, which only the matching provider interprets.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, computed_field, model_validator

CHECK_ID_PATTERN = r"^[A-Z]{2,5}-[A-Z]{2,8}-\d{3}$"
DOTTED_PATH_PATTERN = r"^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)+$"

ParameterValue = str | int | float | bool | list[str]


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """0 is most severe; use for sorting."""
        return _SEVERITY_RANK[self]

    def at_least(self, threshold: Severity) -> bool:
        return self.rank <= threshold.rank


_SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


class Area(StrEnum):
    KUBERNETES = "kubernetes"
    NETWORK = "network"
    IDENTITY = "identity"
    SECURITY = "security"
    RELIABILITY = "reliability"
    OBSERVABILITY = "observability"
    COST = "cost"


class Tier(StrEnum):
    FREE = "free"
    PRO = "pro"


class Status(StrEnum):
    PASS = "pass"  # noqa: S105 - not a password
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"
    SKIPPED = "skipped"


class CostBasis(StrEnum):
    BILLED = "billed"
    ESTIMATE = "estimate"
    UNKNOWN = "unknown"
    """A cost check with no list-price formula, and no billed cost for this resource."""


class CostSource(StrEnum):
    """Where cost findings' ₹ come from: billed cost where the cloud has it, or list prices."""

    BILLED = "billed"
    ESTIMATE = "estimate"


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Scope(_Model):
    """A unit the provider scans: an Azure subscription, an AWS account, a GCP project, ..."""

    kind: str
    id: str
    name: str | None = None


# --------------------------------------------------------------------------- check definition


class Source(_Model):
    """Where a check's data comes from. ``type`` is interpreted by the provider only.

    Exactly one of ``query`` (e.g. a Resource Graph KQL query) or ``collector`` (the name of a
    provider-registered Python data fetcher, for data no query language exposes) must be set.
    """

    type: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    query: str | None = None
    collector: str | None = Field(default=None, pattern=DOTTED_PATH_PATTERN)

    @model_validator(mode="after")
    def _exactly_one_of_query_or_collector(self) -> Self:
        if (self.query is None) == (self.collector is None):
            raise ValueError("source needs exactly one of 'query' or 'collector'")
        return self


class RowsEvaluator(_Model):
    """Default evaluator: the source returns one row per in-scope resource.

    Each row carries a boolean compliance column. Zero rows means the check is not applicable;
    any row with a false compliance value is a failure. All other columns become evidence.
    """

    type: Literal["rows"] = "rows"
    compliant_field: str = "compliant"
    resource_id_field: str = "id"
    name_field: str = "name"


class PythonEvaluator(_Model):
    """Escape hatch for logic a query cannot express, e.g. NSG port-range arithmetic."""

    type: Literal["python"]
    function: str = Field(pattern=DOTTED_PATH_PATTERN)


Evaluator = Annotated[RowsEvaluator | PythonEvaluator, Field(discriminator="type")]


class Fix(_Model):
    summary: str
    steps: list[str] = Field(default_factory=list)
    cli: str | None = None
    terraform: str | None = None


class RemedyRisk(StrEnum):
    """What can go wrong if the fix is applied (not the finding's severity)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return list(RemedyRisk).index(self)


class Downtime(StrEnum):
    NONE = "none"
    RESTART = "restart"
    OUTAGE = "outage"


class Remedy(_Model):
    """A reviewed, per-resource fix the fix pack renders into a script (never run by Skyveda).

    ``az``, ``rollback`` and ``verify`` are templates: ``{field}`` is filled from the failing
    resource's ``id``, ``name``, ``subscriptionId`` (taken from the id) and evidence columns.
    ``terraform`` is accepted for later; it is not rendered yet.
    """

    risk: RemedyRisk
    downtime: Downtime
    before: str = Field(min_length=1)
    az: str = Field(min_length=1)
    rollback: str = Field(min_length=1)
    verify: str = Field(min_length=1)
    terraform: str | None = None


class CostSpec(_Model):
    """How a cost check prices its findings.

    The source returns a per-resource monthly list-price estimate in ₹ in ``field`` (None when the
    check has no list-price formula and is priced from billed cost only); a finding's
    ``est_monthly_waste_inr`` is the sum over its failing resources. When ``billed`` is true the
    whole bill of a flagged resource is its waste, so its billed cost replaces the estimate where
    the cloud reports one (D-028). Set it false when the waste is only part of the bill, such as
    the price gap between two disk tiers.
    """

    field: str | None = "estMonthlyWasteInr"
    basis: str = "list-price estimate"
    billed: bool = True

    @model_validator(mode="after")
    def _priced_somehow(self) -> Self:
        if self.field is None and not self.billed:
            raise ValueError("a cost check needs a list-price 'field', billed cost, or both")
        return self


MCSB_ID = re.compile(r"^(NS|IM|PA|DP|AM|LT|IR|PV|ES|BR|DS|AI)-\d+$")
WAF_ID = re.compile(r"^(RE|SE|CO|OE|PE):\d{2}$")
WAF_PILLARS = {
    "RE": "Reliability",
    "SE": "Security",
    "CO": "Cost Optimization",
    "OE": "Operational Excellence",
    "PE": "Performance Efficiency",
}
FRAMEWORK_KEYS = ("mcsb", "waf_pillar", "waf")


def framework_problem(frameworks: dict[str, list[str]]) -> str | None:
    """Why a ``frameworks`` block is not valid, or None. An empty block is fine (custom checks);
    a non-empty one needs ``waf_pillar`` and only known keys, IDs and pillars, and each WAF ID
    must sit under one of the check's pillars."""
    if not frameworks:
        return None
    unknown = sorted(set(frameworks) - set(FRAMEWORK_KEYS))
    if unknown:
        return f"unknown key(s) {', '.join(unknown)}; use {', '.join(FRAMEWORK_KEYS)}"
    pillars = frameworks.get("waf_pillar", [])
    if not pillars:
        return "waf_pillar is required"
    bad_pillars = [p for p in pillars if p not in WAF_PILLARS.values()]
    if bad_pillars:
        return f"unknown pillar {bad_pillars[0]!r}"
    for control in frameworks.get("mcsb", []):
        if not MCSB_ID.match(control):
            return f"bad MCSB control ID {control!r}"
    for rec in frameworks.get("waf", []):
        if not WAF_ID.match(rec):
            return f"bad Well-Architected ID {rec!r}"
        if WAF_PILLARS[rec.split(":")[0]] not in pillars:
            return f"{rec} is not in the pillar(s) {', '.join(pillars)}"
    return None


class Check(_Model):
    schema_version: Literal[1] = 1
    id: str = Field(pattern=CHECK_ID_PATTERN)
    title: str
    provider: str
    area: Area
    severity: Severity
    tier: Tier = Tier.FREE
    source: Source
    evaluate: Evaluator = Field(default_factory=RowsEvaluator)
    parameters: dict[str, ParameterValue] = Field(default_factory=dict)
    why: str
    fix: Fix
    remedy: Remedy | None = None
    references: list[Annotated[str, Field(pattern=r"^https://")]] = Field(default_factory=list)
    frameworks: dict[str, list[str]] = Field(default_factory=dict)
    cost: CostSpec | None = None

    @model_validator(mode="after")
    def _cost_only_for_cost_checks(self) -> Self:
        if self.cost is not None and self.area is not Area.COST:
            raise ValueError("a 'cost' block is only allowed on cost-area checks")
        return self

    @model_validator(mode="after")
    def _frameworks_are_well_formed(self) -> Self:
        problem = framework_problem(self.frameworks)
        if problem:
            raise ValueError(f"frameworks: {problem}")
        return self


# --------------------------------------------------------------------------- results


class AffectedResource(_Model):
    id: str
    name: str | None = None
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    est_monthly_waste_inr: float | None = Field(default=None, ge=0)
    """This resource's share of a cost finding's waste, so waivers can take it off the total."""
    cost_basis: CostBasis | None = None
    """Whether that share is billed cost or a list-price estimate; None outside cost findings."""


class WaiverKind(StrEnum):
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class Waiver(_Model):
    """A failing resource (or a whole check) the client has accepted, or shown to be wrong.

    ``resource`` is a resource ID, matched case-insensitively; omit it to waive every resource
    the check flags. A waiver applies up to and including its ``expires`` date.
    """

    check: str = Field(pattern=CHECK_ID_PATTERN)
    resource: str | None = Field(default=None, min_length=1)
    kind: WaiverKind = WaiverKind.ACCEPTED_RISK
    reason: str = Field(min_length=1)
    approver: str = Field(min_length=1)
    expires: date

    def covers(self, check_id: str, resource_id: str) -> bool:
        return self.check == check_id and (
            self.resource is None or self.resource.lower() == resource_id.lower()
        )


class WaivedResource(_Model):
    resource: AffectedResource
    waiver: Waiver


class Finding(_Model):
    check_id: str
    title: str
    provider: str
    area: Area
    severity: Severity
    resources: list[AffectedResource] = Field(min_length=1)
    why: str
    fix: Fix
    references: list[str] = Field(default_factory=list)
    frameworks: dict[str, list[str]] = Field(default_factory=dict)
    est_monthly_waste_inr: int | None = Field(default=None, ge=0)
    """Total monthly waste in ₹: billed cost where known, list-price estimates elsewhere.
    None when no resource has a figure, or outside cost findings."""
    billed_monthly_waste_inr: int | None = Field(default=None, ge=0)
    """The part of the total that is billed cost; None when nothing in it is billed."""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def resource_ids(self) -> list[str]:
        return [resource.id for resource in self.resources]

    @model_validator(mode="before")
    @classmethod
    def _drop_computed_fields(cls, data: Any) -> Any:
        """findings.json includes the computed resource_ids; accept it back on load."""
        if isinstance(data, dict) and "resource_ids" in data:
            return {key: value for key, value in data.items() if key != "resource_ids"}
        return data

    @model_validator(mode="after")
    def _waste_only_for_cost_checks(self) -> Self:
        if self.est_monthly_waste_inr is not None and self.area is not Area.COST:
            raise ValueError("est_monthly_waste_inr is only allowed on cost-area findings")
        if self.billed_monthly_waste_inr is not None and self.est_monthly_waste_inr is None:
            raise ValueError("billed_monthly_waste_inr needs est_monthly_waste_inr")
        return self


class CheckResult(_Model):
    check_id: str
    title: str
    area: Area
    severity: Severity
    status: Status
    resources_evaluated: int = Field(default=0, ge=0)
    message: str | None = None
    finding: Finding | None = None
    frameworks: dict[str, list[str]] = Field(default_factory=dict)
    """The check's framework mapping, so reports can count passes as well as failures."""
    waived: list[WaivedResource] = Field(default_factory=list)

    @model_validator(mode="after")
    def _finding_iff_failed(self) -> Self:
        if (self.status is Status.FAIL) != (self.finding is not None):
            raise ValueError("a finding is required for, and only for, failed checks")
        if self.waived and self.status not in (Status.PASS, Status.FAIL):
            raise ValueError("only passed or failed checks can have waived resources")
        return self


class Billing(_Model):
    """The billed-cost read behind a scan's cost findings (D-028)."""

    period_start: date | None = None
    period_end: date | None = None
    """The days read, inclusive. None when the read did not happen."""
    notes: list[str] = Field(default_factory=list)
    """Why some or all flagged resources kept their list-price estimate."""


class ScanResult(_Model):
    """The contents of findings.json. Bump ``schema_version`` on any breaking change."""

    schema_version: Literal[1] = 1
    tool_version: str
    provider: str
    scopes: list[Scope]
    started_at: datetime
    finished_at: datetime
    offline: bool = False
    results: list[CheckResult] = Field(default_factory=list)
    billing: Billing | None = None
    """How cost findings were priced; None when billed cost was not asked for."""

    @property
    def findings(self) -> list[Finding]:
        """Failed checks' findings, most severe first, then by area and check id."""
        found = [result.finding for result in self.results if result.finding is not None]
        return sorted(found, key=lambda f: (f.severity.rank, f.area.value, f.check_id))

    def has_findings_at_or_above(self, threshold: Severity) -> bool:
        return any(finding.severity.at_least(threshold) for finding in self.findings)

    def count_by_status(self) -> dict[Status, int]:
        counts = dict.fromkeys(Status, 0)
        for result in self.results:
            counts[result.status] += 1
        return counts


Row = dict[str, Any]
