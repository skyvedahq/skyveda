"""Load waivers.yaml and apply it to a scan result.

A waiver moves a failing resource out of its finding into the check's ``waived`` list, with the
waiver recorded beside it, and takes its ₹ estimate off the finding. When every failing resource
of a check is waived, the check passes. Scores are computed afterwards, so waivers count in them.
Expired waivers are not applied; they and waivers that matched nothing are returned so the CLI
can warn about them. A waiver for one resource wins over a waiver for the whole check.

Waivers are applied once, to an unwaived result: re-applying to a result that already has waived
resources is refused, because earlier waivers could not be re-checked for expiry.

File format::

    schema_version: 1
    waivers:
      - check: AZ-NET-001
        resource: /subscriptions/.../networkSecurityGroups/nsg-vendor   # omit for the whole check
        kind: accepted_risk            # or false_positive
        reason: Vendor access, limited by the upstream firewall
        approver: Platform lead, Example Ltd
        expires: 2027-03-31
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from skyveda.core.errors import WaiverApplyError, WaiverLoadError
from skyveda.core.evaluators import billed_waste, total_waste
from skyveda.core.models import (
    CheckResult,
    CostBasis,
    ScanResult,
    Status,
    WaivedResource,
    Waiver,
)


class _WaiverFile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    waivers: list[Waiver] = Field(default_factory=list)


@dataclass(frozen=True, slots=True)
class WaiverOutcome:
    result: ScanResult
    expired: tuple[Waiver, ...]
    unused: tuple[Waiver, ...]


def load_waivers(path: Path) -> list[Waiver]:
    """Read and validate a waivers file; raise WaiverLoadError naming the first problem."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise WaiverLoadError(f"Cannot read waivers file {path}: {exc.strerror}") from exc
    except yaml.YAMLError as exc:
        raise WaiverLoadError(f"{path}: not valid YAML ({str(exc).splitlines()[0]})") from exc
    try:
        return _WaiverFile.model_validate(data or {}).waivers
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(part) for part in first["loc"]) or "file"
        raise WaiverLoadError(f"{path}: {where}: {first['msg']}") from exc


def apply_waivers(result: ScanResult, waivers: list[Waiver], today: date) -> WaiverOutcome:
    if any(item.waived for item in result.results):
        raise WaiverApplyError(
            "This findings.json already has waivers applied; apply waivers to the original scan."
        )
    # Resource-specific waivers first, so they win over a waiver for the whole check.
    active = sorted(
        (waiver for waiver in waivers if waiver.expires >= today),
        key=lambda waiver: waiver.resource is None,
    )
    used: set[int] = set()
    results = [_apply(item, active, used) for item in result.results]
    return WaiverOutcome(
        result=result.model_copy(update={"results": results}),
        expired=tuple(waiver for waiver in waivers if waiver.expires < today),
        unused=tuple(waiver for n, waiver in enumerate(active) if n not in used),
    )


def _apply(item: CheckResult, active: list[Waiver], used: set[int]) -> CheckResult:
    finding = item.finding
    if finding is None:
        return item
    priced = finding.est_monthly_waste_inr is not None
    unpriced = [r for r in finding.resources if r.est_monthly_waste_inr is None]
    if priced and any(r.cost_basis is not CostBasis.UNKNOWN for r in unpriced):
        raise WaiverApplyError(
            f"{item.check_id}: findings.json was written by an older Skyveda without per-resource "
            "₹ estimates; re-run the scan before applying waivers."
        )
    remaining = []
    waived = list(item.waived)
    for resource in finding.resources:
        match = next(
            (n for n, w in enumerate(active) if w.covers(item.check_id, resource.id)), None
        )
        if match is None:
            remaining.append(resource)
        else:
            used.add(match)
            waived.append(WaivedResource(resource=resource, waiver=active[match]))
    if len(waived) == len(item.waived):
        return item
    if not remaining:
        return item.model_copy(update={"status": Status.PASS, "finding": None, "waived": waived})
    waste = total_waste(priced, remaining)
    billed = billed_waste(remaining) if priced else None
    trimmed = finding.model_copy(
        update={
            "resources": remaining,
            "est_monthly_waste_inr": waste,
            "billed_monthly_waste_inr": billed,
        }
    )
    return item.model_copy(update={"finding": trimmed, "waived": waived})
