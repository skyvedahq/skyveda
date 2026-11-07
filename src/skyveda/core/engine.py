"""Run checks against a provider and collect the results.

Each check is isolated: a permission gap marks only that check ``skipped`` and any other provider
or evaluation error marks only that check ``error``. The scan as a whole always completes.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from skyveda import __version__
from skyveda.core.billing import apply_billed_costs
from skyveda.core.errors import PermissionDeniedError, SkyvedaError, UnsupportedSourceError
from skyveda.core.evaluators import evaluate
from skyveda.core.models import Check, CheckResult, ScanResult, Scope, Status
from skyveda.core.provider import DataRequest, Provider

log = logging.getLogger(__name__)

FINDINGS_FILE = "findings.json"
Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def run_scan(
    provider: Provider,
    checks: Sequence[Check],
    scopes: Sequence[Scope],
    *,
    offline: bool = False,
    billed_cost: bool = False,
    clock: Clock = _utc_now,
) -> ScanResult:
    """With ``billed_cost``, cost findings are priced from the cloud's billing data (D-028)."""
    started = clock()
    results = [run_check(provider, check, scopes) for check in checks]
    result = ScanResult(
        tool_version=__version__,
        provider=provider.name,
        scopes=list(scopes),
        started_at=started,
        finished_at=clock(),
        offline=offline,
        results=results,
    )
    if billed_cost:
        result = apply_billed_costs(result, checks, provider, started.astimezone(UTC).date())
    return result


def run_check(provider: Provider, check: Check, scopes: Sequence[Scope]) -> CheckResult:
    request = DataRequest(
        key=check.id, source=check.source, scopes=tuple(scopes), parameters=check.parameters
    )
    try:
        rows = provider.fetch(request)
        return evaluate(check, rows)
    except (PermissionDeniedError, UnsupportedSourceError) as exc:
        return _unrun(check, Status.SKIPPED, exc)
    except SkyvedaError as exc:  # includes EvaluationError, QueryError, FixtureNotFoundError
        return _unrun(check, Status.ERROR, exc)


def write_findings(result: ScanResult, out_dir: Path) -> Path:
    """Write findings.json into ``out_dir`` (created if needed) and return its path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / FINDINGS_FILE
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return path


def nothing_ran(result: ScanResult) -> bool:
    """True when no check produced a verdict (all errored or were skipped)."""
    return all(item.status in (Status.ERROR, Status.SKIPPED) for item in result.results)


def _unrun(check: Check, status: Status, exc: SkyvedaError) -> CheckResult:
    log.debug("Check %s %s", check.id, status.value, exc_info=True)
    return CheckResult(
        check_id=check.id,
        title=check.title,
        area=check.area,
        severity=check.severity,
        status=status,
        frameworks=dict(check.frameworks),
        message=str(exc).splitlines()[0],
    )
