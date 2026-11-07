"""Scores per area and overall.

Area score = 100 * weight of passed checks / weight of checks that passed or failed. Checks that
were not applicable, errored or skipped do not count either way. Overall = mean of area scores.
Weights: critical 10, high 5, medium 3, low 1.
"""

from __future__ import annotations

from dataclasses import dataclass

from skyveda.core.models import Area, ScanResult, Severity, Status

WEIGHTS = {Severity.CRITICAL: 10, Severity.HIGH: 5, Severity.MEDIUM: 3, Severity.LOW: 1}
_JUDGED = (Status.PASS, Status.FAIL)


@dataclass(frozen=True, slots=True)
class AreaScore:
    area: Area
    score: int
    passed: int
    failed: int


@dataclass(frozen=True, slots=True)
class Scores:
    overall: int | None
    areas: tuple[AreaScore, ...]


def score(result: ScanResult) -> Scores:
    areas = tuple(
        _area_score(result, area)
        for area in Area
        if any(r.area is area and r.status in _JUDGED for r in result.results)
    )
    overall = round(sum(a.score for a in areas) / len(areas)) if areas else None
    return Scores(overall=overall, areas=areas)


def _area_score(result: ScanResult, area: Area) -> AreaScore:
    judged = [r for r in result.results if r.area is area and r.status in _JUDGED]
    passed = [r for r in judged if r.status is Status.PASS]
    total = sum(WEIGHTS[r.severity] for r in judged)
    earned = sum(WEIGHTS[r.severity] for r in passed)
    return AreaScore(
        area=area,
        score=round(100 * earned / total),
        passed=len(passed),
        failed=len(judged) - len(passed),
    )
