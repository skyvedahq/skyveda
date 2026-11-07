"""Build the fix pack: reviewable scripts and a plan, written as files only.

Nothing here runs a command, reads credentials or calls a cloud. The scripts it writes have every
command commented out, so a person must remove each ``# `` on purpose (CONSTITUTION principle 1).
"""

from __future__ import annotations

import hashlib
import os
import re
import textwrap
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from skyveda.core.errors import RemedyError
from skyveda.core.models import AffectedResource, Check, Finding, Remedy, ScanResult
from skyveda.core.remedy import clean_text, render, resource_values
from skyveda.report.summary import resource_cost

README_FILE = "README.md"
PULL_REQUEST_FILE = "PULL_REQUEST.md"
README_HEADING = "# Fix plan"
PULL_REQUEST_HEADING = "# Fix cloud findings from Skyveda Scan"
SCRIPT_MARK = "# Skyveda fix for "
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_NAME = 80
_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{n}" for n in range(1, 10)),
    *(f"LPT{n}" for n in range(1, 10)),
}
_WIDTH = 96
_CHECK_DIR = re.compile(r"^[A-Z]{2,5}-[A-Z]{2,8}-[0-9]{3}$")


@dataclass(frozen=True, slots=True)
class PlanItem:
    check: Check
    finding: Finding
    resource: AffectedResource
    remedy: Remedy
    script: str
    """Path of the script relative to the output directory, with forward slashes."""
    text: str
    before: str
    """The before-steps with this resource's values filled in."""


@dataclass(frozen=True, slots=True)
class ManualFix:
    check_id: str
    title: str
    resources: int
    reason: str


@dataclass(slots=True)
class FixPlan:
    items: list[PlanItem] = field(default_factory=list)
    manual: list[ManualFix] = field(default_factory=list)


def safe_name(name: str) -> str:
    """A filename-safe version of a resource name: letters, digits, dot, dash, underscore."""
    cleaned = _UNSAFE.sub("_", name).strip("._")[:_MAX_NAME].strip("._")
    if not cleaned or cleaned.upper().split(".")[0] in _RESERVED:
        return f"_{cleaned}" if cleaned else "resource"
    return cleaned


def build_plan(result: ScanResult, checks: Sequence[Check]) -> FixPlan:
    """Order the work: severity first, then ₹ a month from high to low."""
    by_id = {check.id: check for check in checks}
    plan = FixPlan()
    used: dict[str, set[str]] = {}
    seen: set[tuple[str, str]] = set()
    for finding in result.findings:
        check = by_id.get(finding.check_id)
        if check is None or check.remedy is None:
            plan.manual.append(_manual(finding, "no remedy template for this check"))
            continue
        skipped = 0
        for resource in finding.resources:
            key = (finding.check_id, resource.id.lower())
            if key in seen:
                continue
            seen.add(key)
            try:
                text, script, before = _script(check, check.remedy, finding, resource, used)
            except RemedyError:
                skipped += 1
                continue
            plan.items.append(
                PlanItem(check, finding, resource, check.remedy, script, text, before)
            )
        if skipped:
            plan.manual.append(
                _manual(finding, "a field the template needs is missing or unsafe", count=skipped)
            )
    plan.items.sort(key=_order)
    plan.manual.sort(key=lambda item: item.check_id)
    return plan


def write_fix_pack(
    result: ScanResult, checks: Sequence[Check], out: Path, *, force: bool = False
) -> list[Path]:
    """Write README.md, one script per resource and PULL_REQUEST.md under ``out``.

    A non-empty ``out`` is refused unless ``force``; then only the files a previous fix pack
    wrote (``<CHECK-ID>/*.sh``, README.md, PULL_REQUEST.md) are removed first. Every path is
    checked before anything is written or removed.
    """
    plan = build_plan(result, checks)
    root = out.resolve()
    files = {item.script: item.text for item in plan.items}
    files[README_FILE] = render_readme(plan, result)
    files[PULL_REQUEST_FILE] = render_pull_request(plan)
    try:
        if root.exists() and not root.is_dir():
            raise RemedyError(f"{out} is not a folder")
        stale: list[Path] = []
        if root.is_dir() and any(root.iterdir()):
            if not force:
                raise RemedyError(
                    f"{out} is not empty. Use --force to replace a previous fix pack: only its "
                    "<check-id>/*.sh files, README.md and PULL_REQUEST.md are removed."
                )
            stale = _stale_files(root, out)
        targets = {name: _target(root, name) for name in files}
        for path in stale:
            path.unlink()
        written = []
        for name, path in targets.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(files[name], encoding="utf-8", newline="\n")
            written.append(path)
    except OSError as exc:
        raise RemedyError(f"cannot write the fix pack to {out}: {exc.strerror or exc}") from exc
    return written


def _stale_files(root: Path, shown: Path) -> list[Path]:
    """Files an earlier fix pack wrote, and only those.

    Links, junctions and folders that resolve elsewhere are never entered. A README.md,
    PULL_REQUEST.md or script that Skyveda did not write stops the run.
    """
    real = root.resolve()
    ours: list[Path] = []
    foreign: list[Path] = []
    for name, first_line in (
        (README_FILE, README_HEADING),
        (PULL_REQUEST_FILE, PULL_REQUEST_HEADING),
    ):
        path = root / name
        if os.path.lexists(path):
            _sort(path, (0, first_line), ours, foreign, real)
    for folder in sorted(root.iterdir()):
        if not _CHECK_DIR.match(folder.name) or not _is_plain_folder(folder, real):
            continue
        for path in sorted(folder.glob("*.sh")):
            _sort(
                path,
                (1, SCRIPT_MARK),
                ours,
                foreign,
                real,
                parent=real / folder.name,
            )
    if foreign:
        listed = ", ".join(str(path.relative_to(root)) for path in foreign)
        raise RemedyError(f"{shown} holds files Skyveda did not write ({listed}): nothing removed")
    return ours


def _is_plain_folder(folder: Path, real: Path) -> bool:
    return (
        folder.is_dir()
        and not folder.is_symlink()
        and not os.path.isjunction(folder)
        and folder.resolve() == real / folder.name
    )


def _sort(
    path: Path,
    marker: tuple[int, str],
    ours: list[Path],
    foreign: list[Path],
    real: Path,
    parent: Path | None = None,
) -> None:
    resolved = path.resolve()
    inside = resolved.is_relative_to(real) and resolved.parent == (parent or real)
    if path.is_symlink() or not path.is_file() or not inside:
        foreign.append(path)
        return
    with path.open(encoding="utf-8", errors="replace") as handle:
        lines = [handle.readline().rstrip("\r\n"), handle.readline().rstrip("\r\n")]
    line, start = marker
    (ours if lines[line].startswith(start) else foreign).append(path)


def _target(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise RemedyError(f"refusing to write outside the output folder: {relative}")
    return path


def render_readme(plan: FixPlan, result: ScanResult) -> str:
    lines = [
        README_HEADING,
        "",
        "Prepared for review. Nothing in this folder has been run. Every command in every script",
        'is commented out: read the script, then remove the leading "# " from each command',
        "you accept.",
        "",
        f"Source: Skyveda Scan {result.tool_version}, {len(plan.items)} fix(es) in order of "
        "severity, then rupees a month from high to low.",
        "",
    ]
    if plan.items:
        lines += [
            "| # | Severity | Check | Resource | Risk | Downtime | Rupees a month | Script |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for number, item in enumerate(plan.items, start=1):
            lines.append(
                f"| {number} | {item.finding.severity.value} | {item.check.id} | "
                f"{_inline(item.resource.name or item.resource.id)} | {item.remedy.risk.value} | "
                f"{item.remedy.downtime.value} | {resource_cost(item.resource) or 'not known'} | "
                f"[{_inline(item.script)}]({item.script}) |"
            )
    else:
        lines.append("No failing resource has a fix template.")
    lines += ["", "## Manual fix: see report", ""]
    if plan.manual:
        lines += [
            f"- {_inline(m.check_id)} {_inline(m.title)} ({m.resources} resource(s)): {m.reason}"
            for m in plan.manual
        ]
    else:
        lines.append("None: every failing check has a fix template.")
    return "\n".join(lines) + "\n"


def render_pull_request(plan: FixPlan) -> str:
    by_check: dict[str, list[PlanItem]] = {}
    for item in plan.items:
        by_check.setdefault(item.check.id, []).append(item)
    highest = max((item.remedy.risk for item in plan.items), key=lambda r: r.rank, default=None)
    lines = [
        PULL_REQUEST_HEADING,
        "",
        f"Draft, needs review. {len(plan.items)} resource(s) across {len(by_check)} check(s).",
        "Each script is commented out; the reviewer removes the `# ` from each command on purpose.",
        "",
        "## Changes",
        "",
    ]
    for check_id, items in sorted(by_check.items()):
        first = items[0]
        lines.append(
            f"- **{_inline(check_id)}** {_inline(first.check.title)}: {len(items)} resource(s); "
            f"risk {first.remedy.risk.value}, downtime {first.remedy.downtime.value}. "
            f"{_inline(first.check.fix.summary)}"
        )
    lines += ["", "## Risks", ""]
    if highest is None:
        lines.append("No changes.")
    else:
        lines.append(f"Highest risk in this change: {highest.value}.")
        lines += [
            f"- {_inline(item.check.id)} {_inline(item.resource.name or item.resource.id)}: "
            f"{_first_line(item.before)}"
            for item in plan.items
            if item.remedy.risk is highest
        ]
    lines += [
        "",
        "## Before merging",
        "",
        "- [ ] The owner of each resource has agreed",
        "- [ ] Each script's rollback and verify lines have been read",
        "- [ ] Commands were run by a person, in a change window if downtime is not none",
        "",
    ]
    return "\n".join(lines)


def _script(
    check: Check,
    remedy: Remedy,
    finding: Finding,
    resource: AffectedResource,
    used: dict[str, set[str]],
) -> tuple[str, str, str]:
    values = resource_values(resource)
    before = render(remedy.before, values)
    commands = render(remedy.az, values)
    rollback = render(remedy.rollback, values)
    verify = render(remedy.verify, values)
    taken = used.setdefault(check.id, set())
    base = safe_name(resource.name or resource.id.rsplit("/", 1)[-1])
    if base.lower() in taken:  # same name in another group or subscription
        base = f"{base}-{hashlib.sha256(resource.id.lower().encode()).hexdigest()[:8]}"
    taken.add(base.lower())
    header = [
        "#!/usr/bin/env bash",
        *_commented(f"Skyveda fix for {check.id}: {check.title}", "# "),
        *_commented(f"Resource: {resource.id}", "# "),
        *_commented(f"Severity: {finding.severity.value}", "# "),
        *_commented(f"Risk: {remedy.risk.value}", "# "),
        *_commented(f"Downtime: {remedy.downtime.value}", "# "),
        "#",
        "# Prepared for review. Skyveda never runs this. Remove the leading '# ' from each",
        "# command only when you have read it and accept it.",
        "#",
        "# Before you start:",
        *_wrapped(before),
        "#",
        "# Rollback:",
        *_commented(rollback, "#   "),
        "#",
        "# Verify:",
        *_commented(verify, "#   "),
        "",
        "set -euo pipefail",
        "",
    ]
    body = _commented(commands, "# ")
    return "\n".join([*header, *body]) + "\n", f"{check.id}/{base}.sh", before


def _commented(text: str, prefix: str) -> list[str]:
    return [f"{prefix}{line}".rstrip() for line in text.strip("\n").splitlines()]


def _wrapped(text: str) -> list[str]:
    return textwrap.wrap(
        " ".join(clean_text(text).split()),
        width=_WIDTH,
        initial_indent="#   ",
        subsequent_indent="#   ",
        break_on_hyphens=False,  # never split an Azure name such as nsg-app-01
        break_long_words=False,  # nor a long id or command
    )


def _order(item: PlanItem) -> tuple[int, float, str, str]:
    waste = item.resource.est_monthly_waste_inr or 0.0
    return (item.finding.severity.rank, -waste, item.check.id, item.script)


def _manual(finding: Finding, reason: str, count: int | None = None) -> ManualFix:
    return ManualFix(finding.check_id, finding.title, count or len(finding.resources), reason)


def _inline(text: str) -> str:
    """One line of safe Markdown: whitespace collapsed, and | [ ] ` and backslash escaped."""
    flat = " ".join(clean_text(text).split())
    return re.sub(r"([\\|\[\]`<&])", r"\\\1", flat)


def _first_line(text: str) -> str:
    return _inline(textwrap.shorten(" ".join(text.split()), width=160, placeholder="..."))


__all__ = [
    "PULL_REQUEST_FILE",
    "README_FILE",
    "FixPlan",
    "PlanItem",
    "build_plan",
    "render_pull_request",
    "render_readme",
    "safe_name",
    "write_fix_pack",
]
