"""Compare a lab scan with what the lab planted.

    terraform output -json expected_status > expected.json
    terraform output -json expected_flagged > flagged.json      # optional
    python verify.py expected.json <scan-out>/findings.json [flagged.json]

Exits 1 if any check's status differs from the expectation, or, with flagged.json, if a check
flags a different set of resources than the lab planted (a compliant twin flagged too usually
means a wrong property path).
"""

# ruff: noqa: T201 - a command-line script; printing is its output.

from __future__ import annotations

import json
import sys
from pathlib import Path


def read_json(path: str) -> dict[str, object]:
    """Windows PowerShell's `>` writes UTF-16; accept that as well as UTF-8."""
    raw = Path(path).read_bytes()
    encoding = "utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
    data: dict[str, object] = json.loads(raw.decode(encoding))
    return data


def main(expected_path: str, findings_path: str, flagged_path: str | None = None) -> int:
    expected = {key: str(value) for key, value in read_json(expected_path).items()}
    results = read_json(findings_path).get("results")
    if not isinstance(results, list):
        raise SystemExit(f"{findings_path} is not a findings.json")
    actual = {result["check_id"]: result["status"] for result in results}
    mismatches = 0
    for check_id, want in sorted(expected.items()):
        got = actual.get(check_id, "missing")
        ok = got == want
        mismatches += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {check_id:<12} expected {want:<15} got {got}")
    print(f"{len(expected) - mismatches}/{len(expected)} checks behaved as planted.")
    if flagged_path:
        mismatches += compare_flagged(read_json(flagged_path), results)
    return 1 if mismatches else 0


def compare_flagged(flagged: dict[str, object], results: list[dict[str, object]]) -> int:
    """Compare each check's flagged resource names with the names the lab planted."""
    found: dict[str, set[str]] = {}
    for result in results:
        finding = result.get("finding")
        resources = finding.get("resources", []) if isinstance(finding, dict) else []
        found[str(result["check_id"])] = {str(r.get("name")) for r in resources}
    mismatches = 0
    for check_id, names in sorted(flagged.items()):
        want = {str(name) for name in names} if isinstance(names, list) else set()
        got = found.get(check_id, set())
        ok = got == want
        mismatches += not ok
        detail = "" if ok else f"  missing {sorted(want - got)}  extra {sorted(got - want)}"
        print(f"{'ok  ' if ok else 'FAIL'} {check_id:<12} flags {len(got)} as planted{detail}")
    print(f"{len(flagged) - mismatches}/{len(flagged)} checks flagged exactly what was planted.")
    return mismatches


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
