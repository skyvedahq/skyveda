"""Load and validate check definitions.

Built-in checks ship inside the package under ``skyveda/checks/<provider>/*.yaml``; extra
directories can be added with ``--checks-dir``. Every file is validated against the Check model,
ids must be unique, and python evaluators must resolve to trusted Skyveda code.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path

import yaml
from pydantic import ValidationError

from skyveda.core.errors import CheckLoadError
from skyveda.core.evaluators import resolve_transform
from skyveda.core.models import Check, PythonEvaluator
from skyveda.core.remedy import unknown_remedy_fields

CHECK_SUFFIXES = (".yaml", ".yml")


@dataclass(frozen=True, slots=True)
class _CheckFile:
    label: str
    text: str


def builtin_providers() -> list[str]:
    """Provider folders that ship with built-in checks."""
    root = files("skyveda").joinpath("checks")
    return sorted(entry.name for entry in root.iterdir() if entry.is_dir() and _has_checks(entry))


def load_checks(provider: str | None, extra_dirs: Sequence[Path] = ()) -> list[Check]:
    """Load built-in checks (for one provider, or all if None) plus checks from ``extra_dirs``.

    Raises CheckLoadError listing every problem found, not just the first.
    """
    providers = [provider] if provider else builtin_providers()
    sources = [*_builtin_files(providers), *_directory_files(extra_dirs)]
    checks, problems = _parse_all(sources)
    problems += _duplicate_ids(checks)
    if problems:
        listed = "\n  - ".join(problems)
        raise CheckLoadError(f"{len(problems)} problem(s) in checks:\n  - {listed}")
    selected = [check for check in checks if provider is None or check.provider == provider]
    return sorted(selected, key=lambda check: check.id)


def _parse_all(sources: Iterable[_CheckFile]) -> tuple[list[Check], list[str]]:
    checks: list[Check] = []
    problems: list[str] = []
    for source in sources:
        try:
            checks.append(_parse(source))
        except CheckLoadError as exc:
            problems.append(f"{source.label}: {exc}")
    return checks, problems


def _parse(source: _CheckFile) -> Check:
    try:
        check = Check.model_validate(yaml.safe_load(source.text))
    except yaml.YAMLError as exc:
        raise CheckLoadError(f"not valid YAML ({str(exc).splitlines()[0]})") from exc
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(part) for part in first["loc"]) or "file"
        raise CheckLoadError(f"{where}: {first['msg']}") from exc
    if isinstance(check.evaluate, PythonEvaluator):
        resolve_transform(check.evaluate.function)
    unknown = unknown_remedy_fields(check)
    if unknown:
        listed = ", ".join("{" + name + "}" for name in unknown)
        raise CheckLoadError(f"remedy: {listed} not projected by the query")
    return check


def _duplicate_ids(checks: Sequence[Check]) -> list[str]:
    counts = Counter(check.id for check in checks)
    return [f"duplicate check id {check_id}" for check_id, n in sorted(counts.items()) if n > 1]


def _builtin_files(providers: Sequence[str]) -> list[_CheckFile]:
    root = files("skyveda").joinpath("checks")
    found: list[_CheckFile] = []
    for provider in providers:
        folder = root.joinpath(provider)
        if folder.is_dir():
            found += [
                _CheckFile(f"{provider}/{entry.name}", entry.read_text(encoding="utf-8"))
                for entry in sorted(folder.iterdir(), key=lambda item: item.name)
                if _is_check(entry)
            ]
    return found


def _directory_files(directories: Sequence[Path]) -> list[_CheckFile]:
    found: list[_CheckFile] = []
    for directory in directories:
        if not directory.is_dir():
            raise CheckLoadError(f"Checks directory not found: {directory}")
        found += [
            _CheckFile(str(path), path.read_text(encoding="utf-8"))
            for path in sorted(directory.rglob("*"))
            if path.suffix in CHECK_SUFFIXES
        ]
    return found


def _is_check(entry: Traversable) -> bool:
    return entry.is_file() and entry.name.endswith(CHECK_SUFFIXES)


def _has_checks(folder: Traversable) -> bool:
    return any(_is_check(entry) for entry in folder.iterdir())
