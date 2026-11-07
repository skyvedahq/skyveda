"""Offline provider: serves recorded query results from disk instead of calling a cloud.

Layout of a fixtures directory::

    scopes.json          # list of Scope objects
    <request-key>.json   # {"rows": [...]} (extra metadata keys are ignored)
    billed_costs.json    # optional: {"rows": [{"resourceId", "date", "cost", "currency"}]}

Recorded billed costs are served whatever the period asked for, so a demo keeps its figures.

Used by tests, demos and ``skyveda scan --offline DIR``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from datetime import date
from pathlib import Path
from typing import Any

from skyveda.core.billing import DailyCost
from skyveda.core.errors import FixtureNotFoundError, QueryError
from skyveda.core.models import Row, Scope
from skyveda.core.provider import DataRequest

SCOPES_FILE = "scopes.json"
BILLED_COSTS_FILE = "billed_costs.json"
_SAFE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def fixture_filename(key: str) -> str:
    if not _SAFE_KEY.fullmatch(key):
        raise FixtureNotFoundError(f"Invalid fixture key '{key}'.")
    return f"{key}.json"


class OfflineProvider:
    def __init__(self, provider_name: str, fixtures_dir: Path) -> None:
        if not fixtures_dir.is_dir():
            raise FixtureNotFoundError(f"Fixtures directory not found: {fixtures_dir}")
        self.name = provider_name
        self._dir = fixtures_dir

    def authenticate(self) -> None:
        """Offline mode needs no credentials."""

    @property
    def identity(self) -> str | None:
        return f"recorded data in {self._dir}"

    def list_scopes(self) -> list[Scope]:
        items = self._read(SCOPES_FILE)
        if not isinstance(items, list):
            raise QueryError(f"{SCOPES_FILE} must contain a JSON list of scopes.")
        return [Scope.model_validate(item) for item in items]

    def fetch(self, request: DataRequest) -> list[Row]:
        filename = fixture_filename(request.key)
        document = self._read(filename)
        rows = document.get("rows") if isinstance(document, dict) else None
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise QueryError(f"{filename} must contain an object with a 'rows' list of objects.")
        return rows

    def daily_costs(self, resource_ids: Sequence[str], start: date, end: date) -> list[DailyCost]:
        wanted = {resource_id.lower() for resource_id in resource_ids}
        if not (self._dir / BILLED_COSTS_FILE).is_file():
            raise FixtureNotFoundError("no billed costs were recorded")
        document = self._read(BILLED_COSTS_FILE)
        rows = document.get("rows") if isinstance(document, dict) else None
        if not isinstance(rows, list):
            raise QueryError(f"{BILLED_COSTS_FILE} must contain an object with a 'rows' list.")
        try:
            costs = [
                DailyCost(
                    resource_id=str(row["resourceId"]),
                    day=date.fromisoformat(str(row["date"])),
                    amount=float(row["cost"]),
                    currency=str(row["currency"]),
                )
                for row in rows
            ]
        except (KeyError, TypeError, ValueError) as exc:
            raise QueryError(f"{BILLED_COSTS_FILE} has a malformed row ({exc}).") from exc
        return [cost for cost in costs if cost.resource_id.lower() in wanted]

    def close(self) -> None:
        """Nothing to release."""

    def _read(self, filename: str) -> Any:
        path = self._dir / filename
        if not path.is_file():
            raise FixtureNotFoundError(f"No recorded response: {path}")
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
