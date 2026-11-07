from __future__ import annotations

import json
from pathlib import Path

import pytest

from skyveda.core.errors import FixtureNotFoundError, QueryError
from skyveda.core.models import Source
from skyveda.core.offline import OfflineProvider
from skyveda.core.provider import DataRequest, Provider


def request(key: str) -> DataRequest:
    return DataRequest(key=key, source=Source(type="resource_graph", query="q"), scopes=())


def test_offline_provider_satisfies_protocol(azure_fixtures: Path) -> None:
    assert isinstance(OfflineProvider("azure", azure_fixtures), Provider)


def test_lists_recorded_scopes(azure_fixtures: Path) -> None:
    scopes = OfflineProvider("azure", azure_fixtures).list_scopes()
    assert [s.name for s in scopes] == ["skyveda-lab-prod", "skyveda-lab-dev"]


def test_fetch_returns_recorded_rows(tmp_path: Path) -> None:
    (tmp_path / "AZ-AKS-001.json").write_text(json.dumps({"rows": [{"id": "r1"}]}))
    assert OfflineProvider("azure", tmp_path).fetch(request("AZ-AKS-001")) == [{"id": "r1"}]


def test_missing_recording_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(FixtureNotFoundError, match="AZ-AKS-999"):
        OfflineProvider("azure", tmp_path).fetch(request("AZ-AKS-999"))


def test_malformed_recording_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "bad.json").write_text(json.dumps([1, 2]))
    with pytest.raises(QueryError):
        OfflineProvider("azure", tmp_path).fetch(request("bad"))


@pytest.mark.parametrize("key", ["../secrets", "a/b", ".hidden", ""])
def test_keys_cannot_escape_fixture_dir(tmp_path: Path, key: str) -> None:
    with pytest.raises(FixtureNotFoundError):
        OfflineProvider("azure", tmp_path).fetch(request(key))
