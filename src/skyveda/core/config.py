"""Load skyveda.toml: saved options for ``scan`` and ``scopes``.

Options typed on the command line win over the file, and the file wins over built-in defaults.
Relative paths in the file are resolved against the file's own folder, so a config can travel
with its waivers.yaml. Credentials never go in this file; sign-in uses the normal Azure methods.

File format::

    schema_version = 1

    [scan]
    provider = "azure"
    subscriptions = ["<subscription-id>"]
    management_groups = []
    tenant = "<tenant-id>"
    auth = "cli"
    out = "skyveda-out"
    fail_on = "high"
    label = "Prepared for cust-001"
    waivers = "waivers.yaml"
    pdf = true
    cost_source = "billed"    # or "estimate": list prices only
    checks_dirs = []
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from skyveda.core.errors import ConfigLoadError
from skyveda.core.models import CostSource, Severity


class ScanConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: str | None = None
    subscriptions: list[str] = Field(default_factory=list)
    management_groups: list[str] = Field(default_factory=list)
    tenant: str | None = None
    auth: str | None = None
    out: Path | None = None
    fail_on: Severity | None = None
    label: str | None = None
    waivers: Path | None = None
    pdf: bool | None = None
    cost_source: CostSource | None = None
    checks_dirs: list[Path] = Field(default_factory=list)


class _ConfigFile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    scan: ScanConfig = Field(default_factory=ScanConfig)


def load_config(path: Path) -> ScanConfig:
    """Read and validate a config file; raise ConfigLoadError naming the first problem."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigLoadError(f"Cannot read config file {path}: {exc.strerror}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigLoadError(f"{path}: not valid TOML ({exc})") from exc
    try:
        config = _ConfigFile.model_validate(data).scan
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(part) for part in first["loc"]) or "file"
        raise ConfigLoadError(f"{path}: {where}: {first['msg']}") from exc
    base = path.parent
    return config.model_copy(
        update={
            "out": None if config.out is None else base / config.out,
            "waivers": None if config.waivers is None else base / config.waivers,
            "checks_dirs": [base / folder for folder in config.checks_dirs],
        }
    )
