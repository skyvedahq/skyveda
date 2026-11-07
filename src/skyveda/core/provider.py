"""The Provider interface and plugin discovery.

Providers register a factory under the ``skyveda.providers`` entry-point group, so adding AWS or
GCP is a new package (or module) plus one line of packaging metadata: no change to the core.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from typing import Protocol, runtime_checkable

from skyveda.core.errors import ProviderNotFoundError
from skyveda.core.models import ParameterValue, Row, Scope, Source

ENTRY_POINT_GROUP = "skyveda.providers"


@dataclass(frozen=True, slots=True)
class ProviderOptions:
    """Provider-neutral connection options gathered from the CLI.

    ``scope_ids`` are the provider's primary scan units (Azure subscriptions, AWS accounts, GCP
    projects); ``scope_group_ids`` are their containers (management groups, OUs, folders).
    Empty means "everything the credential can read".
    """

    tenant: str | None = None
    auth: str = "default"
    scope_ids: tuple[str, ...] = ()
    scope_group_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DataRequest:
    """One unit of data a check needs. ``key`` names the recording in offline mode."""

    key: str
    source: Source
    scopes: tuple[Scope, ...]
    parameters: Mapping[str, ParameterValue] = field(default_factory=dict)


@runtime_checkable
class Provider(Protocol):
    """What the engine needs from a cloud. Implementations must only ever read."""

    @property
    def name(self) -> str: ...

    def authenticate(self) -> None:
        """Obtain and verify credentials. Raises AuthenticationError on failure."""
        ...

    @property
    def identity(self) -> str | None:
        """Who the provider is signed in as, for display; None before authenticate()."""
        ...

    def list_scopes(self) -> list[Scope]:
        """Resolve the requested scopes (or all accessible ones) into concrete scan units."""
        ...

    def fetch(self, request: DataRequest) -> list[Row]:
        """Run one data request and return its rows."""
        ...

    def close(self) -> None:
        """Release network clients and credentials."""
        ...


ProviderFactory = Callable[[ProviderOptions], Provider]


def available_providers() -> list[str]:
    return sorted(ep.name for ep in entry_points(group=ENTRY_POINT_GROUP))


def load_provider(name: str, options: ProviderOptions) -> Provider:
    matches = entry_points(group=ENTRY_POINT_GROUP, name=name)
    if not matches:
        known = ", ".join(available_providers()) or "none"
        raise ProviderNotFoundError(f"Unknown provider '{name}'. Installed providers: {known}.")
    factory: ProviderFactory = next(iter(matches)).load()
    return factory(options)
