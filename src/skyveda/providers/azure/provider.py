"""AzureProvider: the Azure implementation of the core Provider protocol."""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import date

from azure.core.credentials import TokenCredential

from skyveda.core.billing import DailyCost
from skyveda.core.errors import AuthenticationError, ScopeError, UnsupportedSourceError
from skyveda.core.models import Row, Scope
from skyveda.core.provider import DataRequest, ProviderOptions
from skyveda.providers.azure.arm import ArmReader
from skyveda.providers.azure.auth import (
    AUTH_METHODS,
    Identity,
    build_credential,
    verify_credential,
)
from skyveda.providers.azure.collectors import COLLECTORS, CollectorContext
from skyveda.providers.azure.costs import CostReader
from skyveda.providers.azure.resource_graph import ResourceGraphRunner

SCOPE_KIND = "subscription"
SOURCE_RESOURCE_GRAPH = "resource_graph"
SOURCE_ARM = "arm"
_GUID = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")

# Verified by `skyveda scopes`: subscription rows in `resourcecontainers` carry subscriptionId,
# name (display name) and properties.state.
SUBSCRIPTIONS_KQL = """
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| project id, subscriptionId, name, state = tostring(properties.state)
| order by name asc
"""


class AzureProvider:
    name = "azure"

    def __init__(
        self,
        options: ProviderOptions,
        *,
        credential: TokenCredential | None = None,
        runner: ResourceGraphRunner | None = None,
        arm: ArmReader | None = None,
        costs: CostReader | None = None,
    ) -> None:
        _validate_options(options)
        self._options = options
        self._credential = credential
        self._runner = runner
        self._arm = arm
        self._costs = costs
        self._identity: Identity | None = None
        # Several checks share one collector (e.g. App Service config); fetch it once per scan.
        self._collected: dict[tuple[str, tuple[str, ...]], list[Row]] = {}

    @property
    def identity(self) -> str | None:
        return str(self._identity) if self._identity else None

    def authenticate(self) -> None:
        if self._credential is None:
            self._credential = build_credential(self._options.tenant, self._options.auth)
        self._identity = verify_credential(self._credential, self._options.tenant)
        if self._runner is None:
            self._runner = ResourceGraphRunner.from_credential(self._credential)
        if self._arm is None:
            self._arm = ArmReader.from_credential(self._credential)
        if self._costs is None:
            self._costs = CostReader.from_credential(self._credential)

    def list_scopes(self) -> list[Scope]:
        rows = self._graph().query(
            SUBSCRIPTIONS_KQL,
            subscriptions=self._options.scope_ids,
            management_groups=self._options.scope_group_ids,
        )
        scopes = [_scope_from_row(row) for row in rows]
        _ensure_all_requested_found(self._options.scope_ids, scopes)
        if not scopes:
            raise ScopeError("The credential cannot read any subscription.")
        return scopes

    def fetch(self, request: DataRequest) -> list[Row]:
        source = request.source
        subscription_ids = [scope.id for scope in request.scopes]
        if source.type == SOURCE_RESOURCE_GRAPH and source.query is not None:
            return self._graph().query(source.query, subscriptions=subscription_ids)
        if source.type == SOURCE_ARM and source.collector is not None:
            return self._collect(source.collector, tuple(subscription_ids))
        raise UnsupportedSourceError(f"Azure provider cannot run source type '{source.type}'.")

    def daily_costs(self, resource_ids: Sequence[str], start: date, end: date) -> list[DailyCost]:
        if self._costs is None:
            raise AuthenticationError("Azure provider used before authenticate().")
        return self._costs.daily_costs(resource_ids, start, end)

    def close(self) -> None:
        if self._runner is not None:
            self._runner.close()
        if self._arm is not None:
            self._arm.close()
        if self._costs is not None:
            self._costs.close()
        close = getattr(self._credential, "close", None)
        if callable(close):
            close()

    def _collect(self, name: str, subscription_ids: tuple[str, ...]) -> list[Row]:
        collector = COLLECTORS.get(name)
        if collector is None:
            raise UnsupportedSourceError(f"Unknown collector '{name}'.")
        key = (name, subscription_ids)
        if key not in self._collected:
            if self._arm is None:
                raise AuthenticationError("Azure provider used before authenticate().")
            graph = self._graph()
            context = CollectorContext(
                graph=lambda kql: graph.query(kql, subscriptions=subscription_ids),
                arm=self._arm,
            )
            self._collected[key] = collector(context)
        return self._collected[key]

    def _graph(self) -> ResourceGraphRunner:
        if self._runner is None:
            raise AuthenticationError("Azure provider used before authenticate().")
        return self._runner


def _validate_options(options: ProviderOptions) -> None:
    if options.scope_ids and options.scope_group_ids:
        raise ScopeError("Use either --subscription or --management-group, not both.")
    invalid = [sid for sid in options.scope_ids if not _GUID.fullmatch(sid)]
    if invalid:
        raise ScopeError(f"Not a subscription ID (GUID expected): {', '.join(invalid)}")
    if options.tenant and not _GUID.fullmatch(options.tenant):
        raise ScopeError(f"Not a tenant ID (GUID expected): {options.tenant}")
    if options.auth not in AUTH_METHODS:
        raise ScopeError(f"Unknown auth method '{options.auth}'. Use: {', '.join(AUTH_METHODS)}.")


def _scope_from_row(row: Row) -> Scope:
    return Scope(kind=SCOPE_KIND, id=str(row["subscriptionId"]), name=row.get("name"))


def _ensure_all_requested_found(requested: tuple[str, ...], found: list[Scope]) -> None:
    found_ids = {scope.id.lower() for scope in found}
    missing = [sid for sid in requested if sid.lower() not in found_ids]
    if missing:
        raise ScopeError(
            f"Subscription(s) not found or not readable with this credential: {', '.join(missing)}"
        )
