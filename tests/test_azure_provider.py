from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any

import pytest
from azure.core.credentials import AccessToken
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import AzureCliCredential, DefaultAzureCredential

from skyveda.core.errors import AuthenticationError, ScopeError, UnsupportedSourceError
from skyveda.core.models import Scope, Source
from skyveda.core.provider import DataRequest, Provider, ProviderOptions
from skyveda.providers.azure.auth import (
    ARM_SCOPE,
    TenantPinnedCredential,
    build_credential,
    token_identity,
    verify_credential,
)
from skyveda.providers.azure.provider import AzureProvider
from skyveda.providers.azure.resource_graph import ResourceGraphRunner
from tests.test_resource_graph import FakeGraph, recorded_page

TENANT = "11111111-1111-1111-1111-111111111111"
SUB_1 = "00000000-0000-0000-0000-000000000001"
SUB_9 = "00000000-0000-0000-0000-000000000009"


def fake_jwt(**claims: str) -> str:
    """An unsigned token with the given claims; only the payload is ever read."""
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"e30.{payload}.sig"


class FakeCredential:
    def __init__(self, fail: bool = False, token: str = "fake-token") -> None:  # noqa: S107
        self.fail = fail
        self.token = token
        self.calls: list[dict[str, Any]] = []

    def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:
        self.calls.append({"scopes": scopes, **kwargs})
        if self.fail:
            raise ClientAuthenticationError(message="No account.\nRun az login.")
        return AccessToken(self.token, int(time.time()) + 3600)


def provider_with_pages(
    azure_fixtures: Path, options: ProviderOptions | None = None
) -> tuple[AzureProvider, FakeGraph]:
    graph = FakeGraph(
        [
            recorded_page(azure_fixtures, "subscriptions_page1.json"),
            recorded_page(azure_fixtures, "subscriptions_page2.json"),
        ]
    )
    provider = AzureProvider(
        options or ProviderOptions(),
        credential=FakeCredential(),
        runner=ResourceGraphRunner(graph, sleep=lambda _: None),
    )
    provider.authenticate()
    return provider, graph


def test_azure_provider_satisfies_protocol(azure_fixtures: Path) -> None:
    provider, _ = provider_with_pages(azure_fixtures)
    assert isinstance(provider, Provider)


def test_list_scopes_maps_subscriptions(azure_fixtures: Path) -> None:
    provider, _ = provider_with_pages(azure_fixtures)
    scopes = provider.list_scopes()
    assert scopes[0] == Scope(
        kind="subscription", id="00000000-0000-0000-0000-000000000002", name="skyveda-lab-dev"
    )
    assert len(scopes) == 3


def test_list_scopes_reports_inaccessible_subscriptions(azure_fixtures: Path) -> None:
    provider, _ = provider_with_pages(azure_fixtures, ProviderOptions(scope_ids=(SUB_1, SUB_9)))
    with pytest.raises(ScopeError, match=SUB_9):
        provider.list_scopes()


def test_fetch_runs_kql_over_requested_scopes(azure_fixtures: Path) -> None:
    provider, graph = provider_with_pages(azure_fixtures)
    request = DataRequest(
        key="AZ-AKS-001",
        source=Source(type="resource_graph", query="resources | take 1"),
        scopes=(Scope(kind="subscription", id=SUB_1),),
    )
    provider.fetch(request)
    assert graph.requests[0].query == "resources | take 1"
    assert graph.requests[0].subscriptions == [SUB_1]


def test_fetch_rejects_unknown_source_types(azure_fixtures: Path) -> None:
    provider, _ = provider_with_pages(azure_fixtures)
    request = DataRequest(
        key="x", source=Source(type="collector", collector="azure.aks.versions"), scopes=()
    )
    with pytest.raises(UnsupportedSourceError):
        provider.fetch(request)


@pytest.mark.parametrize(
    "options",
    [
        ProviderOptions(scope_ids=("not-a-guid",)),
        ProviderOptions(tenant="contoso.com"),
        ProviderOptions(scope_ids=(SUB_1,), scope_group_ids=("mg",)),
        ProviderOptions(auth="browser"),
    ],
)
def test_invalid_options_are_rejected_before_any_call(options: ProviderOptions) -> None:
    with pytest.raises(ScopeError):
        AzureProvider(options)


def test_build_credential_without_tenant_is_default_chain() -> None:
    assert isinstance(build_credential(), DefaultAzureCredential)


def test_tenant_pinned_credential_requests_tokens_for_that_tenant() -> None:
    inner = FakeCredential()
    TenantPinnedCredential(inner, TENANT).get_token(ARM_SCOPE)
    assert inner.calls[0]["tenant_id"] == TENANT


def test_verify_credential_gives_actionable_error() -> None:
    with pytest.raises(AuthenticationError, match="az login") as caught:
        verify_credential(FakeCredential(fail=True))
    assert "Run az login." not in str(caught.value)  # only the first line of SDK detail


def test_cli_auth_method_uses_only_the_az_login_account() -> None:
    assert isinstance(build_credential(method="cli"), AzureCliCredential)


def test_token_identity_reads_tenant_and_account() -> None:
    identity = token_identity(fake_jwt(tid=TENANT, unique_name="live.com#founder@example.com"))
    assert identity.tenant_id == TENANT
    assert identity.account == "live.com#founder@example.com"
    assert token_identity("not-a-jwt").tenant_id is None


def test_token_from_another_tenant_is_refused_before_any_query() -> None:
    other = "22222222-2222-2222-2222-222222222222"
    credential = FakeCredential(token=fake_jwt(tid=other, appid="vm-identity"))
    with pytest.raises(AuthenticationError, match="--auth cli"):
        verify_credential(credential, expected_tenant=TENANT)
    assert verify_credential(credential, expected_tenant=other).account == "vm-identity"


def test_provider_reports_who_it_signed_in_as(azure_fixtures: Path) -> None:
    credential = FakeCredential(token=fake_jwt(tid=TENANT, upn="founder@example.com"))
    provider = AzureProvider(ProviderOptions(tenant=TENANT), credential=credential, runner=None)
    assert provider.identity is None
    provider.authenticate()
    assert provider.identity == f"founder@example.com in tenant {TENANT}"
