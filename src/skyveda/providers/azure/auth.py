"""Azure authentication.

``default`` is DefaultAzureCredential: service principal / workload identity env vars, then
managed identity, then developer logins (``az login``, ``azd``, PowerShell). On an Azure VM the
VM's managed identity therefore wins over ``az login``; ``--auth cli`` picks the developer login
explicitly. Interactive browser login is disabled so the CLI never pops a window during an
unattended run. Tokens are never logged or persisted; only their tenant and account claims are
read, to show who is scanning and to refuse a token from the wrong tenant.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any

from azure.core.credentials import AccessToken, TokenCredential
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import (
    AzureCliCredential,
    DefaultAzureCredential,
    EnvironmentCredential,
    ManagedIdentityCredential,
)

from skyveda.core.errors import AuthenticationError

ARM_SCOPE = "https://management.azure.com/.default"
AUTH_METHODS = ("default", "cli", "managed-identity", "environment")


@dataclass(frozen=True, slots=True)
class Identity:
    """Who a token belongs to, read from its claims. Either part may be unknown."""

    tenant_id: str | None
    account: str | None

    def __str__(self) -> str:
        return f"{self.account or 'unknown account'} in tenant {self.tenant_id or 'unknown'}"


class TenantPinnedCredential:
    """Requests every token for a fixed tenant, so ``--tenant`` works with ``az login`` too."""

    def __init__(self, inner: TokenCredential, tenant_id: str) -> None:
        self._inner = inner
        self._tenant_id = tenant_id

    def get_token(
        self,
        *scopes: str,
        claims: str | None = None,
        tenant_id: str | None = None,
        enable_cae: bool = False,
        **kwargs: Any,
    ) -> AccessToken:
        return self._inner.get_token(
            *scopes,
            claims=claims,
            tenant_id=tenant_id or self._tenant_id,
            enable_cae=enable_cae,
            **kwargs,
        )

    def close(self) -> None:
        close = getattr(self._inner, "close", None)
        if callable(close):
            close()


def build_credential(tenant_id: str | None = None, method: str = "default") -> TokenCredential:
    allowed = [tenant_id] if tenant_id else []
    credential: TokenCredential
    if method == "default":
        credential = DefaultAzureCredential(
            exclude_interactive_browser_credential=True, additionally_allowed_tenants=allowed
        )
    elif method == "cli":
        credential = AzureCliCredential(tenant_id=tenant_id or "")
    elif method == "managed-identity":
        credential = ManagedIdentityCredential()
    elif method == "environment":
        credential = EnvironmentCredential()
    else:
        raise AuthenticationError(
            f"Unknown auth method '{method}'. Use one of: {', '.join(AUTH_METHODS)}."
        )
    if tenant_id:
        return TenantPinnedCredential(credential, tenant_id)
    return credential


def verify_credential(credential: TokenCredential, expected_tenant: str | None = None) -> Identity:
    """Fail fast with actionable guidance instead of a deep SDK error on the first query.

    With ``expected_tenant``, a token issued by any other tenant is refused before a single
    query runs, e.g. when an Azure VM's managed identity is picked instead of ``az login``.
    """
    try:
        token = credential.get_token(ARM_SCOPE)
    except ClientAuthenticationError as exc:
        raise AuthenticationError(
            "Could not authenticate to Azure. Run 'az login' (add '--tenant <id>' if needed), "
            "or set AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET for a service "
            f"principal. Details: {_first_line(exc.message)}"
        ) from exc
    identity = token_identity(token.token)
    if expected_tenant and (identity.tenant_id or "").lower() != expected_tenant.lower():
        raise AuthenticationError(
            f"The credential signed in as {identity}, not tenant {expected_tenant}. "
            "On an Azure VM the VM's managed identity is tried before 'az login'; "
            "use '--auth cli' to scan with your 'az login' account."
        )
    return identity


def token_identity(token: str) -> Identity:
    """Read the tenant and account claims of a JWT access token. The signature is not checked:
    this is for display and a tenant sanity check, never for authorisation."""
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError, binascii.Error):
        return Identity(tenant_id=None, account=None)
    if not isinstance(claims, dict):
        return Identity(tenant_id=None, account=None)
    account = next(
        (claims[key] for key in ("upn", "unique_name", "email", "appid") if claims.get(key)),
        None,
    )
    tenant = claims.get("tid")
    return Identity(
        tenant_id=tenant if isinstance(tenant, str) else None,
        account=account if isinstance(account, str) else "managed identity or app",
    )


def _first_line(text: str | None) -> str:
    return (text or "no details").strip().splitlines()[0]
