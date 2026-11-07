"""Azure provider. Requires the ``azure`` extra: ``pip install 'skyveda[azure]'``."""

from __future__ import annotations

from typing import TYPE_CHECKING

from skyveda.core.errors import ProviderNotFoundError

if TYPE_CHECKING:
    from skyveda.core.provider import Provider, ProviderOptions


def create_provider(options: ProviderOptions) -> Provider:
    """Entry-point factory. Imports Azure SDKs lazily so the core works without them."""
    try:
        from skyveda.providers.azure.provider import AzureProvider
    except ImportError as exc:
        raise ProviderNotFoundError(
            "The Azure provider needs extra packages: pip install 'skyveda[azure]'"
        ) from exc
    return AzureProvider(options)
