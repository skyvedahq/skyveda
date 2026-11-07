"""Read-only Azure Resource Manager client for settings Resource Graph does not index.

Resource Graph leaves out some settings checks need, e.g. SQL firewall rules and App Service
site configuration. This client reads them with plain ARM GET requests. It can only send GET:
`_send` is the one place a request is built, and it always builds a GET (a guardrail test checks
this). Paging follows ``nextLink`` only on management.azure.com, so the bearer token is never sent
anywhere else.

Errors: 401/403 become PermissionDeniedError (the check is skipped), 404 means the resource went
away during the scan (None), 408/429/5xx are retried honouring ``Retry-After``.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator, Mapping
from typing import Any, Protocol
from urllib.parse import quote, urlsplit

from azure.core import PipelineClient
from azure.core.credentials import TokenCredential
from azure.core.exceptions import ServiceRequestError, ServiceResponseError
from azure.core.pipeline.policies import BearerTokenCredentialPolicy, UserAgentPolicy
from azure.core.rest import HttpRequest

from skyveda import __version__
from skyveda.core.errors import PermissionDeniedError, QueryError
from skyveda.core.retry import Retry, RetryPolicy, call_with_retry
from skyveda.providers.azure.auth import ARM_SCOPE

log = logging.getLogger(__name__)

ARM_ENDPOINT = "https://management.azure.com"
RETRYABLE_STATUS_CODES = frozenset({408, 429, 500, 502, 503, 504})
MAX_PAGES = 1000


class ArmResponse(Protocol):
    @property
    def status_code(self) -> int: ...

    @property
    def headers(self) -> Mapping[str, str]: ...

    def json(self) -> Any: ...

    def text(self) -> str: ...


Send = Callable[[str], ArmResponse]
"""Sends a GET to an absolute management.azure.com URL and returns the response."""


class TransientError(Exception):
    """A retryable HTTP status, carrying the server's Retry-After."""

    def __init__(self, status: int, after_seconds: float | None) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status
        self.after_seconds = after_seconds


class ArmReader:
    def __init__(
        self,
        send: Send,
        *,
        policy: RetryPolicy | None = None,
        sleep: Callable[[float], None] = time.sleep,
        on_close: Callable[[], None] | None = None,
    ) -> None:
        self._send = send
        self._policy = policy or RetryPolicy()
        self._sleep = sleep
        self._on_close = on_close

    @classmethod
    def from_credential(cls, credential: TokenCredential) -> ArmReader:
        client: PipelineClient[HttpRequest, Any] = PipelineClient(
            base_url=ARM_ENDPOINT,
            policies=[
                UserAgentPolicy(f"skyveda-scan/{__version__}"),
                BearerTokenCredentialPolicy(credential, ARM_SCOPE),
            ],
        )

        def send(url: str) -> ArmResponse:
            response = client.send_request(HttpRequest("GET", url))
            response.read()
            return response  # type: ignore[no-any-return]

        return cls(send, on_close=client.close)

    def get(self, resource_path: str, api_version: str) -> dict[str, Any] | None:
        """GET one ARM object, e.g. ``<site id>/config/web``. None if it no longer exists."""
        return self._get_json(_url(resource_path, api_version))

    def list(self, collection_path: str, api_version: str) -> list[dict[str, Any]]:
        """GET every item of an ARM collection, following ``nextLink`` pages."""
        return list(self._items(_url(collection_path, api_version)))

    def close(self) -> None:
        if self._on_close is not None:
            self._on_close()

    def _items(self, url: str) -> Iterator[dict[str, Any]]:
        for _ in range(MAX_PAGES):
            page = self._get_json(url)
            if page is None:
                return
            values = page.get("value", [])
            if not isinstance(values, list):
                raise QueryError("Azure Resource Manager returned an unexpected list format.")
            yield from (item for item in values if isinstance(item, dict))
            next_link = page.get("nextLink")
            if not next_link:
                return
            url = checked_next_link(str(next_link))
        raise QueryError(f"Azure Resource Manager returned more than {MAX_PAGES} pages.")

    def _get_json(self, url: str) -> dict[str, Any] | None:
        try:
            response = call_with_retry(
                lambda: self._send_once(url),
                classify=classify_retry,
                policy=self._policy,
                sleep=self._sleep,
            )
        except TransientError as exc:
            raise QueryError(f"Azure Resource Manager kept failing (HTTP {exc.status}).") from exc
        except (ServiceRequestError, ServiceResponseError) as exc:
            raise QueryError(f"Could not reach Azure Resource Manager: {exc.message}") from exc
        if response is None:
            return None
        body = response.json()
        if not isinstance(body, dict):
            raise QueryError("Azure Resource Manager returned an unexpected result format.")
        return body

    def _send_once(self, url: str) -> ArmResponse | None:
        response = self._send(url)
        status = response.status_code
        if status == 200:
            return response
        if status == 404:
            log.debug("ARM 404 (resource gone during the scan): %s", path_of(url))
            return None
        if status in (401, 403):
            raise PermissionDeniedError(
                f"No read access to {path_of(url)} (HTTP {status}). Reader is enough."
            )
        if status in RETRYABLE_STATUS_CODES:
            raise TransientError(status, retry_after(response.headers))
        raise QueryError(f"Azure Resource Manager GET failed (HTTP {status}): {path_of(url)}")


def classify_retry(exc: Exception) -> Retry | None:
    if isinstance(exc, TransientError):
        return Retry(after_seconds=exc.after_seconds, throttled=exc.status == 429)
    if isinstance(exc, ServiceRequestError | ServiceResponseError):
        return Retry()
    return None


def _url(path: str, api_version: str) -> str:
    if not path.startswith("/subscriptions/"):
        raise QueryError(f"Not an ARM resource path: {path!r}")
    return f"{ARM_ENDPOINT}{quote(path)}?api-version={quote(api_version)}"


def checked_next_link(link: str) -> str:
    """Only follow pages on ARM itself: the bearer token must never go to another host."""
    parts = urlsplit(link)
    if parts.scheme != "https" or parts.hostname != urlsplit(ARM_ENDPOINT).hostname:
        raise QueryError(f"Refusing to follow a nextLink outside {ARM_ENDPOINT}.")
    return link


def retry_after(headers: Mapping[str, str]) -> float | None:
    value = headers.get("Retry-After") or headers.get("retry-after")
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None


def path_of(url: str) -> str:
    return urlsplit(url).path
