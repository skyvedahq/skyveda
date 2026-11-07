"""Expected, user-facing errors. Anything else is a bug and surfaces as a traceback with -v."""


class SkyvedaError(Exception):
    """Base class for errors the CLI reports as a one-line message with exit code 1."""


class AuthenticationError(SkyvedaError):
    """No usable credential, or the credential was rejected."""


class PermissionDeniedError(SkyvedaError):
    """The credential is valid but lacks read access to the requested data."""


class QueryError(SkyvedaError):
    """A provider query failed for a non-permission reason (bad query, service error)."""


class ProviderNotFoundError(SkyvedaError):
    """No provider plugin is registered under the requested name."""


class UnsupportedSourceError(SkyvedaError):
    """A check uses a source type the selected provider does not implement."""


class FixtureNotFoundError(SkyvedaError):
    """Offline mode could not find a recorded response for a request."""


class ScopeError(SkyvedaError):
    """A requested scope (subscription, management group, ...) is invalid or not accessible."""


class CheckLoadError(SkyvedaError):
    """One or more check definitions are malformed, duplicated or reference unknown code."""


class EvaluationError(SkyvedaError):
    """A check's data could not be evaluated, e.g. the query did not return a compliance column."""


class ConfigLoadError(SkyvedaError):
    """A skyveda.toml file is missing, not valid TOML, or has an invalid option."""


class ReportError(SkyvedaError):
    """A report file could not be produced from the scan result."""


class WaiverLoadError(SkyvedaError):
    """A waivers file is missing, not valid YAML, or has an invalid entry."""


class WaiverApplyError(SkyvedaError):
    """Waivers cannot be applied safely to this scan result."""


class RemedyError(SkyvedaError):
    """A remedy template cannot be filled in from a resource's fields."""
