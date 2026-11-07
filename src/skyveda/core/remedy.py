"""Fill remedy templates from a failing resource. Pure text work: nothing here runs a command.

Placeholders are ``{name}`` with letters, digits and underscores. Values are shell-quoted when
they need it, and a list becomes space-separated words (for a shell ``for`` loop).
"""

from __future__ import annotations

import re
import shlex

from pydantic import JsonValue

from skyveda.core.errors import RemedyError
from skyveda.core.models import AffectedResource, Check, Remedy, RowsEvaluator

PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_SUBSCRIPTION = re.compile(r"^/subscriptions/([^/]+)/", re.IGNORECASE)
_PROJECT_STAGE = re.compile(r"^project\s")
_ALIAS = re.compile(r"^([A-Za-z_]\w*)\s*=(?!=)")
_IDENTIFIER = re.compile(r"^[A-Za-z_]\w*$")
_CONTROL = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]"
)
ALWAYS = frozenset({"id", "name", "subscriptionId"})


def clean_text(text: str) -> str:
    """Replace control, line-break and bidi/format characters with a space (for display)."""
    return _CONTROL.sub(" ", text)


def has_control(text: str) -> bool:
    return _CONTROL.search(text) is not None


def placeholders(text: str) -> set[str]:
    return set(PLACEHOLDER.findall(text))


def used_fields(remedy: Remedy) -> set[str]:
    """Fields the before, az, rollback and verify templates use."""
    return (
        placeholders(remedy.before)
        | placeholders(remedy.az)
        | placeholders(remedy.rollback)
        | placeholders(remedy.verify)
    )


def subscription_of(resource_id: str) -> str | None:
    match = _SUBSCRIPTION.match(resource_id)
    return match.group(1) if match else None


def resource_values(resource: AffectedResource) -> dict[str, JsonValue]:
    """The fields a template may use for one failing resource."""
    if has_control(resource.id) or has_control(resource.name or ""):
        raise RemedyError("the resource id or name holds control or direction characters")
    values: dict[str, JsonValue] = dict(resource.evidence)
    values["id"] = resource.id
    values["name"] = resource.name
    values["subscriptionId"] = subscription_of(resource.id)
    return values


def render(template: str, values: dict[str, JsonValue]) -> str:
    """Fill ``{field}`` placeholders; raise RemedyError if a field is missing or has no value."""

    def fill(match: re.Match[str]) -> str:
        field = match.group(1)
        if field not in values:
            raise RemedyError(f"no field '{field}' on this resource")
        return _shell_value(field, values[field])

    return PLACEHOLDER.sub(fill, template)


def _shell_value(field: str, value: JsonValue) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, str) and _usable(value):
        return shlex.quote(value)
    if isinstance(value, list) and value and all(isinstance(i, str) and _usable(i) for i in value):
        return " ".join(shlex.quote(str(item)) for item in value)
    raise RemedyError(f"field '{field}' has no usable value")


def _usable(text: str) -> bool:
    """Not empty, no control characters, and not readable as a command option."""
    return bool(text) and not text.startswith("-") and not _CONTROL.search(text)


def unknown_remedy_fields(check: Check) -> list[str]:
    """Placeholders a check's remedy uses that its query does not project, sorted.

    Only checked for ``rows`` checks whose query ends in a plain ``project`` of named columns.
    Python evaluators and collectors build their evidence in code: the tests cover those.
    """
    if check.remedy is None or not isinstance(check.evaluate, RowsEvaluator):
        return []
    columns = projected_columns(check.source.query or "")
    if columns is None:
        return []
    spec = check.evaluate
    hidden = {spec.compliant_field, spec.resource_id_field, spec.name_field}
    available = (columns - hidden) | ALWAYS
    return sorted(used_fields(check.remedy) - available)


def projected_columns(query: str) -> set[str] | None:
    """Column names of the query's final ``project``, or None if they cannot be read reliably."""
    text = "\n".join(_strip_comment(line) for line in query.splitlines())
    stages = _split_top_level(text, "|")
    if not stages:
        return None
    last = stages[-1].strip()
    if not _PROJECT_STAGE.match(last):
        return None
    names: set[str] = set()
    for raw in _split_top_level(last[len("project") :], ","):
        item = raw.strip()
        alias = _ALIAS.match(item)
        if alias:
            names.add(alias.group(1))
        elif _IDENTIFIER.match(item):
            names.add(item)
        else:
            return None  # an unnamed expression gets a name KQL chooses: do not guess
    return names


def _strip_comment(line: str) -> str:
    """Cut a ``//`` comment, but not a ``//`` inside a quoted string."""
    quote = ""
    for position, char in enumerate(line):
        if quote:
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif line.startswith("//", position):
            return line[:position]
    return line


def _split_top_level(text: str, separator: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    quote = ""
    current: list[str] = []
    for char in text:
        if quote:
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == separator and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return [part for part in parts if part.strip()]
