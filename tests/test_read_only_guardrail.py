"""Hard requirement: provider code must only read. Fail CI if a mutating or secret-reading SDK
method is ever called anywhere under src/skyveda/providers."""

from __future__ import annotations

import ast
import re
from pathlib import Path

PROVIDERS_DIR = Path(__file__).parents[1] / "src" / "skyveda" / "providers"

FORBIDDEN = re.compile(
    r"^(begin_\w+|create\w*|update\w*|delete\w*|put\w*|patch\w*|set_\w+|purge\w*|"
    r"start|stop|restart|deallocate|regenerate\w*|list_keys|list_secrets|get_secret\w*|"
    r"list_credentials|list_admin_credential\w*|list_user_credential\w*|"
    r"list_cluster_admin_credential\w*|list_cluster_user_credential\w*)$"
)


def _forbidden_calls(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [
        f"{path.name}:{node.lineno} .{node.func.attr}()"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and FORBIDDEN.match(node.func.attr)
    ]


def test_provider_code_never_calls_mutating_or_secret_apis() -> None:
    files = list(PROVIDERS_DIR.rglob("*.py"))
    assert files, "provider sources not found"
    violations = [call for path in files for call in _forbidden_calls(path)]
    assert violations == []


def test_guardrail_detects_violations(tmp_path: Path) -> None:
    sample = tmp_path / "bad.py"
    sample.write_text("client.managed_clusters.begin_delete('rg', 'aks')\nkv.get_secret('x')\n")
    assert len(_forbidden_calls(sample)) == 2


def test_arm_reader_only_ever_builds_get_requests() -> None:
    """The ARM client sends raw HTTP, so the method name check above cannot see its verbs."""
    tree = ast.parse((PROVIDERS_DIR / "azure" / "arm.py").read_text(encoding="utf-8"))
    requests = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "HttpRequest"
    ]
    assert requests, "arm.py builds no HttpRequest: update this test"
    verbs = [
        node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else None
        for node in requests
    ]
    assert verbs == ["GET"] * len(requests)


def test_cost_reader_posts_only_to_a_checked_cost_query() -> None:
    """D-028: the one POST in provider code reads billed cost, and only via _checked_query_url."""
    tree = ast.parse((PROVIDERS_DIR / "azure" / "costs.py").read_text(encoding="utf-8"))
    requests = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "HttpRequest"
    ]
    assert len(requests) == 1, "costs.py should build exactly one HttpRequest: update this test"
    (request,) = requests
    assert isinstance(request.args[0], ast.Constant)
    assert request.args[0].value == "POST"
    url = request.args[1]
    assert isinstance(url, ast.Call)
    assert isinstance(url.func, ast.Name)
    assert url.func.id == "_checked_query_url"
    others = [
        path.name
        for path in PROVIDERS_DIR.rglob("*.py")
        if path.name != "costs.py" and '"POST"' in path.read_text(encoding="utf-8")
    ]
    assert others == []
