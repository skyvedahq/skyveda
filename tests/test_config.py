from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from skyveda.cli import app
from skyveda.core.config import load_config
from skyveda.core.errors import ConfigLoadError
from skyveda.core.models import Severity

runner = CliRunner()


def test_load_config_resolves_paths_against_the_file(tmp_path: Path) -> None:
    path = tmp_path / "skyveda.toml"
    path.write_text(
        'schema_version = 1\n[scan]\nsubscriptions = ["a", "b"]\nfail_on = "high"\n'
        'out = "skyveda-out"\nwaivers = "waivers.yaml"\nchecks_dirs = ["extra"]\n',
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.subscriptions == ["a", "b"]
    assert config.fail_on is Severity.HIGH
    assert config.out == tmp_path / "skyveda-out"
    assert config.waivers == tmp_path / "waivers.yaml"
    assert config.checks_dirs == [tmp_path / "extra"]


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ('[scan]\nsubscription = ["a"]\n', "subscription"),  # typo: the key is plural
        ('[scan]\nfail_on = "urgent"\n', "fail_on"),
        ('[scan]\nclient_secret = "x"\n', "client_secret"),  # credentials have no place here
        ("[scan\n", "not valid TOML"),
    ],
)
def test_load_config_names_the_problem(tmp_path: Path, text: str, problem: str) -> None:
    path = tmp_path / "skyveda.toml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigLoadError, match=problem):
        load_config(path)


def write_config(folder: Path) -> Path:
    (folder / "waivers.yaml").write_text(
        "waivers:\n  - check: AZ-STG-001\n"
        "    reason: r\n    approver: a\n    expires: 2099-01-01\n",
        encoding="utf-8",
    )
    path = folder / "skyveda.toml"
    path.write_text(
        '[scan]\nout = "from-config"\nfail_on = "high"\nlabel = "Prepared for cust-001"\n'
        'waivers = "waivers.yaml"\n',
        encoding="utf-8",
    )
    return path


def test_scan_takes_options_from_the_config(azure_fixtures: Path, tmp_path: Path) -> None:
    config = write_config(tmp_path)
    result = runner.invoke(app, ["scan", "--offline", str(azure_fixtures), "--config", str(config)])
    assert result.exit_code == 2, result.output  # fail_on = high, and high findings remain
    html = (tmp_path / "from-config" / "report.html").read_text("utf-8")
    assert "Prepared for cust-001" in html
    assert "1 resource(s) waived" in result.output


def test_typed_options_override_the_config(azure_fixtures: Path, tmp_path: Path) -> None:
    config = write_config(tmp_path)
    typed_out = tmp_path / "typed"
    args = ["scan", "--offline", str(azure_fixtures), "--config", str(config)]
    # --fail-on critical equals the built-in default, but typed it must still beat the config.
    result = runner.invoke(app, [*args, "--out", str(typed_out), "--fail-on", "critical"])
    assert (typed_out / "report.html").is_file()
    assert not (tmp_path / "from-config").exists()
    assert result.exit_code == 2  # the fixtures' critical NSG finding is not waived


def test_scopes_reads_the_config(azure_fixtures: Path, tmp_path: Path) -> None:
    config = write_config(tmp_path)
    result = runner.invoke(
        app, ["scopes", "--offline", str(azure_fixtures), "--config", str(config)]
    )
    assert result.exit_code == 0, result.output
    assert "Config:" in result.output
