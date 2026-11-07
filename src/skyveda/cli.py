"""Command-line interface: ``skyveda scan | scopes | list-checks | report | fixes``."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import IntEnum
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from skyveda import __version__
from skyveda.core.checks import load_checks
from skyveda.core.config import ScanConfig, load_config
from skyveda.core.engine import FINDINGS_FILE, nothing_ran, run_scan, write_findings
from skyveda.core.errors import ReportError, SkyvedaError
from skyveda.core.models import CostSource, ScanResult, Scope, Severity, Status
from skyveda.core.offline import OfflineProvider
from skyveda.core.provider import Provider, ProviderOptions, load_provider
from skyveda.core.waivers import apply_waivers, load_waivers
from skyveda.report import write_report
from skyveda.report.fixpack import write_fix_pack
from skyveda.report.pdf import write_pdf
from skyveda.report.summary import waste_basis

log = logging.getLogger(__name__)


class ExitCode(IntEnum):
    OK = 0
    ERROR = 1
    FINDINGS_AT_THRESHOLD = 2


app = typer.Typer(
    name="skyveda",
    help="Skyveda Scan: read-only cloud platform health checks with a scored report.",
    no_args_is_help=True,
    add_completion=False,
    # Never render local variables in tracebacks: they could contain tokens.
    pretty_exceptions_show_locals=False,
)
console = Console()
err_console = Console(stderr=True)

ProviderOpt = Annotated[str, typer.Option("--provider", "-p", help="Cloud provider to scan.")]
SubscriptionOpt = Annotated[
    list[str] | None,
    typer.Option(
        "--subscription",
        "-s",
        help="Subscription ID to scan. Repeat or comma-separate. Default: all readable.",
    ),
]
ManagementGroupOpt = Annotated[
    list[str] | None,
    typer.Option(
        "--management-group",
        "-m",
        help="Scan every subscription under this management group. Repeatable.",
    ),
]
TenantOpt = Annotated[
    str | None, typer.Option("--tenant", "-t", help="Entra tenant ID to authenticate against.")
]
AuthOpt = Annotated[
    str,
    typer.Option(
        "--auth",
        help="Credential: default (SDK chain; on an Azure VM its managed identity wins), "
        "cli (your 'az login'), managed-identity or environment.",
    ),
]
PdfOpt = Annotated[
    bool, typer.Option("--pdf", help="Also write report.pdf, for forwarding and printing.")
]
LabelOpt = Annotated[
    str | None,
    typer.Option("--label", help="Line shown under the report title, e.g. who it is for."),
]
ConfigOpt = Annotated[
    Path | None,
    typer.Option(
        "--config",
        help="skyveda.toml with saved options. Options typed here override it.",
        dir_okay=False,
        exists=True,
    ),
]
WaiversOpt = Annotated[
    Path | None,
    typer.Option(
        "--waivers",
        help="waivers.yaml: accepted risks and false positives to take out of the findings.",
        dir_okay=False,
        exists=True,
    ),
]
CostSourceOpt = Annotated[
    CostSource,
    typer.Option(
        "--cost-source",
        help="billed: price cost findings from the cloud's billing data where it has them, "
        "falling back to list prices (needs only Reader). estimate: list prices only.",
    ),
]
OfflineOpt = Annotated[
    Path | None,
    typer.Option(
        "--offline",
        help="Use recorded responses from this directory instead of calling the cloud.",
        file_okay=False,
        exists=True,
    ),
]


def _print_version(value: bool) -> None:
    if value:
        console.print(f"skyveda {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_print_version, is_eager=True, help="Show version and exit."
        ),
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Debug logging.")] = False,
) -> None:
    """Skyveda Scan. Read-only: never creates, changes or deletes cloud resources."""
    _configure_logging(verbose)


@app.command()
def scopes(
    ctx: typer.Context,
    provider: ProviderOpt = "azure",
    subscription: SubscriptionOpt = None,
    management_group: ManagementGroupOpt = None,
    tenant: TenantOpt = None,
    auth: AuthOpt = "default",
    offline: OfflineOpt = None,
    config: ConfigOpt = None,
) -> None:
    """List the scopes (e.g. subscriptions) the current credentials can scan."""
    with _handle_errors():
        saved = _load_config(config)
        provider = _pick(ctx, "provider", provider, saved.provider)
        subscription = _pick(ctx, "subscription", subscription, saved.subscriptions or None)
        management_group = _pick(
            ctx, "management_group", management_group, saved.management_groups or None
        )
        tenant = _pick(ctx, "tenant", tenant, saved.tenant)
        auth = _pick(ctx, "auth", auth, saved.auth)
        options = _options(tenant, auth, subscription, management_group)
        with _open_provider(provider, options, offline) as cloud:
            _print_scopes(cloud.list_scopes())


@app.command()
def scan(
    ctx: typer.Context,
    provider: ProviderOpt = "azure",
    subscription: SubscriptionOpt = None,
    management_group: ManagementGroupOpt = None,
    tenant: TenantOpt = None,
    auth: AuthOpt = "default",
    offline: OfflineOpt = None,
    out: Annotated[Path, typer.Option("--out", "-o", help="Output directory.")] = Path("out"),
    checks_dir: Annotated[
        list[Path] | None,
        typer.Option("--checks-dir", help="Extra directory of check YAML files. Repeatable."),
    ] = None,
    fail_on: Annotated[
        Severity, typer.Option("--fail-on", help="Exit 2 if any finding is at this severity+.")
    ] = Severity.CRITICAL,
    label: LabelOpt = None,
    waivers: WaiversOpt = None,
    pdf: PdfOpt = False,
    cost_source: CostSourceOpt = CostSource.BILLED,
    config: ConfigOpt = None,
) -> None:
    """Run checks and write findings.json and report.html to --out."""
    with _handle_errors():
        saved = _load_config(config)
        provider = _pick(ctx, "provider", provider, saved.provider)
        subscription = _pick(ctx, "subscription", subscription, saved.subscriptions or None)
        management_group = _pick(
            ctx, "management_group", management_group, saved.management_groups or None
        )
        tenant = _pick(ctx, "tenant", tenant, saved.tenant)
        auth = _pick(ctx, "auth", auth, saved.auth)
        out = _pick(ctx, "out", out, saved.out)
        checks_dir = _pick(ctx, "checks_dir", checks_dir, saved.checks_dirs or None)
        fail_on = _pick(ctx, "fail_on", fail_on, saved.fail_on)
        label = _pick(ctx, "label", label, saved.label)
        pdf = _pick(ctx, "pdf", pdf, saved.pdf)
        waivers = _pick(ctx, "waivers", waivers, saved.waivers)
        cost_source = _pick(ctx, "cost_source", cost_source, saved.cost_source)
        options = _options(tenant, auth, subscription, management_group)
        checks = load_checks(provider, checks_dir or [])
        with _open_provider(provider, options, offline) as cloud:
            found = cloud.list_scopes()
            _print_scopes(found)
            result = run_scan(
                cloud,
                checks,
                found,
                offline=offline is not None,
                billed_cost=cost_source is CostSource.BILLED,
            )
        result = _waive(result, waivers)
        findings_path = write_findings(result, out)
        findings_text = findings_path.read_text(encoding="utf-8")
        report_path = write_report(result, findings_text, out, label)
        if pdf:
            _write_pdf(result, findings_text, out, label)
    _print_summary(result)
    console.print(f"Wrote [bold]{findings_path}[/] and [bold]{report_path}[/]")
    raise typer.Exit(_exit_code(result, fail_on))


@app.command("list-checks")
def list_checks(
    provider: ProviderOpt = "azure",
    checks_dir: Annotated[
        list[Path] | None,
        typer.Option("--checks-dir", help="Extra directory of check YAML files. Repeatable."),
    ] = None,
) -> None:
    """List the available checks."""
    with _handle_errors():
        checks = load_checks(provider, checks_dir or [])
    table = Table(title=f"{len(checks)} check(s)")
    for column in ("ID", "Severity", "Area", "Tier", "Title"):
        table.add_column(column)
    for check in checks:
        table.add_row(check.id, check.severity, check.area, check.tier, check.title)
    console.print(table)


@app.command("validate-checks")
def validate_checks(
    checks_dir: Annotated[
        list[Path] | None,
        typer.Option("--checks-dir", help="Extra directory of check YAML files. Repeatable."),
    ] = None,
) -> None:
    """Validate every built-in check (and --checks-dir) and report problems."""
    with _handle_errors():
        checks = load_checks(None, checks_dir or [])
    console.print(f"[green]All {len(checks)} check(s) are valid.[/]")


@app.command()
def report(
    findings: Annotated[
        Path, typer.Argument(help="findings.json produced by 'skyveda scan'.", exists=True)
    ],
    out: Annotated[Path, typer.Option("--out", "-o", help="Output directory.")] = Path("out"),
    label: LabelOpt = None,
    waivers: WaiversOpt = None,
    pdf: PdfOpt = False,
) -> None:
    """Re-render report.html from an existing findings.json.

    With --waivers, also writes the waived findings.json to --out; the input file is never changed.
    """
    text = findings.read_text(encoding="utf-8")
    try:
        result = ScanResult.model_validate_json(text)
    except ValidationError as exc:
        err_console.print(f"[bold red]Error:[/] {findings} is not a valid findings.json.")
        raise typer.Exit(ExitCode.ERROR) from exc
    with _handle_errors():
        if waivers is not None:
            if (out / FINDINGS_FILE).resolve() == findings.resolve():
                err_console.print(
                    "[bold red]Error:[/] --out would overwrite the input findings.json; "
                    "choose another directory."
                )
                raise typer.Exit(ExitCode.ERROR)
            result = _waive(result, waivers)
            written = write_findings(result, out)
            text = written.read_text(encoding="utf-8")
            console.print(f"Wrote [bold]{written}[/]")
        path = write_report(result, text, out, label)
        if pdf:
            _write_pdf(result, text, out, label)
    console.print(f"Wrote [bold]{path}[/]")


@app.command()
def fixes(
    findings: Annotated[
        Path, typer.Argument(help="findings.json produced by 'skyveda scan'.", exists=True)
    ],
    out: Annotated[Path, typer.Option("--out", "-o", help="Output directory.")] = Path("fixes"),
    waivers: WaiversOpt = None,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Write into a non-empty --out, first removing a previous fix pack's "
            "<check-id>/*.sh, README.md and PULL_REQUEST.md (nothing else).",
        ),
    ] = False,
) -> None:
    """Write a fix pack: a plan and reviewable az scripts, with every command commented out.

    Files only: Skyveda never runs a fix. The input findings.json is never changed.
    """
    text = findings.read_text(encoding="utf-8")
    try:
        result = ScanResult.model_validate_json(text)
    except ValidationError as exc:
        err_console.print(f"[bold red]Error:[/] {findings} is not a valid findings.json.")
        raise typer.Exit(ExitCode.ERROR) from exc
    with _handle_errors():
        result = _waive(result, waivers)
        checks = load_checks(result.provider)
        written = write_fix_pack(result, checks, out, force=force)
    console.print(f"Wrote {len(written)} file(s) to [bold]{out}[/], start with README.md")


# --------------------------------------------------------------------------- helpers


def _options(
    tenant: str | None, auth: str, subscriptions: list[str] | None, groups: list[str] | None
) -> ProviderOptions:
    return ProviderOptions(
        tenant=tenant,
        auth=auth,
        scope_ids=_split_values(subscriptions),
        scope_group_ids=_split_values(groups),
    )


def _split_values(values: list[str] | None) -> tuple[str, ...]:
    """Accept both repeated options and comma-separated lists."""
    return tuple(
        part.strip() for value in values or [] for part in value.split(",") if part.strip()
    )


@contextmanager
def _open_provider(name: str, options: ProviderOptions, offline: Path | None) -> Iterator[Provider]:
    cloud: Provider = OfflineProvider(name, offline) if offline else load_provider(name, options)
    try:
        cloud.authenticate()
        console.print(f"Signed in as [bold]{cloud.identity}[/]")
        yield cloud
    finally:
        cloud.close()


@contextmanager
def _handle_errors() -> Iterator[None]:
    try:
        yield
    except SkyvedaError as exc:
        log.debug("Command failed", exc_info=True)
        err_console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(ExitCode.ERROR) from exc


def _write_pdf(result: ScanResult, findings_json: str, out: Path, label: str | None) -> None:
    """The PDF is a convenience copy: if it fails, warn and keep the scan's result."""
    try:
        console.print(f"Wrote [bold]{write_pdf(result, findings_json, out, label)}[/]")
    except ReportError as exc:
        err_console.print(f"[yellow]Warning:[/] {exc} findings.json and report.html are complete.")


def _load_config(path: Path | None) -> ScanConfig:
    if path is None:
        return ScanConfig()
    console.print(f"Config: {path}")
    return load_config(path)


def _pick[T](ctx: typer.Context, name: str, typed: T, saved: T | None) -> T:
    """The typed value if the option was given, else the config value, else the default."""
    source = ctx.get_parameter_source(name)  # compared by name: Typer bundles a private Click
    if saved is None or (source is not None and source.name != "DEFAULT"):
        return typed
    return saved


def _waive(result: ScanResult, path: Path | None) -> ScanResult:
    """Apply the waivers file, if any, and warn about expired or unmatched waivers."""
    if path is None:
        return result
    today = datetime.now(UTC).astimezone().date()  # the local date: expiry dates are local
    outcome = apply_waivers(result, load_waivers(path), today)
    applied = sum(len(item.waived) for item in outcome.result.results)
    console.print(f"Waivers: {applied} resource(s) waived from {path}")
    for waiver in outcome.expired:
        err_console.print(f"[yellow]Waiver expired {waiver.expires}:[/] {waiver.check} not waived")
    for waiver in outcome.unused:
        target = waiver.resource or "all resources"
        err_console.print(f"[yellow]Waiver matched nothing:[/] {waiver.check} {target}")
    return outcome.result


def _print_scopes(found: list[Scope]) -> None:
    table = Table(title=f"{len(found)} scope(s)")
    table.add_column("Kind")
    table.add_column("ID")
    table.add_column("Name")
    for scope in found:
        table.add_row(scope.kind, scope.id, scope.name or "")
    console.print(table)


_STATUS_STYLE = {
    Status.FAIL: "red",
    Status.PASS: "green",
    Status.NOT_APPLICABLE: "dim",
    Status.ERROR: "yellow",
    Status.SKIPPED: "yellow",
}
TOP_FINDINGS = 5


def _print_summary(result: ScanResult) -> None:
    counts = result.count_by_status()
    console.print(
        "  ".join(f"[{_STATUS_STYLE[s]}]{s.value}: {n}[/]" for s, n in counts.items() if n)
    )
    findings = result.findings
    waste = sum(f.est_monthly_waste_inr or 0 for f in findings)
    # "INR", not the rupee sign: legacy Windows consoles (cp1252) cannot encode it.
    basis = waste_basis((r for f in findings for r in f.resources), currency="INR ")
    if waste:
        console.print(f"Waste: [bold]INR {waste:,} a month[/] ({basis})")
    elif basis:
        console.print(f"Waste: not known ({basis})")
    for note in result.billing.notes if result.billing else []:
        err_console.print(f"[yellow]Cost:[/] {note.replace('₹', 'INR ')}")
    if findings:
        table = Table(title=f"Top {min(TOP_FINDINGS, len(findings))} of {len(findings)} finding(s)")
        for column in ("Severity", "Check", "Title", "Resources"):
            table.add_column(column)
        for finding in findings[:TOP_FINDINGS]:
            table.add_row(
                finding.severity, finding.check_id, finding.title, str(len(finding.resources))
            )
        console.print(table)
    for item in result.results:
        if item.status in (Status.ERROR, Status.SKIPPED):
            err_console.print(f"[yellow]{item.check_id} {item.status.value}:[/] {item.message}")


def _exit_code(result: ScanResult, fail_on: Severity) -> ExitCode:
    if nothing_ran(result):
        err_console.print("[bold red]Error:[/] no check produced a result.")
        return ExitCode.ERROR
    if result.has_findings_at_or_above(fail_on):
        return ExitCode.FINDINGS_AT_THRESHOLD
    return ExitCode.OK


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(message)s",
        handlers=[RichHandler(console=err_console, show_path=False)],
        force=True,
    )
    # Azure SDK HTTP logging is noisy and may echo request details; keep it quiet even with -v.
    logging.getLogger("azure").setLevel(logging.WARNING)
