# Skyveda Scan

Read-only command-line scanner that checks a cloud environment against a catalogue of
best-practice checks and produces a scored HTML report with prioritised findings, estimated
monthly waste in ₹ (INR) and fix guidance.

* **Read-only.** Only read/list/get APIs. On Azure it works with the built-in **Reader** role
  (plus **Cost Management Reader** for cost checks).
* **Local only.** No telemetry; nothing leaves your machine except the output files you write.
* **Checks are data.** Each check is one YAML file.

> Status: early development (v0.4: 60 Azure checks mapped to MCSB and Well-Architected, billed cost, fix pack). Azure first; AWS and GCP later.

## Install

From PyPI (Python 3.12+):

```bash
pip install "skyveda[azure]"
```

Or:

* **Azure Cloud Shell (recommended for customers):** build the bundle with
  `uv run python packaging/build_cloudshell_bundle.py`, upload
  `dist/skyveda-cloudshell-<version>.zip` to Cloud Shell, then run
  `unzip -o skyveda-cloudshell-*.zip && bash skyveda-cloudshell/install.sh`.
  See [packaging/cloudshell/README.txt](packaging/cloudshell/README.txt).
* **From the wheel:** `pip install "skyveda-<version>-py3-none-any.whl[azure]"` (Python 3.12+).

On an Azure VM, the default credential uses the VM's managed identity before `az login`;
pass `--auth cli` to scan as your `az login` account, and `--tenant <id>` to refuse any other
tenant.

## Usage

```bash
az login                                   # or service principal env vars / managed identity
skyveda scopes                              # which subscriptions can I read?
skyveda scan --provider azure --subscription <id> --out ./out
skyveda scan --offline tests/fixtures/azure # run on recorded data, no cloud access
skyveda list-checks                         # the check catalogue
skyveda validate-checks                     # check YAML files are valid
```

Options: `--subscription` (repeat or comma-separate), `--management-group`, `--tenant`,
`--label` (a line under the report title), `--waivers`, `--pdf` (also write report.pdf).

### Config file

Save options in a `skyveda.toml` and pass `--config skyveda.toml` to `scan` or `scopes`. Options
typed on the command line override the file. Paths in the file are relative to the file. Never put
credentials in it: sign-in uses `az login`, managed identity or environment variables as usual.

```toml
schema_version = 1

[scan]
subscriptions = ["<subscription-id>"]
tenant = "<tenant-id>"
auth = "cli"
out = "skyveda-out"
fail_on = "high"
label = "Prepared for cust-001"
waivers = "waivers.yaml"
pdf = true
```

### Waivers

A `waivers.yaml` takes accepted risks and wrong findings out of the findings, the ₹ total and the
scores. The report lists every waiver in Appendix D, so nothing disappears silently.

```yaml
schema_version: 1
waivers:
  - check: AZ-NET-001
    resource: /subscriptions/<id>/resourceGroups/<rg>/providers/Microsoft.Network/networkSecurityGroups/<nsg>
    kind: accepted_risk        # or false_positive
    reason: Vendor access, limited by the upstream firewall
    approver: Head of Platform
    expires: 2027-03-31        # applies up to and including this date
```

Omit `resource` to waive every resource the check flags. Expired waivers, and waivers that match
nothing, are not applied and are listed as warnings. To apply waivers to a findings.json someone
sent you, use `skyveda report findings.json --waivers waivers.yaml --out <new dir>`; the original
file is never changed.

### Fix pack

`skyveda fixes` turns findings into reviewable work. It only **writes files**: it runs no command,
calls no cloud and needs no credentials.

```bash
skyveda fixes out/findings.json --out ./fixes [--waivers waivers.yaml]
```

* `fixes/README.md`: the plan, ordered by severity and then ₹ a month, with risk, downtime and the
  script for each item, plus a "Manual fix: see report" list for checks with no fix template.
* `fixes/<check-id>/<resource-name>.sh`: one script per resource, with risk, downtime, before-steps,
  rollback and verify lines in the header. **Every command is commented out**: a reviewer removes
  the `# ` on purpose, after reading it.
* `fixes/PULL_REQUEST.md`: text to paste into your pull request.

Waived resources are skipped. A non-empty `--out` is refused unless you add `--force`, which first
removes only the old pack's `<check-id>/*.sh`, `README.md` and `PULL_REQUEST.md`. Fix templates (az CLI) exist for AZ-COST-001 to 004, AZ-NET-001 and
AZ-STG-001. A check adds one with an optional `remedy:` block in its YAML, and `{placeholders}` may
only use columns the check's query projects (plus `id`, `name` and `subscriptionId`).

Exit codes: `0` ran fine · `2` findings at or above `--fail-on` (default `critical`) · `1` error.

### Framework mapping

Every check carries a `frameworks:` block that maps it to the Microsoft cloud security benchmark (MCSB) and to Well-Architected pillars and recommendations. Each finding shows a "Maps to" line, and the HTML and PDF reports add a per-control and per-pillar pass and fail summary. MCSB control IDs are from the Microsoft cloud security benchmark v2 (preview); the same IDs exist in v1, the default in Microsoft Defender for Cloud. Well-Architected IDs are Skyveda's mapping to Microsoft's published checklists. Skyveda maps to these frameworks; it does not certify compliance. `skyveda validate-checks` rejects malformed IDs.

## Development

Requires [uv](https://docs.astral.sh/uv/). Python 3.12 is installed automatically.

```bash
uv sync --all-extras
uv run ruff check && uv run ruff format --check
uv run mypy
uv run pytest            # sockets are disabled: tests can never reach the cloud
```

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md); every commit needs a `git commit -s` sign-off. Report
vulnerabilities by email, not in an issue: see [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The Skyveda™ name is not licensed with
the code: see [TRADEMARKS.md](TRADEMARKS.md).

Microsoft and Azure are trademarks of the Microsoft group of companies. Skyveda is not affiliated
with or endorsed by Microsoft.
