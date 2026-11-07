# Contributing

Thank you for helping. Contributions are accepted under the Apache License 2.0, the same licence
as the project (inbound = outbound).

## Sign off every commit

Every commit must carry a Developer Certificate of Origin sign-off
(https://developercertificate.org):

```bash
git commit -s
```

This adds `Signed-off-by: Your Name <you@example.com>` and confirms you have the right to submit
the change under the project's licence. Pull requests with unsigned commits are not merged.

## Rules the code must keep

- **Read-only.** Only read, list and get APIs. No call that creates, changes or deletes anything.
- **Real fields only.** Every property path in a check must exist in the provider's API or
  Resource Graph schema, with a fixture that shows it.
- **No real data.** Never put real subscription or tenant IDs, resource names, keys or customer
  data in code, fixtures, issues or pull requests. Use the placeholders in `tests/fixtures`.
- **Tests never touch the cloud.** Sockets are disabled in the test run.

## Before opening a pull request

```bash
uv sync --all-extras
uv run ruff check && uv run ruff format --check
uv run mypy
uv run pytest
```

Security problems go by email, not in an issue: see [SECURITY.md](SECURITY.md).
The Skyveda name is not covered by the code licence: see [TRADEMARKS.md](TRADEMARKS.md).
