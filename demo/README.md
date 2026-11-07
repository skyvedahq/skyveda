# Demo estate

Recorded Resource Graph rows for a **fictional** online retailer: three subscriptions
(`sub-shop-prod`, `sub-shop-nonprod`, `sub-platform-shared`) and about 100 resources. It is used
to make the sample report for outreach. No real tenant, subscription or customer is in it.

Each file follows its check's query projection (the same columns, in the same shape that
Resource Graph returns them). `billed_costs.json` holds fictional billed cost per resource and
day, shaped like Cost Management rows; one public IP has none, to show the list-price fallback.
Result: 18 checks pass and 42 fail, with ₹55,282 a month of waste: ₹53,426 billed and ₹1,856 of
list-price estimates. With `--cost-source estimate` it is ₹42,689, all list-price estimates.

```bash
uv run skyveda scan --offline demo/azure --out out/demo \
  --label "Sample report · fictional online retailer · not a real customer"
```

When a check is added, add its file here. `tests/test_cli.py` fails if the demo stops
covering every check.
