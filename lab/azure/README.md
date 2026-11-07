# Azure flaw lab

Plants one flaw per check, plus compliant twins where cheap, in `sub-skyveda-lab`, so a live scan
proves each check fails and passes on real Azure. **Create and destroy it on the same day.**

Only the maintainer runs `apply` and `destroy`, by hand; automated agents are blocked from both.

## Cost

| Part | Variable | Default | Approx. cost while it exists |
|---|---|---|---|
| NSGs, storage, Key Vault, disk, snapshot | always | on | a few rupees a day |
| Unattached public IP | always | on | about INR 0.4 an hour |
| Empty Basic App Service plan | `enable_app_service` | on | about INR 1.5 an hour |
| Stopped VM | `enable_vm` | off | about INR 8 an hour while running |
| AKS, one node | `enable_aks` | off | about INR 8 an hour |
| Batch 1: second vault, 2 SQL servers (no databases), vnet, 2 web apps on F1 | `enable_batch1` | on | about INR 0 |
| Batch 1: 2 NAT gateways | `enable_batch1` | on | about INR 4 an hour each |
| Batch 2: 2 container registries (Standard and Premium since batch 3) | `enable_batch2` | on | about INR 60 and 150 a day |
| Batch 2: second VM (zone 2, Premium disk, public IP) | `enable_vm` | off | about INR 8 an hour until deallocated |
| Batch 3: 2 MySQL B1ms flexible servers (PostgreSQL is refused here) | `enable_batch3` | on | about INR 1.5 an hour each |
| Batch 3: 2 serverless Cosmos DB, 2 Basic Service Bus, 2 AI services (S), LB, disk, 2 DNS zones | `enable_batch3` | on | about INR 0 while idle |
| Batch 3: 2 Basic C0 Redis caches. Azure refuses new ones since the retirement, so leave off | `enable_redis` | off | about INR 2 an hour each |

Estimates from list prices; the ₹500 budget alert (D-026) is the backstop.

VMs and the AKS node use `Standard_D2s_v4` (2 vCPU; 6 vCPUs in all), and VM 002 sits in zone 2.
On this subscription the older `Standard_B1s`/`Standard_B2s` are not offered in Central India,
the B-series v2 families have a quota of 0, and D2s_v4 is offered in zones 2 and 3 only.
`terraform plan` catches none of this. Before changing a size, check both
`az vm list-skus -l centralindia --resource-type virtualMachines` and `az vm list-usage -l centralindia`.

## What it cannot plant

* **AZ-STG-002** (TLS below 1.2): Azure no longer accepts it. Pass case only.
* **AZ-COST-004** (snapshot older than 90 days): a new snapshot is never old. Pass case only.
* **AZ-REDIS-001, AZ-REDIS-002**: Azure no longer creates Azure Cache for Redis ("retiring, create
  Azure Managed Redis instead", 3 Nov 2026). Offline fixtures only; existing caches are still scanned.

* **AZ-STG-004** (shared keys off): Terraform cannot refresh an account without shared keys.
  Fail case only.
* **AZ-NET-004** (storage denies public access): the same problem. Fail case only.
* **AZ-AKS-006/007/008**: the lab cluster is compliant on these, which proves the property paths;
  the fail cases stay in recorded data.
* **AZ-AKS-009/010**, **AZ-VM-001/003**: the same, pass cases only (RBAC on, workload identity
  on, SSH keys, managed disks). Clusters without RBAC and unmanaged disks can no longer be made.
* **AZ-SQL-004**, **AZ-REDIS-002** (TLS below 1.2) and **AZ-NET-007/008** (Basic public IPs and
  load balancers): retired by Azure, so pass cases only.
* **AZ-VM-002**: VM 002 has Trusted Launch (pass). VM 001 is expected to be Standard (fail); if
  Azure now makes new VMs Trusted Launch by default, VM 001 passes too, and that is not a bug.

These cases stay covered by the recorded fixtures in `tests/fixtures/azure`.

If `apply` fails because a region is not accepting new SQL servers, apply with
`-var "enable_batch1=false"` and tell Claude: the SQL checks then wait for another region.
The same goes for batch 3 (MySQL, Cosmos DB or AI services refused): `-var "enable_batch3=false"`.

## Run

PowerShell, from this folder:

```powershell
$env:AZURE_CONFIG_DIR = "$HOME\.azure-skyveda"
az account show --query "{tenant:tenantId, sub:name}" -o table   # must be the Skyveda tenant

terraform init
terraform apply -var "expires=2026-10-30"            # today's date; add -var "enable_vm=true" etc.
# with enable_vm=true, also run the command in: terraform output stop_vm_command
#   (stops VM 001 without deallocating, and deallocates VM 002)
# For a full run of every check: -var "enable_vm=true" -var "enable_aks=true"

# wait about 5 minutes: Resource Graph indexes new resources with a delay
cd ..\..
uv run skyveda scan --tenant <tenant-id> --auth cli --out out\lab
cd lab\azure
terraform output -json expected_status > expected.json
terraform output -json expected_flagged > flagged.json
uv run python verify.py expected.json ..\..\out\lab\findings.json flagged.json

terraform destroy -var "expires=2026-10-30"          # same day, always
```
