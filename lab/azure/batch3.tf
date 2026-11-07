# Checks batch 3. As in batch 2, where a check fails on a missing value the lab plants the PASS
# case too: a wrong property path makes such a check fail everything, so only a pass proves it.
# Also changed for batch 3: storage account 01 allows cross-tenant replication (AZ-STG-005),
# the HTTP web app allows CORS from * (AZ-WEB-006), registry 01 is Standard with anonymous pull
# and registry 02 Premium with public access off (AZ-ACR-002/003), VM 002 has Trusted Launch
# (AZ-VM-002), and the AKS cluster has workload identity (AZ-AKS-010).
# Passes from existing resources: AZ-SQL-004 (both SQL servers 1.2), AZ-NET-007 (Standard IPs),
# AZ-VM-001 and AZ-VM-003 (SSH keys, managed disks), AZ-AKS-009 (RBAC is on by default).

resource "random_password" "batch3" {
  count   = var.enable_batch3 ? 1 : 0
  length  = 24
  special = false
}

# --- AZ-NET-006: PostgreSQL's port open to the Internet (fail). NSGs 001 and 002 expose no
# database port (pass).

resource "azurerm_network_security_group" "db_open" {
  count               = var.enable_batch3 ? 1 : 0
  name                = "nsg-${local.name}-003"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags

  security_rule {
    name                       = "allow-postgres-from-internet"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5432"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# --- AZ-NET-008: a Standard load balancer (pass); no charge without rules. Basic load balancers
# and public IPs can no longer be created, so their fail cases stay in recorded data.

resource "azurerm_lb" "standard" {
  count               = var.enable_batch3 ? 1 : 0
  name                = "lb-${local.name}-001"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  sku                 = "Standard"
  tags                = local.tags
}

# --- AZ-VM-004: disk 001 (main.tf) and the VM OS disks allow export from anywhere (fail);
# disk 002 denies it (pass). 4 GB Standard HDD, a few rupees a month.

resource "azurerm_managed_disk" "locked" {
  count                 = var.enable_batch3 ? 1 : 0
  name                  = "disk-${local.name}-002"
  location              = azurerm_resource_group.lab.location
  resource_group_name   = azurerm_resource_group.lab.name
  storage_account_type  = "Standard_LRS"
  create_option         = "Empty"
  disk_size_gb          = 4
  network_access_policy = "DenyAll"
  tags                  = local.tags
}

# --- AZ-COST-008: zone 01 has no network link (fail); zone 02 is linked to batch 1's vnet (pass).

resource "azurerm_private_dns_zone" "unlinked" {
  count               = var.enable_batch3 ? 1 : 0
  name                = "unlinked.skyveda-flawlab.internal"
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone" "linked" {
  count               = var.enable_batch3 && var.enable_batch1 ? 1 : 0
  name                = "linked.skyveda-flawlab.internal"
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "linked" {
  count                 = var.enable_batch3 && var.enable_batch1 ? 1 : 0
  name                  = "link-${local.name}"
  resource_group_name   = azurerm_resource_group.lab.name
  private_dns_zone_name = azurerm_private_dns_zone.linked[0].name
  virtual_network_id    = azurerm_virtual_network.batch1[0].id
  tags                  = local.tags
}

# --- AZ-COSMOS-001/002: account 01 uses keys and is open to all networks (fail); 02 is
# Entra-only with public access off (pass). Serverless: no charge while idle.

resource "azurerm_cosmosdb_account" "lab" {
  for_each                      = var.enable_batch3 ? { "01" = false, "02" = true } : {}
  name                          = "cosmos-skyveda-flawlab-${each.key}"
  location                      = azurerm_resource_group.lab.location
  resource_group_name           = azurerm_resource_group.lab.name
  offer_type                    = "Standard"
  kind                          = "GlobalDocumentDB"
  local_authentication_enabled  = !each.value
  public_network_access_enabled = !each.value
  tags                          = local.tags

  capabilities {
    name = "EnableServerless"
  }

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.lab.location
    failover_priority = 0
  }
}

# --- AZ-PGSQL-001: server 01 is public (fail), 02 has public access off (pass).
# MySQL, not PostgreSQL: this subscription is refused PostgreSQL in centralindia (SkuNotAvailable,
# 3 Nov 2026), and the check reads the same field on both. Burstable B1ms, about INR 1.5 an hour
# each. The password lives only in the local state.

resource "azurerm_mysql_flexible_server" "lab" {
  for_each               = var.enable_batch3 ? { "01" = "Enabled", "02" = "Disabled" } : {}
  name                   = "mysql-skyveda-flawlab-${each.key}"
  location               = azurerm_resource_group.lab.location
  resource_group_name    = azurerm_resource_group.lab.name
  version                = "8.0.21"
  sku_name               = "B_Standard_B1ms"
  administrator_login    = "skyvedalab"
  administrator_password = random_password.batch3[0].result
  public_network_access  = each.value
  tags                   = local.tags

  lifecycle {
    ignore_changes = [zone]
  }
}

# --- AZ-MSG-001: namespace 01 allows SAS keys (fail), 02 is Entra-only (pass).
# Basic tier: billed per operation, nothing while idle.

resource "azurerm_servicebus_namespace" "lab" {
  for_each            = var.enable_batch3 ? { "01" = true, "02" = false } : {}
  name                = "sb-skyveda-flawlab-${each.key}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  sku                 = "Basic"
  local_auth_enabled  = each.value
  tags                = local.tags
}

# --- AZ-AI-001: account 01 allows keys (fail), 02 is Entra-only (pass). S0 is billed per call.
# Entra-only access needs a custom subdomain, so both have one.

resource "azurerm_cognitive_account" "lab" {
  for_each              = var.enable_batch3 ? { "01" = true, "02" = false } : {}
  name                  = "ai-skyveda-flawlab-${each.key}"
  location              = azurerm_resource_group.lab.location
  resource_group_name   = azurerm_resource_group.lab.name
  kind                  = "TextAnalytics"
  sku_name              = "S"
  custom_subdomain_name = "ai-skyveda-flawlab-${each.key}"
  local_auth_enabled    = each.value
  tags                  = local.tags
}

# --- AZ-REDIS-001/002 (with enable_redis): cache 01 has the non-TLS port on (fail), 02 off
# (pass); both require TLS 1.2 (AZ-REDIS-002 pass). Basic C0, about INR 2 an hour each, and
# about 20 minutes to create.

resource "azurerm_redis_cache" "lab" {
  for_each             = var.enable_redis ? { "01" = true, "02" = false } : {}
  name                 = "redis-skyveda-flawlab-${each.key}"
  location             = azurerm_resource_group.lab.location
  resource_group_name  = azurerm_resource_group.lab.name
  capacity             = 0
  family               = "C"
  sku_name             = "Basic"
  non_ssl_port_enabled = each.value
  minimum_tls_version  = "1.2"
  tags                 = local.tags
}
