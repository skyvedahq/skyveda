# Checks batch 1: Key Vault, SQL, subnet NSGs, NAT gateways and App Service.
# Each check gets a planted flaw and a compliant twin, so verify.py can prove the property path
# is read correctly: a wrong path usually flags the twin too.
# AZ-STG-003 is planted on storage account 01 in main.tf. AZ-STG-004 fails on both accounts;
# turning shared keys off breaks Terraform's own refresh of the account, so its pass case stays
# in recorded data.

# --- AZ-KV-002 and AZ-KV-003: the main.tf vault uses access policies and is open (fail);
# this one uses RBAC and has public access off (pass).

resource "azurerm_key_vault" "rbac" {
  count                         = var.enable_batch1 ? 1 : 0
  name                          = "kv-skyveda-flawlab-lab02"
  location                      = azurerm_resource_group.lab.location
  resource_group_name           = azurerm_resource_group.lab.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  soft_delete_retention_days    = 7
  purge_protection_enabled      = false
  rbac_authorization_enabled    = true
  public_network_access_enabled = false
  tags                          = local.tags
}

# --- AZ-SQL-001/002/003: server 01 uses SQL logins, has an allow-all firewall rule next to the
# "Allow Azure services" rule, and is public (fail). Server 02 is Entra-only and private (pass).
# Logical servers without databases cost nothing. The generated password lives only in the local
# state, which destroy empties.

resource "random_password" "sql" {
  count   = var.enable_batch1 ? 1 : 0
  length  = 24
  special = true
}

resource "azurerm_mssql_server" "open" {
  count                         = var.enable_batch1 ? 1 : 0
  name                          = "sql-${local.name}-01"
  location                      = azurerm_resource_group.lab.location
  resource_group_name           = azurerm_resource_group.lab.name
  version                       = "12.0"
  administrator_login           = "skyvedalab"
  administrator_login_password  = random_password.sql[0].result
  minimum_tls_version           = "1.2"
  public_network_access_enabled = true
  tags                          = local.tags
}

# AZ-SQL-002 reads these rules with an ARM collector: Resource Graph does not index
# microsoft.sql/servers/firewallrules (shown on live Azure).
resource "azurerm_mssql_firewall_rule" "allow_all" {
  count            = var.enable_batch1 ? 1 : 0
  name             = "allow-all-internet"
  server_id        = azurerm_mssql_server.open[0].id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_mssql_firewall_rule" "azure_services" {
  count            = var.enable_batch1 ? 1 : 0
  name             = "AllowAllWindowsAzureIps"
  server_id        = azurerm_mssql_server.open[0].id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

resource "azurerm_mssql_server" "entra_only" {
  count                         = var.enable_batch1 ? 1 : 0
  name                          = "sql-${local.name}-02"
  location                      = azurerm_resource_group.lab.location
  resource_group_name           = azurerm_resource_group.lab.name
  version                       = "12.0"
  minimum_tls_version           = "1.2"
  public_network_access_enabled = false
  tags                          = local.tags

  azuread_administrator {
    login_username              = "skyveda-lab-admin"
    object_id                   = data.azurerm_client_config.current.object_id
    azuread_authentication_only = true
  }
}

# --- AZ-NET-003: one subnet with an NSG (pass) and one without (fail).
# --- AZ-COST-006: NAT gateway 01 is attached to nothing (fail); 02 serves the NSG subnet (pass).

resource "azurerm_virtual_network" "batch1" {
  count               = var.enable_batch1 ? 1 : 0
  name                = "vnet-${local.name}-002"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  address_space       = ["10.43.0.0/24"]
  tags                = local.tags
}

resource "azurerm_subnet" "with_nsg" {
  count                = var.enable_batch1 ? 1 : 0
  name                 = "snet-${local.name}-with-nsg"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.batch1[0].name
  address_prefixes     = ["10.43.0.0/26"]
}

resource "azurerm_subnet" "without_nsg" {
  count                = var.enable_batch1 ? 1 : 0
  name                 = "snet-${local.name}-no-nsg"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.batch1[0].name
  address_prefixes     = ["10.43.0.64/26"]
}

resource "azurerm_subnet_network_security_group_association" "with_nsg" {
  count                     = var.enable_batch1 ? 1 : 0
  subnet_id                 = azurerm_subnet.with_nsg[0].id
  network_security_group_id = azurerm_network_security_group.closed.id
}

resource "azurerm_nat_gateway" "unused" {
  count               = var.enable_batch1 ? 1 : 0
  name                = "ng-${local.name}-01"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  sku_name            = "Standard"
  tags                = local.tags
}

resource "azurerm_nat_gateway" "attached" {
  count               = var.enable_batch1 ? 1 : 0
  name                = "ng-${local.name}-02"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  sku_name            = "Standard"
  tags                = local.tags
}

resource "azurerm_subnet_nat_gateway_association" "attached" {
  count          = var.enable_batch1 ? 1 : 0
  subnet_id      = azurerm_subnet.with_nsg[0].id
  nat_gateway_id = azurerm_nat_gateway.attached[0].id
}

# --- AZ-WEB-001: one app allows HTTP (fail), one is HTTPS-only (pass), on a free F1 plan.
# The HTTP app also has minimum TLS 1.0, so the lab shows whether Resource Graph exposes
# siteConfig.minTlsVersion (needed before AZ-WEB-002 can be written). F1 is excluded from
# AZ-COST-005, which only looks at paid plans.

resource "azurerm_service_plan" "free" {
  count               = var.enable_batch1 ? 1 : 0
  name                = "asp-${local.name}-free"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  os_type             = "Linux"
  sku_name            = "F1"
  tags                = local.tags
}

resource "azurerm_linux_web_app" "http" {
  count               = var.enable_batch1 ? 1 : 0
  name                = "app-${local.name}-http"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  service_plan_id     = azurerm_service_plan.free[0].id
  https_only          = false
  tags                = local.tags

  site_config {
    always_on           = false
    minimum_tls_version = "1.0"

    cors { # AZ-WEB-006 fails here; the HTTPS app has no CORS list and passes
      allowed_origins = ["*"]
    }
  }
}

resource "azurerm_linux_web_app" "https" {
  count               = var.enable_batch1 ? 1 : 0
  name                = "app-${local.name}-https"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  service_plan_id     = azurerm_service_plan.free[0].id
  https_only          = true
  tags                = local.tags

  identity { # AZ-WEB-003 passes here; the HTTP app has no identity and fails
    type = "SystemAssigned"
  }

  site_config {
    always_on           = false
    minimum_tls_version = "1.2"
  }
}
