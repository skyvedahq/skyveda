# Skyveda flaw lab: one planted flaw per check, plus compliant twins where cheap, so a scan
# proves each check both fails and passes on real Azure. Destroy it the day it is created.

locals {
  name = "skyveda-flawlab-lab-cin"
  tags = {
    owner      = "skyveda"
    env        = "lab"
    workload   = "flawlab"
    managed-by = "terraform"
    expires    = var.expires
  }
}

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "lab" {
  name     = "rg-${local.name}"
  location = var.location
  tags     = local.tags
}

# --- AZ-NET-001: SSH open to the Internet (fail) and SSH from a private range only (pass).

resource "azurerm_network_security_group" "open" {
  name                = "nsg-${local.name}-001"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags

  security_rule {
    name                       = "allow-ssh-from-internet"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_group" "closed" {
  name                = "nsg-${local.name}-002"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags

  security_rule {
    name                       = "allow-ssh-from-private-range"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "10.0.0.0/8"
    destination_address_prefix = "*"
  }
}

# --- AZ-STG-003 fails on 01 (HTTP allowed) and passes on 02.
# --- AZ-STG-001 fails on 01 and passes on 02. AZ-STG-002 passes on both: Azure no longer
# accepts a minimum TLS below 1.2, so that flaw is tested with recorded data only.
# AZ-NET-002 fails on both accounts and the vault: none has a private endpoint.

resource "azurerm_storage_account" "public" {
  name                             = "stskyvedaflawlablabcin01"
  resource_group_name              = azurerm_resource_group.lab.name
  location                         = azurerm_resource_group.lab.location
  account_tier                     = "Standard"
  account_replication_type         = "LRS"
  min_tls_version                  = "TLS1_2"
  allow_nested_items_to_be_public  = true
  https_traffic_only_enabled       = false
  cross_tenant_replication_enabled = true # AZ-STG-005 fails here and passes on 02
  tags                             = merge(local.tags, { environment = "prod" })
}

resource "azurerm_storage_account" "private" {
  name                             = "stskyvedaflawlablabcin02"
  resource_group_name              = azurerm_resource_group.lab.name
  location                         = azurerm_resource_group.lab.location
  account_tier                     = "Standard"
  account_replication_type         = "ZRS" # AZ-REL-003 passes here and fails on LRS account 01
  cross_tenant_replication_enabled = false # AZ-STG-005 pass twin
  min_tls_version                  = "TLS1_2"
  allow_nested_items_to_be_public  = false
  tags                             = merge(local.tags, { environment = "prod" })
}

# --- AZ-KV-001: soft delete is always on; purge protection is off (fail).

resource "azurerm_key_vault" "lab" {
  name                       = "kv-skyveda-flawlab-lab"
  location                   = azurerm_resource_group.lab.location
  resource_group_name        = azurerm_resource_group.lab.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
  tags                       = local.tags
}

# --- AZ-COST-001: an unattached disk (fail). AZ-COST-004: a fresh snapshot of it (pass); a
# snapshot older than 90 days cannot be created, so the fail case stays in recorded data.

resource "azurerm_managed_disk" "orphan" {
  name                 = "disk-${local.name}-001"
  location             = azurerm_resource_group.lab.location
  resource_group_name  = azurerm_resource_group.lab.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 4
  tags                 = local.tags
}

resource "azurerm_snapshot" "fresh" {
  name                = "snap-${local.name}-001"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  create_option       = "Copy"
  source_uri          = azurerm_managed_disk.orphan.id
  tags                = local.tags
}

# --- AZ-COST-002: a Standard static public IP attached to nothing (fail).

resource "azurerm_public_ip" "unused" {
  name                = "pip-${local.name}-001"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

# --- AZ-COST-005: a Basic App Service plan with no apps (fail).

resource "azurerm_service_plan" "empty" {
  count               = var.enable_app_service ? 1 : 0
  name                = "asp-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  os_type             = "Linux"
  sku_name            = "B1"
  tags                = local.tags
}

# --- AZ-COST-003: a VM that you stop, but do not deallocate, after apply (fail).
# No public IP; the generated key lives only in the local state, which destroy empties.

resource "tls_private_key" "vm" {
  count     = var.enable_vm ? 1 : 0
  algorithm = "ED25519"
}

resource "azurerm_virtual_network" "lab" {
  count               = var.enable_vm ? 1 : 0
  name                = "vnet-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  address_space       = ["10.42.0.0/24"]
  tags                = local.tags
}

resource "azurerm_subnet" "lab" {
  count                = var.enable_vm ? 1 : 0
  name                 = "snet-${local.name}"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab[0].name
  address_prefixes     = ["10.42.0.0/26"]
}

resource "azurerm_network_interface" "vm" {
  count               = var.enable_vm ? 1 : 0
  name                = "nic-${local.name}-001"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.lab[0].id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "stopped" {
  count                 = var.enable_vm ? 1 : 0
  name                  = "vm-${local.name}-001"
  location              = azurerm_resource_group.lab.location
  resource_group_name   = azurerm_resource_group.lab.name
  size                  = "Standard_D2s_v4"
  admin_username        = "skyveda"
  network_interface_ids = [azurerm_network_interface.vm[0].id]
  tags                  = merge(local.tags, { environment = "prod" }) # AZ-REL-002: no zone, fails

  admin_ssh_key {
    username   = "skyveda"
    public_key = tls_private_key.vm[0].public_key_openssh
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS" # AZ-COST-007 pass twin: Premium, VM stopped not deallocated
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }
}

# --- AZ-AKS-002/003/004/005 and AZ-REL-001: local accounts on, a public API server with no
# authorised ranges, a single system pool, no zones, tagged prod on the Free tier (all fail).

resource "azurerm_kubernetes_cluster" "lab" {
  count               = var.enable_aks ? 1 : 0
  name                = "aks-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  dns_prefix          = "skyveda-flawlab"
  sku_tier            = "Free"
  tags                = merge(local.tags, { environment = "prod" })

  # AZ-AKS-006/007/008 pass here; the flaws above stay for AZ-AKS-002/003/004/005 and AZ-REL-001.
  azure_policy_enabled      = true
  automatic_upgrade_channel = "patch"
  oidc_issuer_enabled       = true # AZ-AKS-010 passes; RBAC is on by default (AZ-AKS-009)
  workload_identity_enabled = true

  network_profile {
    network_plugin = "azure"
    network_policy = "calico"
  }

  default_node_pool {
    name       = "system"
    vm_size    = "Standard_D2s_v4"
    node_count = 1
  }

  identity {
    type = "SystemAssigned"
  }
}
