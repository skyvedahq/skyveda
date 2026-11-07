# Checks batch 2. Where a check fails on a missing value, the lab plants the PASS case: a wrong
# property path makes such a check fail everything, so only a pass proves the path.
# Also changed for batch 2 in main.tf and batch1.tf: storage tags and ZRS (AZ-REL-003), VM 001's
# prod tag and Premium disk (AZ-REL-002, AZ-COST-007), the AKS add-on, upgrade channel and network
# policy (AZ-AKS-006/007/008), and the HTTPS web app's managed identity (AZ-WEB-003).
# AZ-NET-004 is planted as a failure only: an account that denies public access blocks
# Terraform's own reads of it.

# --- AZ-ACR-001: admin user on (fail) and off (pass).
# Batch 3: registry 01 is Standard with anonymous pull (AZ-ACR-002 fail; about INR 60 a day) and
# registry 02 Premium with public access off (AZ-ACR-002/003 pass; about INR 150 a day).
# AZ-ACR-003 fails on 01.

resource "azurerm_container_registry" "admin" {
  count                  = var.enable_batch2 ? 1 : 0
  name                   = "acrskyvedaflawlab01"
  location               = azurerm_resource_group.lab.location
  resource_group_name    = azurerm_resource_group.lab.name
  sku                    = "Standard"
  admin_enabled          = true
  anonymous_pull_enabled = true
  tags                   = local.tags
}

resource "azurerm_container_registry" "no_admin" {
  count                         = var.enable_batch2 ? 1 : 0
  name                          = "acrskyvedaflawlab02"
  location                      = azurerm_resource_group.lab.location
  resource_group_name           = azurerm_resource_group.lab.name
  sku                           = "Premium"
  admin_enabled                 = false
  public_network_access_enabled = false
  tags                          = local.tags
}

# --- VM 002 (with enable_vm): zone 2 (AZ-REL-002 pass), a public IP on its NIC (AZ-NET-005 fail),
# and a Premium OS disk; deallocate it after apply (AZ-COST-007 fail).

resource "azurerm_public_ip" "vm2" {
  count               = var.enable_vm ? 1 : 0
  name                = "pip-${local.name}-002"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = ["2"]
  tags                = local.tags
}

resource "azurerm_network_interface" "vm2" {
  count               = var.enable_vm ? 1 : 0
  name                = "nic-${local.name}-002"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.lab[0].id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm2[0].id
  }
}

resource "azurerm_linux_virtual_machine" "zoned" {
  count                 = var.enable_vm ? 1 : 0
  name                  = "vm-${local.name}-002"
  location              = azurerm_resource_group.lab.location
  resource_group_name   = azurerm_resource_group.lab.name
  size                  = "Standard_D2s_v4"
  zone                  = "2"
  secure_boot_enabled   = true # AZ-VM-002: Trusted Launch passes here; VM 001 is Standard
  vtpm_enabled          = true
  admin_username        = "skyveda"
  network_interface_ids = [azurerm_network_interface.vm2[0].id]
  tags                  = merge(local.tags, { environment = "prod" })

  admin_ssh_key {
    username   = "skyveda"
    public_key = tls_private_key.vm[0].public_key_openssh
  }

  os_disk {
    name                 = "osdisk-${local.name}-002"
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }
}
