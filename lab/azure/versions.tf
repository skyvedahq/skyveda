terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  # Pinned so a machine's managed identity or another az login can never apply this elsewhere.
  tenant_id       = var.tenant_id
  subscription_id = var.subscription_id
  use_cli         = true
  use_msi         = false

  features {
    key_vault {
      # The lab vault has no purge protection, so destroy can purge it and the name is reusable.
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = false
    }
  }
}
