output "resource_group" {
  value = azurerm_resource_group.lab.name
}

output "stop_vm_command" {
  description = "Run after apply: stops VM 001 without deallocating (AZ-COST-003) and deallocates VM 002 (AZ-COST-007)."
  value = var.enable_vm ? join(" ", [
    "az vm stop --skip-shutdown -g", azurerm_resource_group.lab.name,
    "-n", azurerm_linux_virtual_machine.stopped[0].name,
    "; az vm deallocate -g", azurerm_resource_group.lab.name,
    "-n", azurerm_linux_virtual_machine.zoned[0].name,
  ]) : null
}

output "expected_status" {
  description = "What the scan must report for each check, given the enabled parts of the lab."
  value = {
    "AZ-NET-001"  = "fail"
    "AZ-NET-002"  = "fail"
    "AZ-STG-001"  = "fail"
    "AZ-STG-002"  = "pass"
    "AZ-KV-001"   = "fail"
    "AZ-COST-001" = "fail"
    "AZ-COST-002" = "fail"
    "AZ-COST-003" = var.enable_vm ? "fail" : "not_applicable"
    "AZ-COST-004" = "pass"
    "AZ-COST-005" = var.enable_app_service ? "fail" : "not_applicable"
    "AZ-AKS-002"  = var.enable_aks ? "fail" : "not_applicable"
    "AZ-AKS-003"  = var.enable_aks ? "fail" : "not_applicable"
    "AZ-AKS-004"  = var.enable_aks ? "fail" : "not_applicable"
    "AZ-AKS-005"  = var.enable_aks ? "fail" : "not_applicable"
    "AZ-REL-001"  = var.enable_aks ? "fail" : "not_applicable"
    "AZ-STG-003"  = "fail"
    "AZ-STG-004"  = "fail"
    "AZ-KV-002"   = "fail"
    "AZ-KV-003"   = "fail"
    "AZ-SQL-001"  = var.enable_batch1 ? "fail" : "not_applicable"
    "AZ-SQL-003"  = var.enable_batch1 ? "fail" : "not_applicable"
    "AZ-NET-003"  = var.enable_batch1 || var.enable_vm ? "fail" : "not_applicable"
    "AZ-COST-006" = var.enable_batch1 ? "fail" : "not_applicable"
    "AZ-WEB-001"  = var.enable_batch1 ? "fail" : "not_applicable"
    "AZ-AKS-006"  = var.enable_aks ? "pass" : "not_applicable"
    "AZ-AKS-007"  = var.enable_aks ? "pass" : "not_applicable"
    "AZ-AKS-008"  = var.enable_aks ? "pass" : "not_applicable"
    "AZ-REL-002"  = var.enable_vm ? "fail" : "not_applicable"
    "AZ-REL-003"  = "fail"
    "AZ-NET-004"  = "fail"
    "AZ-NET-005"  = var.enable_vm ? "fail" : "not_applicable"
    "AZ-COST-007" = var.enable_vm ? "fail" : "not_applicable"
    "AZ-ACR-001"  = var.enable_batch2 ? "fail" : "not_applicable"
    "AZ-WEB-003"  = var.enable_batch1 ? "fail" : "not_applicable"
    "AZ-SQL-002"  = var.enable_batch1 ? "fail" : "not_applicable"
    "AZ-WEB-002"  = var.enable_batch1 ? "fail" : "not_applicable"
    "AZ-WEB-004"  = var.enable_batch1 ? "pass" : "not_applicable"
    "AZ-WEB-005"  = var.enable_batch1 ? "pass" : "not_applicable"
    # Batch 3
    "AZ-SQL-004"    = var.enable_batch1 ? "pass" : "not_applicable"
    "AZ-STG-005"    = "fail"
    "AZ-REDIS-001"  = var.enable_redis ? "fail" : "not_applicable"
    "AZ-REDIS-002"  = var.enable_redis ? "pass" : "not_applicable"
    "AZ-COSMOS-001" = var.enable_batch3 ? "fail" : "not_applicable"
    "AZ-COSMOS-002" = var.enable_batch3 ? "fail" : "not_applicable"
    "AZ-PGSQL-001"  = var.enable_batch3 ? "fail" : "not_applicable"
    "AZ-MSG-001"    = var.enable_batch3 ? "fail" : "not_applicable"
    "AZ-AI-001"     = var.enable_batch3 ? "fail" : "not_applicable"
    "AZ-VM-001"     = var.enable_vm ? "pass" : "not_applicable"
    "AZ-VM-002"     = var.enable_vm ? "fail" : "not_applicable"
    "AZ-VM-003"     = var.enable_vm ? "pass" : "not_applicable"
    "AZ-VM-004"     = "fail"
    "AZ-NET-006"    = var.enable_batch3 ? "fail" : "pass"
    "AZ-NET-007"    = "pass"
    "AZ-NET-008"    = var.enable_batch3 || var.enable_aks ? "pass" : "not_applicable"
    "AZ-AKS-009"    = var.enable_aks ? "pass" : "not_applicable"
    "AZ-AKS-010"    = var.enable_aks ? "pass" : "not_applicable"
    "AZ-ACR-002"    = var.enable_batch2 ? "fail" : "not_applicable"
    "AZ-ACR-003"    = var.enable_batch2 ? "fail" : "not_applicable"
    "AZ-WEB-006"    = var.enable_batch1 ? "fail" : "not_applicable"
    "AZ-COST-008"   = var.enable_batch3 ? "fail" : "not_applicable"
  }
}

output "expected_flagged" {
  description = "Exactly which resources each new check must flag; the compliant twins must not appear."
  value = merge(var.enable_batch1 ? {
    "AZ-STG-003"  = ["stskyvedaflawlablabcin01"]
    "AZ-STG-004"  = ["stskyvedaflawlablabcin01", "stskyvedaflawlablabcin02"]
    "AZ-KV-002"   = [azurerm_key_vault.lab.name]
    "AZ-KV-003"   = [azurerm_key_vault.lab.name]
    "AZ-SQL-001"  = [azurerm_mssql_server.open[0].name]
    "AZ-SQL-003"  = [azurerm_mssql_server.open[0].name]
    "AZ-NET-003"  = concat([azurerm_subnet.without_nsg[0].name], var.enable_vm ? [azurerm_subnet.lab[0].name] : [])
    "AZ-COST-006" = [azurerm_nat_gateway.unused[0].name]
    "AZ-WEB-001"  = [azurerm_linux_web_app.http[0].name]
    "AZ-WEB-003"  = [azurerm_linux_web_app.http[0].name]
    "AZ-SQL-002"  = [azurerm_mssql_firewall_rule.allow_all[0].name]
    "AZ-WEB-002"  = [azurerm_linux_web_app.http[0].name]
    "AZ-WEB-004"  = []
    "AZ-WEB-005"  = []
    } : {},
    {
      "AZ-REL-003" = [azurerm_storage_account.public.name]
      "AZ-NET-004" = [azurerm_storage_account.public.name, azurerm_storage_account.private.name]
    },
    var.enable_vm ? {
      "AZ-REL-002"  = [azurerm_linux_virtual_machine.stopped[0].name]
      "AZ-NET-005"  = [azurerm_network_interface.vm2[0].name]
      "AZ-COST-007" = [azurerm_linux_virtual_machine.zoned[0].os_disk[0].name]
    } : {},
    var.enable_batch2 ? { "AZ-ACR-001" = [azurerm_container_registry.admin[0].name] } : {},
    # Planted as passes: nothing may be flagged.
    var.enable_aks ? { "AZ-AKS-006" = [], "AZ-AKS-007" = [], "AZ-AKS-008" = [] } : {},
    # Batch 3
    {
      "AZ-STG-005" = [azurerm_storage_account.public.name]
      "AZ-NET-007" = []
      "AZ-VM-004" = concat([azurerm_managed_disk.orphan.name], var.enable_vm ? [
        azurerm_linux_virtual_machine.stopped[0].os_disk[0].name,
        azurerm_linux_virtual_machine.zoned[0].os_disk[0].name,
      ] : [])
    },
    var.enable_batch1 ? {
      "AZ-SQL-004" = []
      "AZ-WEB-006" = [azurerm_linux_web_app.http[0].name]
    } : {},
    var.enable_batch2 ? {
      "AZ-ACR-002" = [azurerm_container_registry.admin[0].name]
      "AZ-ACR-003" = [azurerm_container_registry.admin[0].name]
    } : {},
    var.enable_batch3 ? {
      "AZ-NET-006"    = [azurerm_network_security_group.db_open[0].name]
      "AZ-NET-008"    = []
      "AZ-COST-008"   = [azurerm_private_dns_zone.unlinked[0].name]
      "AZ-COSMOS-001" = [azurerm_cosmosdb_account.lab["01"].name]
      "AZ-COSMOS-002" = [azurerm_cosmosdb_account.lab["01"].name]
      "AZ-PGSQL-001"  = [azurerm_mysql_flexible_server.lab["01"].name]
      "AZ-MSG-001"    = [azurerm_servicebus_namespace.lab["01"].name]
      "AZ-AI-001"     = [azurerm_cognitive_account.lab["01"].name]
    } : {},
    var.enable_vm ? {
      "AZ-VM-001" = []
      "AZ-VM-002" = [azurerm_linux_virtual_machine.stopped[0].name]
      "AZ-VM-003" = []
    } : {},
    var.enable_aks ? { "AZ-AKS-009" = [], "AZ-AKS-010" = [] } : {},
    var.enable_redis ? {
      "AZ-REDIS-001" = [azurerm_redis_cache.lab["01"].name]
      "AZ-REDIS-002" = []
    } : {},
  )
}
