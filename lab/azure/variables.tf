variable "tenant_id" {
  description = "Tenant to build the lab in. Set it in terraform.tfvars (gitignored)."
  type        = string
}

variable "subscription_id" {
  description = "Lab subscription. Set it in terraform.tfvars (gitignored)."
  type        = string
}

variable "location" {
  type    = string
  default = "centralindia"
}

variable "expires" {
  description = "Date (YYYY-MM-DD) by which the lab must be destroyed; set it to today."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", var.expires))
    error_message = "Use YYYY-MM-DD."
  }
}

variable "enable_app_service" {
  description = "Empty Basic App Service plan for AZ-COST-005 (about INR 1.5 an hour)."
  type        = bool
  default     = true
}

variable "enable_vm" {
  description = "Small VM to stop (not deallocate) for AZ-COST-003 (about INR 1-2 an hour)."
  type        = bool
  default     = false
}

variable "enable_batch1" {
  description = "Checks batch 1: second vault, two SQL servers, a vnet, two NAT gateways (about INR 4 an hour each) and two web apps on a free plan."
  type        = bool
  default     = true
}

variable "enable_batch2" {
  description = "Checks batch 2: two Basic container registries (about INR 15 a day each). Batch 2's VM parts follow enable_vm."
  type        = bool
  default     = true
}

variable "enable_aks" {
  description = "Free-tier AKS cluster with one node for the AKS and REL checks (about INR 4-5 an hour)."
  type        = bool
  default     = false
}

variable "enable_batch3" {
  description = "Checks batch 3: two Cosmos DB serverless accounts, two PostgreSQL B1ms servers (about INR 1.5 an hour each), Service Bus, AI services, a load balancer, a disk and private DNS zones."
  type        = bool
  default     = true
}

variable "enable_redis" {
  description = "Two Basic C0 Redis caches for AZ-REDIS-001/002 (about INR 2 an hour each; about 20 minutes to create)."
  type        = bool
  default     = false
}
