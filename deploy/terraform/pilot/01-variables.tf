variable "azure_subscription_id" {
  description = "Azure subscription that owns the pilot resources."
  type        = string
}

variable "location" {
  description = "Azure region for all pilot resources."
  type        = string
  default     = "centralindia"
}

variable "resource_prefix" {
  description = "Stable prefix applied to pilot resource names."
  type        = string
  default     = "sahayak-pilot"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,24}$", var.resource_prefix))
    error_message = "resource_prefix must contain 3-24 lowercase letters, digits, or hyphens."
  }
}

variable "vm_size" {
  description = "Pilot VM SKU. Standard_B2ats_v2 is the approved minimum available in Central India."
  type        = string
  default     = "Standard_B2ats_v2"
}

variable "admin_username" {
  description = "Non-root Linux administrator account."
  type        = string
  default     = "sahayakops"
}

variable "admin_ssh_public_key" {
  description = "OpenSSH public key used for emergency administration."
  type        = string
  sensitive   = true
}

variable "enable_emergency_ssh" {
  description = "Temporarily permit SSH from operator_cidr. Keep false normally."
  type        = bool
  default     = false
}

variable "operator_cidr" {
  description = "Single trusted operator CIDR used only when emergency SSH is enabled."
  type        = string
  default     = "127.0.0.1/32"
}

variable "monthly_budget_usd" {
  description = "Hard operational budget used for Azure cost notifications."
  type        = number
  default     = 15
}

variable "budget_start_date" {
  description = "First day of the current billing month in RFC3339 format."
  type        = string
  default     = "2026-09-01T00:00:00Z"
}

variable "alert_emails" {
  description = "Email addresses receiving budget notifications."
  type        = list(string)
}

variable "cloudflare_account_id" {
  description = "Cloudflare account ID containing the tunnel and R2 bucket."
  type        = string
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID for dagzer.com."
  type        = string
}

variable "cloudflare_zone_name" {
  description = "Cloudflare-managed parent DNS zone."
  type        = string
  default     = "dagzer.com"
}

variable "cloudflare_record_name" {
  description = "DNS label published through Cloudflare Tunnel."
  type        = string
  default     = "sahayak"
}

variable "r2_bucket_name" {
  description = "Private R2 bucket for encrypted backups and media."
  type        = string
  default     = "sahayak-pilot-private"
}

variable "tags" {
  description = "Common resource tags."
  type        = map(string)
  default = {
    application = "sahayak"
    environment = "pilot"
    managed_by  = "terraform"
    cost_center = "dagzer"
  }
}
