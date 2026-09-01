output "resource_group_name" {
  description = "Azure resource group containing the pilot."
  value       = azurerm_resource_group.pilot.name
}

output "vm_name" {
  description = "Azure application VM name."
  value       = azurerm_linux_virtual_machine.application.name
}

output "vm_public_ip" {
  description = "Emergency operations IP. Application ingress remains blocked."
  value       = azurerm_public_ip.application.ip_address
}

output "application_url" {
  description = "Cloudflare-published application URL."
  value       = "https://${var.cloudflare_record_name}.${var.cloudflare_zone_name}"
}

output "r2_bucket_name" {
  description = "Private backup and media bucket."
  value       = cloudflare_r2_bucket.private.name
}

output "estimated_fixed_monthly_usd" {
  description = "Retail estimate for compute, E4 SSD, and Standard IPv4 before taxes."
  value       = var.vm_size == "Standard_B2ats_v2" ? 11.51 : 21.23
}
