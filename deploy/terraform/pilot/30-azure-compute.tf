resource "azurerm_linux_virtual_machine" "application" {
  name                            = "${var.resource_prefix}-vm"
  computer_name                   = "sahayak-pilot"
  location                        = azurerm_resource_group.pilot.location
  resource_group_name             = azurerm_resource_group.pilot.name
  size                            = var.vm_size
  admin_username                  = var.admin_username
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.application.id]
  tags                            = var.tags

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.admin_ssh_public_key
  }

  identity {
    type = "SystemAssigned"
  }

  os_disk {
    name                 = "${var.resource_prefix}-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = 32
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  custom_data = base64encode(templatefile("${path.module}/cloud-init.tftpl", {
    admin_username    = var.admin_username
    cloudflared_image = "cloudflare/cloudflared@sha256:51c9cefcb4569df44e1ad403ab1d3d8065aa8e84339bcfc6aee75502e1140339"
    tunnel_token      = data.cloudflare_zero_trust_tunnel_cloudflared_token.application.token
  }))

  boot_diagnostics {}

  lifecycle {
    precondition {
      condition = contains([
        "Standard_B2ats_v2",
        "Standard_B2als_v2"
      ], var.vm_size)
      error_message = "The controlled-pilot stack permits only approved Basv2 pilot SKUs."
    }
  }
}
