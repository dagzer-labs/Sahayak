resource "azurerm_resource_group" "pilot" {
  name     = "${var.resource_prefix}-rg"
  location = var.location
  tags     = var.tags
}

resource "azurerm_virtual_network" "pilot" {
  name                = "${var.resource_prefix}-vnet"
  location            = azurerm_resource_group.pilot.location
  resource_group_name = azurerm_resource_group.pilot.name
  address_space       = ["10.42.0.0/16"]
  tags                = var.tags
}

resource "azurerm_subnet" "application" {
  name                 = "application"
  resource_group_name  = azurerm_resource_group.pilot.name
  virtual_network_name = azurerm_virtual_network.pilot.name
  address_prefixes     = ["10.42.1.0/24"]
}

resource "azurerm_network_security_group" "application" {
  name                = "${var.resource_prefix}-nsg"
  location            = azurerm_resource_group.pilot.location
  resource_group_name = azurerm_resource_group.pilot.name
  tags                = var.tags
}

resource "azurerm_network_security_rule" "emergency_ssh" {
  count = var.enable_emergency_ssh ? 1 : 0

  name                        = "temporary-emergency-ssh"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = var.operator_cidr
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.pilot.name
  network_security_group_name = azurerm_network_security_group.application.name
}

resource "azurerm_subnet_network_security_group_association" "application" {
  subnet_id                 = azurerm_subnet.application.id
  network_security_group_id = azurerm_network_security_group.application.id
}

# A Standard public IP is the least expensive explicit outbound path for the
# VM. No inbound application ports are allowed; Cloudflare Tunnel publishes
# the API through an outbound-only connection.
resource "azurerm_public_ip" "application" {
  name                = "${var.resource_prefix}-pip"
  location            = azurerm_resource_group.pilot.location
  resource_group_name = azurerm_resource_group.pilot.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_interface" "application" {
  name                = "${var.resource_prefix}-nic"
  location            = azurerm_resource_group.pilot.location
  resource_group_name = azurerm_resource_group.pilot.name
  tags                = var.tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.application.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.application.id
  }
}
