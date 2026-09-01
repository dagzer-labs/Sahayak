terraform {
  required_version = ">= 1.16.0, < 1.17.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "= 4.81.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "= 5.24.0"
    }
  }
}

provider "azurerm" {
  subscription_id = var.azure_subscription_id
  features {}
}

# Authentication is read from CLOUDFLARE_API_TOKEN. The token is never stored
# in variables, plans, or committed files.
provider "cloudflare" {}
