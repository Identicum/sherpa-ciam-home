terraform {
  required_providers {
    keycloak = {
      source  = "keycloak/keycloak"
      version = "= 5.7.0"
    }
  }
}

provider "keycloak" {
  client_id     = "admin-cli"
  username      = "admin"
  password      = var.admin_password
  url           = var.idp_url
  base_path     = "" 
}