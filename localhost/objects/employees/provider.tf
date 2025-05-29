terraform {
  required_providers {
    keycloak = {
      source  = "keycloak/keycloak"
    }
  }
}

provider "keycloak" {
  client_id     = "admin-cli"
  username      = "admin"
  password      = "admin"
  url           = "http://idp:8080"
  base_path     = "" 
}