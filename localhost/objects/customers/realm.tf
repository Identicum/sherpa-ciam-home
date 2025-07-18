resource "keycloak_realm" "realm" {
  realm        = var.realm_name
  enabled      = true
  attributes   = {
    frontendUrl = "http://idp:8080"
  }
}
