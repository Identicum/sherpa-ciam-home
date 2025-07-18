resource "keycloak_realm" "realm" {
  realm        = "employees"
  enabled      = true
  attributes   = {
    frontendUrl = "http://idp:8080"
  }
}
