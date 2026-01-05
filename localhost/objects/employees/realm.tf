resource "keycloak_realm" "realm" {
  realm        = "employees"
  enabled      = true
  attributes   = {
    frontendUrl = "https://localhost.idsherpa.com"
  }
}
