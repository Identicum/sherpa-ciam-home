resource "keycloak_realm" "realm" {
  realm        = "customers"
  enabled      = true
}
