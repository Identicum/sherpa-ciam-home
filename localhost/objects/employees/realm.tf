resource "keycloak_realm" "realm" {
  realm        = "employees"
  enabled      = true
}
