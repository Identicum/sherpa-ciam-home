resource "keycloak_user" "jdoe" {
  realm_id       = keycloak_realm.realm.id
  username       = "jdoe"
  email          = "jdoe@identicum.com"
  enabled        = true
  first_name     = "John"
  last_name      = "Doe"
  email_verified = true
  initial_password {
    value     = "Sherpa.2025"
  }
}
