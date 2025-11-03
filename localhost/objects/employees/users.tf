resource "keycloak_user" "user1" {
  realm_id       = keycloak_realm.realm.id
  username       = "user1"
  email          = "user1@identicum.com"
  enabled        = true
  first_name     = "user1"
  last_name      = "user1"
  email_verified = true
  initial_password {
    value     = "Sherpa.2025"
  }
}
