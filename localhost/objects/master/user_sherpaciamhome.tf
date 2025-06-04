resource "keycloak_user" "sherpaciamhome" {
  realm_id       = data.keycloak_realm.realm.id
  username       = "sherpaciamhome"
  email          = "sherpaciamhome@identicum.com"
  enabled        = true
  first_name     = "Sherpa"
  last_name      = "CIAM Home"
  email_verified = true
  initial_password {
    value     = "Sherpa.2025"
  }
}

resource "keycloak_user_roles" "sherpaciamhome_roles" {
  realm_id = data.keycloak_realm.realm.id
  user_id  = keycloak_user.sherpaciamhome.id
  role_ids = [ keycloak_role.idp_readonly.id ]
}
