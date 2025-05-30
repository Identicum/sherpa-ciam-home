resource "keycloak_openid_client" "sherpaciamhome" {
  realm_id                     = data.keycloak_realm.realm.id
  client_id                    = "sherpaciamhome_client_id"
  client_secret                = "sherpaciamhome_client_secret"
  name                         = "sherpaciamhome"
  enabled                      = true
  access_type                  = "CONFIDENTIAL"
  standard_flow_enabled        = false
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = true
}

resource "keycloak_openid_client_default_scopes" "sherpaciamhome_defaultscopes" {
  realm_id  = data.keycloak_realm.realm.id
  client_id = keycloak_openid_client.sherpaciamhome.id
  default_scopes = [ "basic", "roles" ]
}

resource "keycloak_openid_client_optional_scopes" "sherpaciamhome_optionalscopes" {
  depends_on = [ keycloak_openid_client_default_scopes.sherpaciamhome_defaultscopes ]
  realm_id  = data.keycloak_realm.realm.id
  client_id = keycloak_openid_client.sherpaciamhome.id
  optional_scopes = [ ]
}