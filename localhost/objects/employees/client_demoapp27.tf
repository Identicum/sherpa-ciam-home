resource "keycloak_openid_client" "demoapp17" {
  realm_id                        = resource.keycloak_realm.realm.id
  client_id                       = "demoapp27_client_id"
  client_secret                   = "demoapp27_client_secret"
  name                            = "demoapp27"
  description                     = "[CLIENT_CREDENTIALS]##contact@identicum.com##no service_account scope"
  enabled                         = true
  access_type                     = "CONFIDENTIAL"
  standard_flow_enabled           = false
  implicit_flow_enabled           = false
  direct_access_grants_enabled    = false
  service_accounts_enabled        = true
  frontchannel_logout_enabled     = false
}

resource "keycloak_openid_client_optional_scopes" "demoapp27" {
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp17.id
  optional_scopes = [ ]
}

resource "keycloak_openid_client_default_scopes" "demoapp27" {
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp17.id
  default_scopes = [ "basic", "roles" ]
}
