resource "keycloak_openid_client" "demoapp17" {
  realm_id                        = resource.keycloak_realm.realm.id
  client_id                       = "demoapp17_client_id"
  client_secret                   = "demoapp17_client_secret"
  name                            = "demoapp17"
  description                     = "[CLIENT_CREDENTIALS]##contact@identicum.com##client_session_idle_timeout > realm_sso_idle_timeout."
  enabled                         = true
  access_type                     = "CONFIDENTIAL"
  standard_flow_enabled           = false
  implicit_flow_enabled           = false
  direct_access_grants_enabled    = false
  service_accounts_enabled        = true
  frontchannel_logout_enabled     = false
  access_token_lifespan           = "1800"
  client_session_idle_timeout     = "2800"
}

resource "keycloak_openid_client_default_scopes" "demoapp17_defaultscopes" {
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp17.id
  default_scopes = [ "basic", "profile" ]
}

resource "keycloak_openid_client_optional_scopes" "demoapp17_optionalscopes" {
  depends_on = [ keycloak_openid_client_default_scopes.demoapp17_defaultscopes ]
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp17.id
  optional_scopes = [ ]
}
