resource "keycloak_openid_client" "demoapp15" {
  realm_id                        = resource.keycloak_realm.realm.id
  client_id                       = "demoapp15_client_id"
  client_secret                   = "demoapp15_client_secret"
  name                            = "demoapp15"
  description                     = "[CLIENT_CREDENTIALS]##contact@identicum.com##CLIENT_CREDENTIALS with implicit, authorization_code, ropc; without client_credentials."
  enabled                         = true
  access_type                     = "CONFIDENTIAL"
  pkce_code_challenge_method      = "S256"
  standard_flow_enabled           = true
  implicit_flow_enabled           = true
  direct_access_grants_enabled    = true
  service_accounts_enabled        = false
  root_url                        = "https://demoapp15"
  base_url                        = "/"
  valid_redirect_uris             = [ "/private/redirect_uri", "/private/info" ]
  valid_post_logout_redirect_uris = [ "/logoutSuccess.html" ]
  frontchannel_logout_enabled     = false
  access_token_lifespan           = "1800"
}

resource "keycloak_openid_client_default_scopes" "demoapp15_defaultscopes" {
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp15.id
  default_scopes = [ "basic", "profile" ]
}

resource "keycloak_openid_client_optional_scopes" "demoapp15_optionalscopes" {
  depends_on = [ keycloak_openid_client_default_scopes.demoapp15_defaultscopes ]
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp15.id
  optional_scopes = [ ]
}
