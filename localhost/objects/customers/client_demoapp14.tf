resource "keycloak_openid_client" "demoapp14" {
  realm_id                        = resource.keycloak_realm.realm.id
  client_id                       = "demoapp14_client_id"
  client_secret                   = "demoapp14_client_secret"
  name                            = "demoapp14"
  description                     = "[SPA_NGINX]##contact@identicum.com##Confidential Client with PKCE enabled."
  enabled                         = true
  access_type                     = "CONFIDENTIAL"
  pkce_code_challenge_method      = "S256"
  standard_flow_enabled           = true
  implicit_flow_enabled           = false
  direct_access_grants_enabled    = false
  service_accounts_enabled        = false
  root_url                        = "https://demoapp14"
  base_url                        = "/"
  valid_redirect_uris             = [ "/private/redirect_uri", "/private/info" ]
  valid_post_logout_redirect_uris = [ "/logoutSuccess.html" ]
  frontchannel_logout_enabled     = false
}

resource "keycloak_openid_client_default_scopes" "demoapp14_defaultscopes" {
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp14.id
  default_scopes = [ "basic", "profile" ]
}

resource "keycloak_openid_client_optional_scopes" "demoapp14_optionalscopes" {
  depends_on = [ keycloak_openid_client_default_scopes.demoapp14_defaultscopes ]
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp14.id
  optional_scopes = [ ]
}
