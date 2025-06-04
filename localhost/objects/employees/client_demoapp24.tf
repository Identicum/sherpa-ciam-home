resource "keycloak_openid_client" "demoapp24" {
  realm_id                        = resource.keycloak_realm.realm.id
  client_id                       = "demoapp24_client_id"
  client_secret                   = "demoapp24_client_secret"
  name                            = "demoapp24"
  description                     = "[SPA_NGINX]##contact@identicum.com##frontchannel logout enabled, no url"
  enabled                         = true
  access_type                     = "CONFIDENTIAL"
  standard_flow_enabled           = true
  implicit_flow_enabled           = false
  direct_access_grants_enabled    = false
  service_accounts_enabled        = false
  root_url                        = "https://demoapp24"
  base_url                        = "/"
  valid_redirect_uris             = [ "/private/redirect_uri", "/private/info" ]
  valid_post_logout_redirect_uris = [ "/logoutSuccess.html" ]
  frontchannel_logout_enabled     = true
}

resource "keycloak_openid_client_default_scopes" "demoapp24_defaultscopes" {
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp24.id
  default_scopes = [ "basic", "profile" ]
}

resource "keycloak_openid_client_optional_scopes" "demoapp24_optionalscopes" {
  depends_on = [ keycloak_openid_client_default_scopes.demoapp24_defaultscopes ]
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp24.id
  optional_scopes = [ ]
}
