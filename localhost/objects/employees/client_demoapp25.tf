resource "keycloak_openid_client" "demoapp25" {
  realm_id                        = resource.keycloak_realm.realm.id
  client_id                       = "demoapp25_client_id"
  client_secret                   = "demoapp25_client_secret"
  name                            = "demoapp25"
  description                     = "[SPA_NGINX]##contact@identicum.com##frontchannel logout disabled, with url"
  enabled                         = true
  access_type                     = "CONFIDENTIAL"
  standard_flow_enabled           = true
  implicit_flow_enabled           = false
  direct_access_grants_enabled    = false
  service_accounts_enabled        = false
  root_url                        = "https://demoapp25"
  base_url                        = "/"
  valid_redirect_uris             = [ "/private/redirect_uri", "/private/info" ]
  valid_post_logout_redirect_uris = [ "/logoutSuccess.html" ]
  frontchannel_logout_enabled     = false
  frontchannel_logout_url         = "https://demoapp25/frontchannel_logout"
}

resource "keycloak_openid_client_default_scopes" "demoapp25_defaultscopes" {
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp25.id
  default_scopes = [ "basic", "profile" ]
}

resource "keycloak_openid_client_optional_scopes" "demoapp25_optionalscopes" {
  depends_on = [ keycloak_openid_client_default_scopes.demoapp25_defaultscopes ]
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp25.id
  optional_scopes = [ ]
}
