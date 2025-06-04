resource "keycloak_openid_client" "demoapp23" {
  realm_id                        = resource.keycloak_realm.realm.id
  client_id                       = "demoapp23_client_id"
  client_secret                   = "demoapp23_client_secret"
  name                            = "demoapp23"
  description                     = "[SPA_NGINX]##contact@identicum.com##multiple absolute redirect_uri values"
  enabled                         = true
  access_type                     = "CONFIDENTIAL"
  standard_flow_enabled           = true
  implicit_flow_enabled           = false
  direct_access_grants_enabled    = false
  service_accounts_enabled        = false
  root_url                        = "https://demoapp23"
  base_url                        = "/"
  valid_redirect_uris             = [ "https://demoapp23/private/redirect_uri", "https://demoapp23/private/info" ]
  valid_post_logout_redirect_uris = [ "https://demoapp23/logoutSuccess.html" ]
  frontchannel_logout_enabled     = false
}

resource "keycloak_openid_client_default_scopes" "demoapp23_defaultscopes" {
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp23.id
  default_scopes = [ "basic", "profile" ]
}

resource "keycloak_openid_client_optional_scopes" "demoapp23_optionalscopes" {
  depends_on = [ keycloak_openid_client_default_scopes.demoapp23_defaultscopes ]
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp23.id
  optional_scopes = [ ]
}
