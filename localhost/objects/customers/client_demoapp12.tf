resource "keycloak_openid_client" "demoapp12" {
  realm_id                        = resource.keycloak_realm.realm.id
  client_id                       = "demoapp12_client_id"
  name                            = "demoapp12"
  description                     = "[SPA_PUBLIC]##idp@identicum.com##Public SPA, no PKCE"
  enabled                         = true
  access_type                     = "PUBLIC"
  standard_flow_enabled           = true
  implicit_flow_enabled           = false
  direct_access_grants_enabled    = false
  service_accounts_enabled        = false
  root_url                        = "https://demoapp12.example.com"
  base_url                        = "/"
  valid_redirect_uris             = [ "/private/redirect_uri", "/private/info" ]
  valid_post_logout_redirect_uris = [ "/logoutSuccess.html" ]
  frontchannel_logout_enabled     = false
}

resource "keycloak_openid_client_default_scopes" "demoapp12_defaultscopes" {
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp12.id
  default_scopes = [ "basic", "profile" ]
}

resource "keycloak_openid_client_optional_scopes" "demoapp12_optionalscopes" {
  depends_on = [ keycloak_openid_client_default_scopes.demoapp12_defaultscopes ]
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp12.id
  optional_scopes = [ ]
}
