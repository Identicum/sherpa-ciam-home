resource "keycloak_openid_client" "demoapp11" {
  realm_id                        = resource.keycloak_realm.realm.id
  client_id                       = "demoapp11_client_id"
  client_secret                   = "demoapp11_client_secret"
  name                            = "demoapp11"
  description                     = "[MOBILE]##idp@identicum.com##Mobile confidential"
  enabled                         = true
  access_type                     = "CONFIDENTIAL"
  standard_flow_enabled           = true
  implicit_flow_enabled           = false
  direct_access_grants_enabled    = false
  service_accounts_enabled        = false
  root_url                        = "https://demoapp11.example.com"
  base_url                        = "/"
  valid_redirect_uris             = [ "/private/redirect_uri", "/private/info" ]
  valid_post_logout_redirect_uris = [ "/logoutSuccess.html" ]
  frontchannel_logout_enabled     = false
}

resource "keycloak_openid_client_default_scopes" "demoapp11_defaultscopes" {
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp11.id
  default_scopes = [ "basic", "profile" ]
}

resource "keycloak_openid_client_optional_scopes" "demoapp11_optionalscopes" {
  depends_on = [ keycloak_openid_client_default_scopes.demoapp11_defaultscopes ]
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp11.id
  optional_scopes = [ ]
}
