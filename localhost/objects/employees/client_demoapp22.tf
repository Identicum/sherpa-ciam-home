resource "keycloak_openid_client" "demoapp22" {
  realm_id                        = resource.keycloak_realm.realm.id
  client_id                       = "demoapp22_client_id"
  client_secret                   = "demoapp22_client_secret"
  name                            = "demoapp22"
  description                     = "[SPA_NGINX]####no owner email"
  enabled                         = true
  access_type                     = "CONFIDENTIAL"
  standard_flow_enabled           = true
  implicit_flow_enabled           = false
  direct_access_grants_enabled    = false
  service_accounts_enabled        = false
  root_url                        = "https://demoapp22.example.com"
  base_url                        = "/"
  valid_redirect_uris             = [ "/private/redirect_uri", "/private/info" ]
  valid_post_logout_redirect_uris = [ "/logoutSuccess.html" ]
  frontchannel_logout_enabled     = false
}

resource "keycloak_openid_client_optional_scopes" "demoapp22" {
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp22.id
  optional_scopes = [ "service_account" ]
}

resource "keycloak_openid_client_default_scopes" "demoapp22" {
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp22.id
  default_scopes = [ "basic", "profile" ]
}
