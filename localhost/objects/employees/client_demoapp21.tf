resource "keycloak_openid_client" "demoapp21" {
  realm_id                        = resource.keycloak_realm.realm.id
  client_id                       = "demoapp21_client_id"
  client_secret                   = "demoapp21_client_secret"
  name                            = "demoapp21"
  description                     = "no TAG"
  enabled                         = true
  access_type                     = "CONFIDENTIAL"
  standard_flow_enabled           = true
  implicit_flow_enabled           = false
  direct_access_grants_enabled    = false
  service_accounts_enabled        = false
  root_url                        = "https://demoapp21.example.com"
  base_url                        = "/"
  valid_redirect_uris             = [ "/private/redirect_uri", "/private/info" ]
  valid_post_logout_redirect_uris = [ "/logoutSuccess.html" ]
}

resource "keycloak_openid_client_default_scopes" "demoapp21_defaultscopes" {
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp21.id
  default_scopes = [ "basic", "profile" ]
}

resource "keycloak_openid_client_optional_scopes" "demoapp21_optionalscopes" {
  depends_on = [ keycloak_openid_client_default_scopes.demoapp21_defaultscopes ]
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp21.id
  optional_scopes = [ ]
}
