resource "keycloak_openid_client" "demoapp13" {
  realm_id                        = resource.keycloak_realm.realm.id
  client_id                       = "demoapp13_client_id"
  name                            = "demoapp13"
  description                     = "[SPA_NGINX]##contact@identicum.com##NGINX SPA, should be confidential. With web_origins. No post_logout."
  enabled                         = true
  access_type                     = "PUBLIC"
  standard_flow_enabled           = true
  implicit_flow_enabled           = false
  direct_access_grants_enabled    = false
  service_accounts_enabled        = false
  root_url                        = "https://demoapp13"
  base_url                        = "/"
  valid_redirect_uris             = [ "/private/redirect_uri", "/private/info" ]
  web_origins                     = [ "https://demoapp13.example.com" ]
  frontchannel_logout_enabled     = false
}

resource "keycloak_openid_client_default_scopes" "demoapp13_defaultscopes" {
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp13.id
  default_scopes = [ "basic", "profile" ]
}

resource "keycloak_openid_client_optional_scopes" "demoapp13_optionalscopes" {
  depends_on = [ keycloak_openid_client_default_scopes.demoapp13_defaultscopes ]
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp13.id
  optional_scopes = [ ]
}
