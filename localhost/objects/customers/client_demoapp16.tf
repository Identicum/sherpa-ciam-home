resource "keycloak_openid_client" "demoapp16" {
  realm_id                        = resource.keycloak_realm.realm.id
  client_id                       = "demoapp16_client_id"
  client_secret                   = "demoapp16_client_secret"
  name                            = "demoapp16"
  description                     = "[ROPC]##contact@identicum.com##ROPC with authorization_code, client_credentials; without ropc."
  enabled                         = true
  access_type                     = "CONFIDENTIAL"
  standard_flow_enabled           = true
  implicit_flow_enabled           = false
  direct_access_grants_enabled    = false
  service_accounts_enabled        = true
  root_url                        = "https://demoapp16"
  base_url                        = "/"
  valid_redirect_uris             = [ "/private/redirect_uri", "/private/info" ]
  valid_post_logout_redirect_uris = [ "/logoutSuccess.html" ]
  frontchannel_logout_enabled     = false
}

resource "keycloak_openid_client_default_scopes" "demoapp16_defaultscopes" {
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp16.id
  default_scopes = [ "basic", "profile" ]
}

resource "keycloak_openid_client_optional_scopes" "demoapp16_optionalscopes" {
  depends_on = [ keycloak_openid_client_default_scopes.demoapp16_defaultscopes ]
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.demoapp16.id
  optional_scopes = [ ]
}
