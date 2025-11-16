resource "keycloak_openid_client" "sherpaciamhome" {
  realm_id                        = resource.keycloak_realm.realm.id
  client_id                       = "sherpaciamhome_client_id"
  client_secret                   = "sherpaciamhome_client_secret"
  description                     = "[SPA_NGINX]##contact@identicum.com##Sherpa CIAM Home"
  enabled                         = true
  access_type                     = "CONFIDENTIAL"
  standard_flow_enabled           = true
  implicit_flow_enabled           = false
  direct_access_grants_enabled    = false
  service_accounts_enabled        = false
  root_url                        = "http://localhost"
  base_url                        = "/"
  valid_redirect_uris             = [ "/oidc_callback" ]
  valid_post_logout_redirect_uris = [ "/logoutSuccess" ]
  frontchannel_logout_enabled     = false
}

resource "keycloak_openid_client_optional_scopes" "sherpaciamhome" {
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.sherpaciamhome.id
  optional_scopes = [ ]
}

resource "keycloak_openid_client_default_scopes" "sherpaciamhome" {
  realm_id  = resource.keycloak_realm.realm.id
  client_id = keycloak_openid_client.sherpaciamhome.id
  default_scopes = [ "basic", "email", "profile" ]
}
