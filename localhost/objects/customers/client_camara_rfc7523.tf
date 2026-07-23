resource "keycloak_openid_client" "camara_rfc7523" {
  realm_id                     = keycloak_realm.realm.id
  name                         = "camara_rfc7523"
  client_id                    = "https://rfc7523-issuer.idsherpa.com"
  client_secret                = "camara_rfc7523_client_secret"
  description                  = "CAMARA example using JWT bearer grant"
  access_type                  = "CONFIDENTIAL"
  standard_flow_enabled        = false
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = false
  access_token_lifespan        = "300"
  extra_config = {
    (module.constants.owner_email)           = "idp@identicum.com",
    (module.constants.type)                  = (module.constants.clientType_jwtBearer),
    "oauth2.jwt.authorization.grant.enabled" = true
    "oauth2.jwt.authorization.grant.idp"     = keycloak_oidc_identity_provider.camara.alias
  }
}

resource "keycloak_openid_client_default_scopes" "camara_rfc7523" {
  depends_on     = [ keycloak_openid_client_optional_scopes.camara_rfc7523 ]
  realm_id       = keycloak_realm.realm.id
  client_id      = keycloak_openid_client.camara_rfc7523.id
  default_scopes = [ "basic" ]
}

resource "keycloak_openid_client_optional_scopes" "camara_rfc7523" {
  realm_id        = keycloak_realm.realm.id
  client_id       = keycloak_openid_client.camara_rfc7523.id
  optional_scopes = [ keycloak_openid_client_scope.camara_dpv_CheckLocation.name, keycloak_openid_client_scope.camara_location-retrieval.name ]
}
