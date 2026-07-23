resource "keycloak_oidc_identity_provider" "camara" {
  realm           = keycloak_realm.realm.id
  alias           = "camara"
  enabled         = true
  issuer          = "https://rfc7523-issuer.idsherpa.com"
  jwks_url        = "https://jwkporter.idsherpa.com/jwks"

  # Fields required in OIDC provider, not needed for JWT authorization grant (JWT Bearer)
  extra_config = {
    "jwt.authorization.grant.enabled" = "true"
  }
  authorization_url = "https://external-issuer.com/auth"
  token_url         = "https://external-issuer.com/token"
  client_id         = "rfc7523issuer_client_id_not_in_use"
  client_secret     = "rfc7523issuer_client_secret_not_in_use"
  login_hint        = "false"
}
