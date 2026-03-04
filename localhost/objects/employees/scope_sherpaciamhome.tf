resource "keycloak_openid_client_scope" "sherpa_ciam_home_roles" {
  realm_id               = keycloak_realm.realm.id
  name                   = "sherpa_ciam_home_roles"
  description            = "Sherpa CIAM home roles"
}

resource "keycloak_generic_protocol_mapper" "openid_sherpa_ciam_home_roles" {
  realm_id        = keycloak_realm.realm.id
  client_scope_id = keycloak_openid_client_scope.sherpa_ciam_home_roles.id
  name            = "groups"
  protocol        = "openid-connect"
  protocol_mapper = "oidc-usermodel-realm-role-mapper"
  config = {
    "introspection.token.claim": false,
    "multivalued": true,
    "access.token.claim": true,
    "claim.name": "sherpa_ciam_home_roles",
    "jsonType.label": "String"
  }
}
