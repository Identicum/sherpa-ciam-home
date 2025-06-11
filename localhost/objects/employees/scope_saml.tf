resource "keycloak_saml_client_scope" "saml_scope" {
  realm_id = keycloak_realm.realm.id
  name     = "saml_scope"
}