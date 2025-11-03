resource "keycloak_saml_client" "demoapp26" {
  realm_id                        = resource.keycloak_realm.realm.id
  client_id                       = "http://demoapp0/"
  name                            = "demoapp26"
  description                     = "[SAML]##contact@identicum.com##no redirect uris"
  enabled                         = true
  # valid_redirect_uris             = [ "http://demoapp0/acs.jsp" ]
  # logout_service_post_binding_url = "http://demoapp0/sls.jsp"
  client_signature_required       = false
  force_name_id_format            = true
  name_id_format                  = "username"
}

resource "keycloak_saml_client_default_scopes" "demoapp26" {
  realm_id       = keycloak_realm.realm.id
  client_id      = keycloak_saml_client.demoapp26.id
  default_scopes = [ keycloak_saml_client_scope.saml_scope.name ]
}