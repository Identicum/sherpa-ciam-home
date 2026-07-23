resource "keycloak_openid_client_scope" "camara_dpv_CheckLocation" {
   realm_id               = keycloak_realm.realm.id
   name                   = "dpv:CheckLocation"
}

resource "keycloak_openid_client_scope" "camara_location-retrieval" {
   realm_id               = keycloak_realm.realm.id
   name                   = "#location-retrieval"
}