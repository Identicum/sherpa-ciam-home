resource "keycloak_role" "dev_deployments" {
  realm_id = keycloak_realm.realm.id
  name     = "dev_deployments"
}
resource "keycloak_role" "test_deployments" {
  realm_id = keycloak_realm.realm.id
  name     = "test_deployments"
}
resource "keycloak_role" "prod_deployments" {
  realm_id = keycloak_realm.realm.id
  name     = "prod_deployments"
}

resource "keycloak_role" "dev_tests" {
  realm_id = keycloak_realm.realm.id
  name     = "dev_tests"
}
resource "keycloak_role" "test_tests" {
  realm_id = keycloak_realm.realm.id
  name     = "test_tests"
}
resource "keycloak_role" "prod_tests" {
  realm_id = keycloak_realm.realm.id
  name     = "prod_tests"
}

resource "keycloak_role" "dev_userSessions" {
  realm_id = keycloak_realm.realm.id
  name     = "dev_user-sessions"
}
resource "keycloak_role" "test_userSessions" {
  realm_id = keycloak_realm.realm.id
  name     = "test_user-sessions"
}
resource "keycloak_role" "prod_userSessions" {
  realm_id = keycloak_realm.realm.id
  name     = "prod_user-sessions"
}

resource "keycloak_role" "dev_changeEmail" {
  realm_id = keycloak_realm.realm.id
  name     = "dev_change-email"
}
resource "keycloak_role" "test_changeEmail" {
  realm_id = keycloak_realm.realm.id
  name     = "test_change-email"
}
resource "keycloak_role" "prod_changeEmail" {
  realm_id = keycloak_realm.realm.id
  name     = "prod_change-email"
}