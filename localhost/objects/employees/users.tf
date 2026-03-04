resource "keycloak_user" "user1" {
  realm_id       = keycloak_realm.realm.id
  username       = "user1"
  email          = "user1@identicum.com"
  enabled        = true
  first_name     = "user1"
  last_name      = "user1"
  email_verified = true
  initial_password {
    value     = "Sherpa.2025"
  }
}
resource "keycloak_user_roles" "user1" {
  realm_id = keycloak_realm.realm.id
  user_id  = keycloak_user.user1.id

  role_ids = [
    keycloak_role.dev_deployments.id,
    keycloak_role.test_deployments.id,
    keycloak_role.prod_deployments.id,
    keycloak_role.dev_tests.id,
    keycloak_role.test_tests.id,
    keycloak_role.prod_tests.id,
    keycloak_role.dev_userSessions.id,
    keycloak_role.test_userSessions.id,
    keycloak_role.prod_userSessions.id
  ]
}


resource "keycloak_user" "user2" {
  realm_id       = keycloak_realm.realm.id
  username       = "user2"
  email          = "user2@identicum.com"
  enabled        = true
  first_name     = "user2"
  last_name      = "user2"
  email_verified = true
  initial_password {
    value     = "Sherpa.2025"
  }
}
resource "keycloak_user_roles" "user2" {
  realm_id = keycloak_realm.realm.id
  user_id  = keycloak_user.user2.id

  role_ids = [
    keycloak_role.dev_deployments.id,
    keycloak_role.test_deployments.id,
    keycloak_role.dev_tests.id,
    keycloak_role.test_tests.id,
    keycloak_role.dev_userSessions.id
  ]
}

