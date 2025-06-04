# MASTER
data "keycloak_openid_client" "master_realm_client" {
  realm_id  = data.keycloak_realm.realm.id
  client_id = "master-realm"
}

data "keycloak_role" "master_view_realm" {
  realm_id = data.keycloak_realm.realm.id
  client_id = data.keycloak_openid_client.master_realm_client.id
  name     = "view-realm"
}

data "keycloak_role" "master_view_clients" {
  realm_id = data.keycloak_realm.realm.id
  client_id = data.keycloak_openid_client.master_realm_client.id
  name     = "view-clients"
}

# CUSTOMERS
data "keycloak_openid_client" "customers_realm_client" {
  realm_id  = data.keycloak_realm.realm.id
  client_id = "customers-realm"
}

data "keycloak_role" "customers_view_realm" {
  realm_id  = data.keycloak_realm.realm.id
  client_id = data.keycloak_openid_client.customers_realm_client.id
  name      = "view-realm"
}

data "keycloak_role" "customers_view_clients" {
  realm_id  = data.keycloak_realm.realm.id
  client_id = data.keycloak_openid_client.customers_realm_client.id
  name      = "view-clients"
}

# EMPLOYEES
data "keycloak_openid_client" "employees_realm_client" {
  realm_id  = data.keycloak_realm.realm.id
  client_id = "employees-realm"
}

data "keycloak_role" "employees_view_realm" {
  realm_id  = data.keycloak_realm.realm.id
  client_id = data.keycloak_openid_client.employees_realm_client.id
  name      = "view-realm"
}

data "keycloak_role" "employees_view_clients" {
  realm_id  = data.keycloak_realm.realm.id
  client_id = data.keycloak_openid_client.employees_realm_client.id
  name      = "view-clients"
}

# ROLES
resource "keycloak_role" "idp_readonly" {
  realm_id  = data.keycloak_realm.realm.id
  name      = "idp_readonly"
  composite_roles = [
    data.keycloak_role.master_view_realm.id,
    data.keycloak_role.master_view_clients.id,
    data.keycloak_role.customers_view_realm.id,
    data.keycloak_role.customers_view_clients.id,
    data.keycloak_role.employees_view_realm.id,
    data.keycloak_role.employees_view_clients.id
  ]
}