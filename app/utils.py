import json
import os
from sherpa.utils.basics import Properties
from sherpa.utils.basics import Logger
from sherpa.keycloak.keycloak_lib import SherpaKeycloakAdmin

logger = Logger(os.path.basename(__file__), "TRACE", "/tmp/python-flask.log")
properties = Properties("/local.properties", "/local.properties")

def get_data():
    try:
        with open('/data/data.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # ToDo: Handle cases where the file does not exist
        return {}
    except json.JSONDecodeError:
        # ToDo: Handle cases where JSON is invalid
        return {}

def getRealms():
    data = get_data()
    return list(data.get("realms", {}).keys())

def getRealm(env, realmName):
    kc_admin = getKeycloakAdmin(env, realmName)
    if not kc_admin:
        return []
    try:
        realm = kc_admin.get_realm(realmName)
        return realm
    except Exception as e:
        logger.error("Error fetching realm for {}/{}: {}", env, realm, e)
        return []

def getEnvironments():
    data = get_data()
    return list(data.get("environments", {}).keys())

# def getKeycloakUrl(env):
#     data = get_data()
#     return data.get("environments", {}).get(env, {}).get("keycloak_url", "")

def getKeycloakAdmin(env, realm):
    data = get_data()
    kc_admin = SherpaKeycloakAdmin(
            logger=logger, 
            local_properties=properties, 
            server_url=data.get("environments", {}).get(env, {}).get("keycloak_url", ""), 
            username=data.get("environments", {}).get(env, {}).get("username", ""), 
            password=data.get("environments", {}).get(env, {}).get("password", ""), 
            user_realm_name="master",
            realm_name=realm, 
            verify=False
        )
    return kc_admin

def getClients(env, realm):
    kc_admin = getKeycloakAdmin(env, realm)
    if not kc_admin:
        return []
    try:
        clients = kc_admin.get_clients()
        return clients
    except Exception as e:
        logger.error("Error fetching clients for {}/{}: {}", env, realm, e)
        return []

def getClient(env, realmName, client_id):
    """
    Get Client object in normalized form, to simplify functions.

    :param env (str): Environment
    :param realmName (str): Realm name
    :param client_id (str): client_id
    :return: Client object
    """
    kc_admin = getKeycloakAdmin(env, realmName)
    if not kc_admin:
        return {}
    try:
        client_keycloak_id = kc_admin.get_client_id(client_id)
        client = kc_admin.get_client(client_keycloak_id)
        realm = kc_admin.get_realm(realmName)
        response = {}
        logger.trace("KC Client object: {}, type: {}", client, type(client))
        response["id"] = client["id"]
        response["realm_name"] = realmName
        response["client_id"] = client["clientId"]
        response["name"] = client["name"]
        response["enabled"] = client["enabled"]

        client_description = client["description"] if "description" in client else ""
        response["tag"] = getClientTag(client_description, client["clientId"])
        response["owner_email"] = splitDescription(client_description, 1, "")
        response["description"] = splitDescription(client_description, 2, client_description)

        if client["publicClient"]:
            response["access_type"] = "PUBLIC"
        else:
            response["access_type"] = "CONFIDENTIAL"

        response["authorization_code_flow"] = client["standardFlowEnabled"]
        response["implicit_flow"] = client["implicitFlowEnabled"]
        response["client_credentials_flow"] = client["serviceAccountsEnabled"]
        response["ropc_flow"] = client["directAccessGrantsEnabled"]

        response["root_url"] = client.get("rootUrl", "")
        response["admin_url"] = client.get("adminUrl", "")
        response["base_url"] = client.get("baseUrl", "")
        response["redirect_uris"] = client.get("redirectUris", [])
        if client["attributes"] and client["attributes"].get("post.logout.redirect.uris"):
            response["post_logout_redirect_uris"] = client["attributes"]["post.logout.redirect.uris"].split('##')
        else:
            response["post_logout_redirect_uris"] = []
        logger.trace("post_logout_redirect_uris: {}", response["post_logout_redirect_uris"])
        response["web_origins"] = client.get("webOrigins", [])

        response["access_token_lifespan"] = client["attributes"].get("access.token.lifespan", "(inherit from realm)")
        response["effective_access_token_lifespan"] = client["attributes"].get("access.token.lifespan", realm.get("accessTokenLifespan", ""))
        response["realm_access_token_lifespan"] = realm.get("accessTokenLifespan", "")

        response["client_session_idle"] = client["attributes"].get("client.session.idle.timeout", "(inherit from realm)")
        response["effective_client_session_idle"] = client["attributes"].get("client.session.idle.timeout", realm.get("clientSessionIdleTimeout", ""))
        response["realm_client_session_idle"] = realm.get("clientSessionIdleTimeout", "")

        response["client_session_max"] = client["attributes"].get("client.session.max.lifespan", "(inherit from realm)")
        response["effective_client_session_max"] = client["attributes"].get("client.session.max.lifespan", realm.get("clientSessionMaxLifespan", ""))
        response["realm_client_session_max"] = realm.get("clientSessionMaxLifespan", "")

        logger.trace("Returning response: {}", response)
        return response
    except Exception as e:
        logger.error("Error fetching client for {}/{}/{}: {}", env, realmName, client_id, e)
        return {}

def splitDescription(description, position, defaultValue):
    """
    Extract Client information from description custom syntax.

    :param description (str): Client description in format 'TAG##ownerEmail##Client description'.
    :return: Text in position, otherwise None.
    """
    extracted = None
    if description and isinstance(description, str) and "##" in description:
        extracted = description.split("##")[position]
    logger.trace("description: {}, position: {}, type: {}, extracted: '{}', type: {}", description, position, type(position), extracted, type(extracted))
    if extracted is not None:
        return extracted
    else:
        return defaultValue

def getClientTag(description, client_id):
    """
    Get [TAG] from description and client_id.

    :param description (str): Client description in format '[TAG]##ownerEmail##Client description'.
    :param client_id (str): client_id.
    :return: TAG or TAG_MISSING or TAG_INVALID
    """
    tag = splitDescription(description, 0, "[TAG_MISSING]")
    native_clients = [ "account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console" ]
    for realm_name in getRealms():
        native_clients.append("{}-realm".format(realm_name))
    if client_id in native_clients:
        tag = "[KEYCLOAK_NATIVE]"
    if tag not in ["[TAG_MISSING]", "[KEYCLOAK_NATIVE]", "[SPA_NGINX]", "[MOBILE]", "[WEB_BACKEND]", "[CLIENT_CREDENTIALS]", "[SPA_PUBLIC]", "[ROPC]", "[IDP_INTERNAL]"]:
        tag = "[TAG_INVALID]"           
    return tag