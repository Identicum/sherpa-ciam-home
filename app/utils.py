import json
import os
from sherpa.utils.basics import Properties
from sherpa.utils.basics import Logger
from sherpa.keycloak.keycloak_lib import SherpaKeycloakAdmin

logger = Logger(os.path.basename(__file__), os.environ.get("LOG_LEVEL"), "/tmp/python-flask.log")
properties = Properties("/local.properties", "/local.properties")


def get_data():
    datafile = '/data/home.json'
    try:
        with open(datafile, 'r') as f:
            data = json.load(f)
        envs = data.get("environments", {})
        for env_name, env_info in envs.items():
            password = env_info.get("password")
            if isinstance(password, str) and password.startswith("$env:"):
                env_var = password[5:]
                logger.debug("Getting password for env {} from variable '{}'", env_name, env_var)
                env_info["password"] = os.environ.get(env_var, "")
        return data
    except FileNotFoundError:
        logger.error("Data file '{}' not found.", datafile)
        return {}
    except json.JSONDecodeError:
        logger.error("Data file '{}' is not a valid JSON.", datafile)
        return {}


def getRealms(logger):
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


def getEnvironments(logger):
    data = get_data()
    return list(data.get("environments", {}).keys())



def getWorkspaces(logger, realm, environment):
    data = get_data()
    return list(data.get("realms", {}).get(realm, {}).get("workspaces", {}).get(environment, []))


def getKeycloakAdmin(env, realm):
    data = get_data()
    kc_admin = SherpaKeycloakAdmin(
            logger=logger, 
            properties=properties, 
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
        
        if client["attributes"] and client["attributes"].get("realm_client", "") == "true":
            response["type"] = "realm"
        else:
            response["type"] = client["protocol"]

        client_description = client.get("description", "")
        response["tag"] = getClientTag(client_description, client["clientId"])
        response["owner_email"] = splitDescription(client_description, 1, "")
        response["description"] = splitDescription(client_description, 2, client_description)

        if response["type"] == "realm":
            response["enabled"] = True
        else:
            response["enabled"] = client["enabled"]

        # OIDC Exclusive Client Attributes
        if response["type"] == "openid-connect":
            if client["publicClient"]:
                response["access_type"] = "PUBLIC"
            else:
                response["access_type"] = "CONFIDENTIAL"
            if client["attributes"]:
                response["pkce_code_challenge_method"] = client["attributes"].get("pkce.code.challenge.method", None)

            response["authorization_code_flow"] = client["standardFlowEnabled"]
            response["implicit_flow"] = client["implicitFlowEnabled"]
            response["client_credentials_flow"] = client["serviceAccountsEnabled"]
            response["ropc_flow"] = client["directAccessGrantsEnabled"]

            response["frontchannel_logout_enabled"] = client.get("frontchannelLogout", False)
            response["frontchannel_logout_url"] = client["attributes"].get("frontchannel.logout.url", "")

            response["access_token_lifespan"] = int(client["attributes"].get("access.token.lifespan", 0))
            response["effective_access_token_lifespan"] = int(client["attributes"].get("access.token.lifespan", realm.get("accessTokenLifespan", 0)))
            response["realm_access_token_lifespan"] = realm["accessTokenLifespan"]

            response["client_session_idle"] = client["attributes"].get("client.session.idle.timeout", 0)
            effective_realm_client_session_idle = realm["clientSessionIdleTimeout"]
            if effective_realm_client_session_idle == 0:
                effective_realm_client_session_idle = realm["ssoSessionIdleTimeout"]
            response["realm_client_session_idle"] = effective_realm_client_session_idle
            response["effective_client_session_idle"] = int(client["attributes"].get("client.session.idle.timeout", effective_realm_client_session_idle))

            response["client_session_max"] = int(client["attributes"].get("client.session.max.lifespan", 0))
            response["effective_client_session_max"] = int(client["attributes"].get("client.session.max.lifespan", realm.get("clientSessionMaxLifespan", 0)))
            response["realm_client_session_max"] = realm.get("clientSessionMaxLifespan", "")

        # SAML Exclusive Client Attributes
        if response["type"] == "saml":
            if client["attributes"] and client["attributes"].get("saml.assertion.signature"):
                response["saml_assertion_signature"] = client["attributes"]["saml.assertion.signature"]
            if client["attributes"] and client["attributes"].get("saml_name_id_format"):
                response["saml_nameid_format"] = client["attributes"]["saml_name_id_format"]

        # All Clients' Attributes
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
    for realm_name in getRealms(logger):
        native_clients.append("{}-realm".format(realm_name))
    if client_id in native_clients:
        tag = "[KEYCLOAK_NATIVE]"
    if tag not in ["[TAG_MISSING]", "[KEYCLOAK_NATIVE]", "[SPA_NGINX]", "[MOBILE]", "[WEB_BACKEND]", "[CLIENT_CREDENTIALS]", "[SPA_PUBLIC]", "[ROPC]", "[IDP_INTERNAL]", "[SAML]"]:
        tag = "[TAG_INVALID]"           
    return tag

def getVarFiles(logger, environment):
    data = get_data()
    return list(data.get("environments", {}).get(environment, {}).get("var_files", []))