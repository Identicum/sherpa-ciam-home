import json
import os
from sherpa.utils.basics import Properties
from sherpa.utils.basics import Logger
from sherpa.keycloak.keycloak_lib import SherpaKeycloakAdmin

logger = Logger(os.path.basename(__file__), os.environ.get("LOG_LEVEL"), "/tmp/python-flask.log")
properties = Properties("/local.properties", "/local.properties")

valid_client_types = ["[SPA_NGINX]", "[MOBILE]", "[WEB_BACKEND]", "[CLIENT_CREDENTIALS]", "[SPA_PUBLIC]", "[ROPC]", "[IDP_INTERNAL]", "[SAML]"]

def getData() -> dict:
    """Returns the parsed contents of /data/home.json

    Returns:
        dict: Parsed contents of /data/home.json
    """
    datafile = '/data/home.json'
    try:
        with open(datafile, 'r') as f:
            data = json.load(f)
        envs = data.get("environments", {})
        for env_name, env_info in envs.items():
            password = env_info.get("password")
            if isinstance(password, str) and password.startswith("$env:"):
                env_var = password[5:]
                logger.trace("Getting password for env {} from variable '{}'", env_name, env_var)
                env_info["password"] = os.environ.get(env_var, "")
        return data
    except FileNotFoundError:
        logger.error("Data file '{}' not found.", datafile)
        return {}
    except json.JSONDecodeError:
        logger.error("Data file '{}' is not a valid JSON.", datafile)
        return {}


def getRealmTypes(logger: Logger) -> list:
    """Returns the list of realm types from /data/home.json

    Args:
        logger (Logger): Logger instance

    Returns:
        list: List of realm types
    """
    data = getData()
    return list(data.get("realms", {}).keys())


def getRealms(logger: Logger, environment: str) -> list:
    """Returns only the list of realms from /data/home.json

    Args:
        logger (Logger): Logger instance
        environment (str): Environment name

    Returns:
        list: List of realms from /data/home.json
    """
    data = getData()
    realm_list = []
    realm_types = list(data.get("realms", {}).keys())
    for realm_type in realm_types:
        logger.trace("getRealms() processing realm_type: {}", realm_type)
        for workspace in getWorkspaces(logger, realm_type, environment):
            logger.trace("getRealms() processing workspace: {}", workspace)
            realm_name = getRealmName(logger, realm_type, environment, workspace)
            realm_list.append(realm_name)
    return realm_list


def getRealm(env: str, realmName: str) -> dict:
    """Will fetch a realm from a given Environment using Keycloak's Admin API and return it

    Args:
        env (str): Environment name
        realmName (str): Realm name

    Returns:
        dict: Realm Object from the Keycloak API
    """
    kc_admin = getKeycloakAdmin(env, realmName)
    if not kc_admin:
        return []
    try:
        realm = kc_admin.get_realm(realmName)
        return realm
    except Exception as e:
        logger.error("Error fetching realm for {}/{}: {}", env, realm, e)
        return []


def getRealmName(logger: Logger, realmType: str, environment: str, workspace: str) -> str:
    """Get realm name from its type, environment and workspace

    Args:
        logger (Logger): Logger instance
        realmType (str): Realm type
        environment (str): Environment
        workspace (str): Workspace

    Returns:
        str: Realm name
    """
    data = getData()
    realmName = data.get("realms", {}).get(realmType, {}).get(environment, {}).get(workspace, {}).get("realm_name", realmType)
    logger.trace("getRealmName() processing realmType: {}, environment: {}, workspace: {}, realmName: {}", realmType, environment, workspace, realmName)
    return realmName


def getEnvironments(logger: Logger) -> list:
    """Returns only the list of environments from /data/home.json

    Args:
        logger (Logger): Logger instance

    Returns:
        list: List of Environments from /data/home.json
    """
    data = getData()
    return list(data.get("environments", {}).keys())



def getWorkspaces(logger: Logger, realmType: str, environment: str) -> list:
    data = getData()
    """Returns only the list of a given realm's workspaces from /data/home.json

    Args:
        logger (Logger): Logger instance

    Returns:
        list: List of the given realm's workspaces from /data/home.json
    """
    logger.trace("getWorkspaces() processing realmType: {}, environment: {}", realmType, environment)
    realms = data.get("realms", {})
    realm_type = realms.get(realmType)
    instance = realm_type.get(environment)

    return list(data.get("realms", {}).get(realmType).get(environment, {}).keys())


def getKeycloakAdmin(env: str, realm: str) -> SherpaKeycloakAdmin:
    """Creates an instance of SherpaKeycloakAdmin passing the given environment and realm's data in params
    (See in [sherpa-py-keycloak](https://github.com/Identicum/sherpa-py-keycloak/blob/main/sherpa/keycloak/keycloak_lib.py))

    Args:
        env (str): Environment name - Must match the equal one in /home/data.json for the function to properly fetch `keycloak_url`, `username` and `password`
        realm (str): Realm name - To be passed as a parameter for SherpaKeycloakAdmin

    Returns:
        SherpaKeycloakAdmin: Resulting SherpaKeycloakAdmin instance
    """
    data = getData()
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


def getClients(env: str, realm: str) -> list:
    """Will fetch a given realm in a given environment's client list from the Keycloak API and return it.

    Args:
        env (str): Environment name
        realm (str): Realm name

    Returns:
        list: List of clients in the realm
    """
    kc_admin = getKeycloakAdmin(env, realm)
    if not kc_admin:
        return []
    try:
        clients = kc_admin.get_clients()
        return clients
    except Exception as e:
        logger.error("Error fetching clients for {}/{}: {}", env, realm, e)
        return []


def getClient(env: str, realmName: str, client_id: str) -> dict:
    """Will fetch a Client from a given Realm in a given Environment using the provided `client_id` in the Keycloak API, then format the object so as to standardize the output between different client types

    Args:
        env (str): Environment name
        realmName (str): Realm name
        client_id (str): Client ID
    Returns:
        dict: Resulting Client Object
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
        response["name"] = client.get("name", "")
        
        if client["attributes"] and client["attributes"].get("realm_client", "") == "true":
            response["type"] = "realm"
        else:
            response["type"] = client["protocol"]

        client_description = client.get("description", "")
        response["tag"] = getClientTag(client_description, client["clientId"], response["type"])
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


def splitDescription(description: str, position: int, defaultValue: str) -> str:
    """Extracts whichever detail it finds in the provided `position` inside of a client `description` (also provided). Will return the provided default value if it finds nothing.

    Args:
        description (str): Client Description - Custom Syntax
        position (str): Desired detail's position in the description
        defaultValue (str): Value to be provided if nothing is found

    Returns:
        str: Found value in the client description
    """
    extracted = None
    if description and isinstance(description, str) and "##" in description:
        extracted = description.split("##")[position]
    logger.trace("description: {}, position: {}, type: {}, extracted: '{}', type: {}", description, position, type(position), extracted, type(extracted))
    if extracted is not None:
        return extracted
    else:
        return defaultValue


def getClientTag(description: str, client_id: str, client_type: str) -> str:
    """Extracts a client tag from a provided description (Custom Syntax) \n
    Will automatically filter Native keycloak client tags using the provided client_id and mark unsupported tags as [TAG_INVALID]

    Args:
        description (str): _description_
        client_id (str): _description_
        client_type (str): realm / openid-connect / saml

    Returns:
        str: Client Tag - Example: [SPA_PUBLIC]
    """
    if client_type=="realm":
        return "[KEYCLOAK_NATIVE]"

    native_clients = [ "account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console" ]
    if client_id in native_clients:
        return "[KEYCLOAK_NATIVE]"

    tag = splitDescription(description, 0, "")
    if tag == "":
        return "[TAG_MISSING]"
    if tag not in valid_client_types:
        return "[TAG_INVALID]"           
    return tag


def getVarFiles(logger: Logger, environment: str) -> list:
    """Returns only the list of var_file paths related to the provided environment - from /data/home.json

    Args:
        logger (Logger): Logger instance
        environment (str): Environment name - Must match that of the one in /data/home.json

    Returns:
        list: List of var_file paths related to the environment
    """
    data = getData()
    return list(data.get("environments", {}).get(environment, {}).get("var_files", []))