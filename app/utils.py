from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from elasticsearch import Elasticsearch
import json
import os
from sherpa.utils.basics import Properties
from sherpa.utils.basics import Logger
from sherpa.keycloak.keycloak_lib import SherpaKeycloakAdmin
import smtplib


def getLogger():
    return Logger(os.path.basename(__file__), os.environ.get("LOG_LEVEL"), "/tmp/python-flask.log")


def getLocalDatetime() -> str:
    """Return the current local date/time as an ISO string with timezone offset."""
    localNow = datetime.now().astimezone()
    return localNow.strftime("%Y-%m-%d %H:%M:%S")


def getConfig(logger: Logger) -> dict:
    """Returns the parsed contents of /conf/home.json

    Args:
        logger (Logger): Logger instance

    Returns:
        dict: Configuration JSON
    """
    configfile = '/conf/home.json'
    logger.debug("Getting config from '{}'", configfile)
    try:
        with open(configfile, 'r') as f:
            config = json.load(f)
        for environmentName, environmentInfo in config.get("environments", {}).items():
            keycloakPassword = environmentInfo.get("password")
            if isinstance(keycloakPassword, str) and keycloakPassword.startswith("$env:"):
                environmentVariableName = keycloakPassword[5:]
                logger.trace("Getting KC password for env {} from variable '{}'", environmentName, environmentVariableName)
                environmentInfo["password"] = os.environ.get(environmentVariableName, "")
            elasticPassword = environmentInfo.get("elastic_configuration", {}).get("password", "")
            if isinstance(elasticPassword, str) and elasticPassword.startswith("$env:"):
                environmentVariableName = elasticPassword[5:]
                logger.trace("Getting Elastic password for env {} from variable '{}'", environmentName, environmentVariableName)
                environmentInfo["elastic_configuration"]["password"] = os.environ.get(environmentVariableName, "")
        return config
    except FileNotFoundError:
        logger.error("Config file '{}' not found.", configfile)
        return {}
    except json.JSONDecodeError:
        logger.error("Config file '{}' is not a valid JSON.", configfile)
        return {}


def getRealmTypes(logger: Logger, config: dict) -> list:
    """Returns the list of realm types in the configuration

    Args:
        logger (Logger): Logger instance
        config (dict): JSON configuration

    Returns:
        list: List of realm types
    """
    return list(config.get("realms", {}).keys())


def getRealms(logger: Logger, environment: str, config: dict) -> list:
    """Returns only the list of realms from the configuration

    Args:
        logger (Logger): Logger instance
        environment (str): Environment name
        config (dict): JSON configuration

    Returns:
        list: List of realms in the configuration
    """
    realmsList = []
    realmTypes = list(config.get("realms", {}).keys())
    for realmType in realmTypes:
        logger.trace("getRealms() processing realmType: {}", realmType)
        for workspace in getWorkspaces(logger=logger, realmType=realmType, environment=environment, config=config):
            logger.trace("getRealms() processing workspace: {}", workspace)
            realmName = getRealmName(logger=logger, realmType=realmType, environment=environment, workspace=workspace, config=config)
            realmsList.append(realmName)
    return realmsList


def getRealm(logger: Logger, environment: str, realmName: str, config: dict) -> dict:
    """Will fetch a realm from a given Environment using Keycloak's Admin API and return it

    Args:
        logger (Logger): Logger instance
        environment (str): Environment name
        realmName (str): Realm name
        config (dict): JSON configuration

    Returns:
        dict: Realm Object from the Keycloak API
    """
    kcAdmin = getKeycloakAdmin(logger=logger, environment=environment, realmName=realmName, config=config)
    if not kcAdmin:
        return []
    try:
        realm = kcAdmin.get_realm(realmName)
        return realm
    except Exception as e:
        logger.error("Error fetching realm for {}/{}: {}", environment, realmName, e)
        return []


def getDiscoveryUrl(logger: Logger, environment: str, realm: dict, config: dict) -> str:
    """Returns the OpenID Connect Discovery URL for a given environment and realm

    Args:
        logger (Logger): Logger instance
        environment (str): Environment name
        realm (dict): Realm Object from the Keycloak API
        config (dict): JSON configuration

    Returns:
        str: Discovery URL
    """
    baseUrl = realm.get("attributes", {}).get("frontendUrl", config.get("environments", {}).get(environment, {}).get("keycloak_url"))
    discoveryUrl = "{}/realms/{}/.well-known/openid-configuration".format(baseUrl, realm["realm"])
    logger.debug("Discovery URL: {}", discoveryUrl)
    return discoveryUrl



def getRealmName(logger: Logger, realmType: str, environment: str, workspace: str, config: dict) -> str:
    """Get realm name from its type, environment and workspace

    Args:
        logger (Logger): Logger instance
        realmType (str): Realm type
        environment (str): Environment
        workspace (str): Workspace
        config (dict): JSON configuration

    Returns:
        str: Realm name
    """
    realmName = config.get("realms", {}).get(realmType, {}).get(environment, {}).get(workspace, {}).get("realm_name", realmType)
    logger.trace("getRealmName() processing realmType: {}, environment: {}, workspace: {}, realmName: {}", realmType, environment, workspace, realmName)
    return realmName


def getEnvironments(logger: Logger, config: dict) -> list:
    """Returns the list of environments in the configuration

    Args:
        logger (Logger): Logger instance
        config (dict): JSON configuration

    Returns:
        list: List of environments in the configuration
    """
    return list(config.get("environments", {}).keys())



def getWorkspaces(logger: Logger, realmType: str, environment: str, config: dict) -> list:
    """Returns workspaces for a realmType and environment

    Args:
        logger (Logger): Logger instance
        realmType (str): Realm type
        environment (str): Environment
        config (dict): JSON configuration

    Returns:
        list: List of the given realm's workspaces from the configuration
    """
    logger.trace("getWorkspaces() processing realmType: {}, environment: {}", realmType, environment)
    return list(config.get("realms", {}).get(realmType).get(environment, {}).keys())


def getElastic(logger: Logger, environment: str, config: dict):
    """Returns ElasticSearch connection

    Args:
        logger (Logger): Logger instance
        environment (str): Environment
        config (dict): JSON configuration

    Returns:
        Elasticsearch: ElasticSeach connection
    """
    urls = config.get("environments", {}).get(environment, {}).get("elastic_configuration", {}).get("urls", [])
    if urls:
        username = config.get("environments", {}).get(environment, {}).get("elastic_configuration", {}).get("username", "")
        password = config.get("environments", {}).get(environment, {}).get("elastic_configuration", {}).get("password", "")
        if username and password:
            logger.debug("Connecting to urls: {}, username: {}", urls, username)
            return Elasticsearch(urls, http_auth=(username, password))
        else:
            logger.debug("Connecting to urls: {}", urls)
            return Elasticsearch(urls)
    else:
        logger.debug("No Elastic URLs provided.")
        return None


def getKeycloakAdmin(logger: Logger, environment: str, realmName: str, config: dict) -> SherpaKeycloakAdmin:
    """Creates an instance of SherpaKeycloakAdmin
    See in [sherpa-py-keycloak](https://github.com/Identicum/sherpa-py-keycloak/blob/main/sherpa/keycloak/keycloak_lib.py)

    Args:
        environment (str): Environment name
        realmName (str): Realm name
        config (dict): JSON configuration

    Returns:
        SherpaKeycloakAdmin: SherpaKeycloakAdmin instance
    """
    properties = Properties("/local.properties", "/local.properties")
    kcAdmin = SherpaKeycloakAdmin(
            logger=logger, 
            properties=properties, 
            server_url=config.get("environments", {}).get(environment, {}).get("keycloak_url", ""), 
            username=config.get("environments", {}).get(environment, {}).get("username", ""), 
            password=config.get("environments", {}).get(environment, {}).get("password", ""), 
            user_realm_name="master",
            realm_name=realmName, 
            verify=False
        )
    return kcAdmin


def getClients(logger: Logger, environment: str, realmName: str, config: dict) -> list:
    """Will fetch a given realm in a given environment's client list from the Keycloak API and return it.

    Args:
        environment (str): Environment name
        realmName (str): Realm name
        config (dict): JSON configuration

    Returns:
        list: List of clients in the realm
    """
    kcAdmin = getKeycloakAdmin(logger=logger, environment=environment, realmName=realmName, config=config)
    if not kcAdmin:
        logger.error("Error fetching clients for {}/{}. No kcAdmin.", environment, realmName)
        return []
    try:
        clients = kcAdmin.get_clients()
        return clients
    except Exception as e:
        logger.error("Error fetching clients for {}/{}: {}", environment, realmName, e)
        return []


def getClientLastActivity(logger: Logger, elastic: Elasticsearch, realmName: str, client_id: str) -> list:
    """List Clients including last activity.

    Args:
        logger (Logger): Logger instance
        elastic (Elasticsearch): ElasticSearch connection
        realmName (str): Realm name
        client_id (str): client_id

    Returns:
        str: Date of last activity of the client, or "No activity"
    """
    activityQueryResponse = elastic.search(index="", body={
        "size": 1,
        "query": {
            "bool": {
                "must": [
                    {"match": {"idp.realm": realmName}},
                    {"match": {"idp.client_id": client_id}}
                ]
            }
        },
    })
    logger.debug("activityQueryResponse: {}", activityQueryResponse)
    hits_list = activityQueryResponse.get("hits", {}).get("hits", [])
    if hits_list:
        timestamp = hits_list[0].get("_source", {}).get("@timestamp", "")
        dt_utc = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        dt_local = dt_utc.astimezone()
        return dt_local.strftime("%Y-%m-%d %H:%M")
    else:
        return "No activity"


def getNormalizedClient(logger: Logger, environment: str, realmName: str, client_id: str, config: dict) -> dict:
    """Will fetch a Client from a given Realm in a given Environment using the provided `client_id` in the Keycloak API, then format the object so as to standardize the output between different client types

    Args:
        logger (Logger): Logger instance
        environment (str): Environment name
        realmName (str): Realm name
        client_id (str): Client ID
        config (dict): JSON configuration

    Returns:
        dict: Resulting Normalized Client object
    """
    kcAdmin = getKeycloakAdmin(logger=logger, environment=environment, realmName=realmName, config=config)
    if not kcAdmin:
        return {}
    try:
        clientKeycloakId = kcAdmin.get_client_id(client_id)
        client = kcAdmin.get_client(clientKeycloakId)
        realm = kcAdmin.get_realm(realmName)
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
        response["tag"] = getClientTag(logger=logger, description=client_description, client_id=client["clientId"], client_type=response["type"])
        response["owner_email"] = splitDescription(logger=logger, description=client_description, position=1, defaultValue="")
        response["description"] = splitDescription(logger=logger, description=client_description, position=2, defaultValue=client_description)

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
                response["client_secret"] = client.get("secret", "")
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
        response["default_scopes"] = client.get("defaultClientScopes", [])
        response["optional_scopes"] = client.get("optionalClientScopes", [])
        response["protocol_mappers"] = client.get("protocolMappers", [])

        logger.trace("Returning response: {}", response)
        return response
    except Exception as e:
        logger.error("Error fetching client for {}/{}/{}: {}", environment, realmName, client_id, e)
        return {}


def splitDescription(logger: Logger, description: str, position: int, defaultValue: str) -> str:
    """Extracts whichever detail it finds in the provided `position` inside of a client `description` (also provided). Will return the provided default value if it finds nothing.

    Args:
        logger (Logger): Logger instance
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


def getClientTag(logger: Logger, description: str, client_id: str, client_type: str) -> str:
    """Extracts a client tag from a provided description (Custom Syntax) \n
    Will automatically filter Native keycloak client tags using the provided client_id and mark unsupported tags as [TAG_INVALID]

    Args:
        logger (Logger): Logger instance
        description (str): _description_
        client_id (str): _description_
        client_type (str): realm / openid-connect / saml

    Returns:
        str: Client Tag - Example: [SPA_PUBLIC]
    """
    native_clients = [ "account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console" ]
    if client_type=="realm" or client_id in native_clients:
        return "[KEYCLOAK_NATIVE]"

    valid_client_types = ["[SPA_NGINX]", "[MOBILE]", "[WEB_BACKEND]", "[CLIENT_CREDENTIALS]", "[SPA_PUBLIC]", "[ROPC]", "[IDP_INTERNAL]", "[SAML]"]
    tag = splitDescription(logger=logger, description=description, position=0, defaultValue="")
    if tag == "":
        return "[TAG_MISSING]"
    if tag not in valid_client_types:
        return "[TAG_INVALID]"           
    return tag


def getVarFiles(logger: Logger, environment: str, config: dict) -> list:
    """Returns the list of var_file paths related to the provided environment

    Args:
        logger (Logger): Logger instance
        environment (str): Environment name
        config (dict): JSON configuration

    Returns:
        list: List of var_file paths related to the environment
    """
    return list(config.get("environments", {}).get(environment, {}).get("var_files", []))


def smtpSend(logger: Logger, host, port, subject, body, from_addr, to_addr, cc_addr=None):
    """
    Send SMTP email

    """
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    recipients = [to_addr]
    if cc_addr is not None:
        msg['Cc'] = cc_addr
        recipients.append(cc_addr)
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))
    try:
        with smtplib.SMTP(host, port) as server:
            server.sendmail(from_addr, recipients, msg.as_string())
        logger.debug("Email sent.")
    except Exception as e:
        logger.error("Error sending email: {}", e)
