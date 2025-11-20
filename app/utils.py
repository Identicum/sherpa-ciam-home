from datetime import datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from elasticsearch import Elasticsearch
import json
import mimetypes
import os
from sherpa.utils.basics import Properties
from sherpa.utils.basics import Logger
from sherpa.keycloak.keycloak_lib import SherpaKeycloakAdmin
import smtplib
import uuid
import requests


def load_messages():
    """
    Load messages from default.messages, optionally overridden by custom.messages
    :return: dict of messages
    """
    def read_properties(path):
        props = {}
        if path and os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        if '=' in line:
                            key, value = line.split('=', 1)
                            props[key.strip()] = value.strip()
            except Exception:
                pass
        return props

    default_path = os.path.join(os.path.dirname(__file__), 'default.messages')
    override_path = '/conf/custom.messages'
    messages = read_properties(default_path)
    override_messages = read_properties(override_path)
    messages.update(override_messages)
    return messages


def getLocalDatetime() -> str:
    """Return the current local date/time as an ISO string with timezone offset."""
    localNow = datetime.now().astimezone()
    return localNow.strftime("%Y-%m-%d %H:%M:%S")


def getConfig(logger) -> dict:
    """Returns the parsed contents of /conf/home.json

    Args:
        logger instance

    Returns:
        dict: Configuration JSON
    """
    configfile = '/conf/home.json'
    logger.debug("Getting config from '{}'", configfile)
    try:
        with open(configfile, 'r') as f:
            config = json.load(f)
        for environmentName, environmentInfo in config.get("environments", {}).items():
            for key in ["keycloak_password", "elastic_password"]:
                json_value = environmentInfo.get(key, "")
                if isinstance(json_value, str) and json_value.startswith("$env:"):
                    environmentVariableName = json_value[5:]
                    logger.trace("Getting {} for env {} from variable '{}'", key, environmentName, environmentVariableName)
                    environmentInfo[key] = os.environ.get(environmentVariableName, "")
        logger.trace("Config loaded: {}", config)
        return config
    except FileNotFoundError:
        logger.error("Config file '{}' not found.", configfile)
        return {}
    except json.JSONDecodeError:
        logger.error("Config file '{}' is not a valid JSON.", configfile)
        return {}


def getRealmTypes(logger, config: dict) -> list:
    """Returns the list of realm types in the configuration

    Args:
        logger instance
        config (dict): JSON configuration

    Returns:
        list: List of realm types
    """
    return list(config.get("realms", {}).keys())


def getRealms(logger, environment: str, config: dict) -> list:
    """Returns only the list of realms from the configuration

    Args:
        logger instance
        environment (str): Environment name
        config (dict): JSON configuration

    Returns:
        list: List of realms in the configuration
    """
    realmsList = []
    for realmType in getRealmTypes(logger=logger, config=config):
        logger.trace("getRealms() processing realmType: {}", realmType)
        for workspace in getRealmWorkspaces(logger=logger, realmType=realmType, environment=environment, config=config):
            logger.trace("getRealms() processing workspace: {}", workspace)
            realmName = getRealmName(logger=logger, realmType=realmType, environment=environment, workspace=workspace, config=config)
            realmsList.append(realmName)
    return realmsList


def getRealm(logger, environment: str, realmName: str, config: dict) -> dict:
    """Will fetch a realm from a given Environment using Keycloak's Admin API and return it

    Args:
        logger: Logger instance
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


def getDiscoveryUrl(logger, environment: str, realm: dict, config: dict) -> str:
    """Returns the OpenID Connect Discovery URL for a given environment and realm

    Args:
        logger: Logger instance
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


def getRealmName(logger, realmType: str, environment: str, workspace: str, config: dict) -> str:
    """Get realm name from its type, environment and workspace

    Args:
        logger: Logger instance
        realmType (str): Realm type
        environment (str): Environment
        workspace (str): Workspace
        config (dict): JSON configuration

    Returns:
        str: Realm name
    """
    realmName = config.get("realms").get(realmType).get("environments").get(environment).get(workspace).get("realm_name", realmType)
    logger.trace("getRealmName({}, {}, {}) returning: {}", realmType, environment, workspace, realmName)
    return realmName


def getEnvironments(logger, config: dict) -> list:
    """Returns the list of environments in the configuration

    Args:
        logger: Logger instance
        config (dict): JSON configuration

    Returns:
        list: List of environments in the configuration
    """
    return list(config.get("environments", {}).keys())


def getRealmWorkspaces(logger, realmType: str, environment: str, config: dict) -> list:
    """Returns workspaces for a realmType and environment

    Args:
        logger: Logger instance
        realmType (str): Realm type
        environment (str): Environment
        config (dict): JSON configuration

    Returns:
        list: List of the given realm's workspaces from the configuration
    """
    logger.trace("Processing realmType: {}, environment: {}", realmType, environment)
    return list(config.get("realms").get(realmType).get("environments").get(environment, {}).keys())


def getElastic(logger, environment: str, config: dict):
    """Returns ElasticSearch connection

    Args:
        logger: Logger instance
        environment (str): Environment
        config (dict): JSON configuration

    Returns:
        Elasticsearch: ElasticSeach connection
    """
    urls = config.get("environments", {}).get(environment, {}).get("elastic_urls", [])
    if urls:
        username = config.get("environments", {}).get(environment, {}).get("elastic_username", "")
        password = config.get("environments", {}).get(environment, {}).get("elastic_password", "")
        if username and password:
            logger.debug("Connecting to urls: {}, username: {}", urls, username)
            return Elasticsearch(urls, http_auth=(username, password))
        else:
            logger.debug("Connecting to urls: {}", urls)
            return Elasticsearch(urls)
    else:
        logger.debug("No Elastic URLs provided.")
        return None


def getKibanaUrl(logger, environment: str, config: dict, realmName: str, client_id: str) -> str:
    """Returns Kibana URL connection

    Args:
        logger: Logger instance
        environment (str): Environment
        config (dict): JSON configuration
        realmName (str): Realm name
        client_id (str): client_id

    Returns:
        str: Kibana URL
    """
    base_url = config.get("environments", {}).get(environment, {}).get("kibana_url", "")
    if base_url:
        kibana_index = config.get("environments", {}).get(environment, {}).get("kibana_index")
        kibana_url = f"{base_url}/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-4w,to:now))&_a=(columns:!(),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'{kibana_index}',key:idp.client_id,negate:!f,params:(query:'{client_id}'),type:phrase),query:(match_phrase:(idp.client_id:'{client_id}'))),('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'{kibana_index}',key:idp.realm,negate:!f,params:(query:'{realmName}'),type:phrase),query:(match_phrase:(idp.realm:'{realmName}')))),index:'{kibana_index}',interval:auto,query:(language:kuery,query:''),sort:!(!('@timestamp',desc)))"
        logger.trace("Kibana URL: {}", kibana_url)
        return kibana_url
    else:
        logger.debug("No Kibana URL provided.")
        return None


def getKeycloakAdmin(logger, environment: str, realmName: str, config: dict) -> SherpaKeycloakAdmin:
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
            username=config.get("environments", {}).get(environment, {}).get("keycloak_username", ""), 
            password=config.get("environments", {}).get(environment, {}).get("keycloak_password", ""), 
            user_realm_name="master",
            realm_name=realmName, 
            verify=False
        )
    return kcAdmin


def getClients(logger, environment: str, realmName: str, config: dict) -> list:
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


def getClientLastActivity(logger, elastic: Elasticsearch, realmName: str, client_id: str) -> list:
    """List Clients including last activity.

    Args:
        logger: Logger instance
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


def getNormalizedClient(logger, environment: str, realmName: str, client_id: str, config: dict) -> dict:
    """Will fetch a Client from a given Realm in a given Environment using the provided `client_id` in the Keycloak API, then format the object so as to standardize the output between different client types

    Args:
        logger: Logger instance
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

            response["access_token_lifespan"] = client["attributes"].get("access.token.lifespan", "(inherit)")
            response["effective_access_token_lifespan"] = client["attributes"].get("access.token.lifespan", realm.get("accessTokenLifespan", 0))
            response["realm_access_token_lifespan"] = realm["accessTokenLifespan"]

            response["client_session_idle"] = client["attributes"].get("client.session.idle.timeout", "(inherit)")

            response["realm_client_session_idle"] = realm["clientSessionIdleTimeout"]
            if response["realm_client_session_idle"] == 0:
                effective_realm_client_session_idle = realm["ssoSessionIdleTimeout"]
            else:
                effective_realm_client_session_idle = response["realm_client_session_idle"]
            response["effective_client_session_idle"] = int(client["attributes"].get("client.session.idle.timeout", effective_realm_client_session_idle))

            response["client_session_max"] = client["attributes"].get("client.session.max.lifespan", "(inherit)")
            response["effective_client_session_max"] = client["attributes"].get("client.session.max.lifespan", realm.get("clientSessionMaxLifespan", 0))
            response["realm_client_session_max"] = realm.get("clientSessionMaxLifespan", "")

            response["client_offline_session_idle"] = client["attributes"].get("client.offline.session.idle.timeout", "(inherit)")
            # response["realm_client_offline_session_idle"] = realm["offlineSessionIdleTimeout"]
            response["realm_offline_session_idle"] = realm["offlineSessionIdleTimeout"]
            response["effective_client_offline_session_idle"] = client["attributes"].get("client.offline.session.idle.timeout", response["realm_offline_session_idle"])
            response["realm_offline_session_max_lifespan_enabled"] = realm["offlineSessionMaxLifespanEnabled"]
            
            response["client_offline_session_max"] = client["attributes"].get("client.offline.session.max.lifespan", "(inherit)")
            response["effective_client_offline_session_max"] = client["attributes"].get("client.offline.session.max.lifespan", realm.get("offlineSessionMaxLifespan", 0))
            if response["realm_offline_session_max_lifespan_enabled"]:
                response["realm_offline_session_max"] = realm.get("offlineSessionMaxLifespan", "")
            else:
                response["realm_offline_session_max"] = ""


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

        activity_url = getKibanaUrl(logger=logger, environment=environment, config=config, realmName=realmName, client_id=response["client_id"])
        if activity_url:
            response["activity_url"] = activity_url

        logger.trace("Returning response: {}", response)
        return response
    except Exception as e:
        logger.error("Error fetching client for {}/{}/{}: {}", environment, realmName, client_id, e)
        return {}


def splitDescription(logger, description: str, position: int, defaultValue: str) -> str:
    """Extracts whichever detail it finds in the provided `position` inside of a client `description` (also provided). Will return the provided default value if it finds nothing.

    Args:
        logger: Logger instance
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


def getClientTag(logger, description: str, client_id: str, client_type: str) -> str:
    """Extracts a client tag from a provided description (Custom Syntax) \n
    Will automatically filter Native keycloak client tags using the provided client_id and mark unsupported tags as [TAG_INVALID]

    Args:
        logger: Logger instance
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


def getVarFiles(logger, environment: str, config: dict) -> list:
    """Returns the list of var_file paths related to the provided environment

    Args:
        logger: Logger instance
        environment (str): Environment name
        config (dict): JSON configuration

    Returns:
        list: List of var_file paths related to the environment
    """
    return list(config.get("environments", {}).get(environment, {}).get("var_files", []))


def smtpSend(logger, subject, body, to_addr, cc_addr=None, attached_files=[]):
    """
    Send SMTP email with optional file attachments.
    """
    host = os.environ.get("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT"))
    from_addr = os.environ.get("SMTP_FROM_ADDR")
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    recipients = [to_addr]
    if cc_addr is not None:
        msg['Cc'] = cc_addr
        recipients.append(cc_addr)
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))

    # Attach files if provided
    for file_path in attached_files:
        try:
            ctype, encoding = mimetypes.guess_type(file_path)
            if ctype is None or encoding is not None:
                ctype = 'application/octet-stream'
            maintype, subtype = ctype.split('/', 1)
            with open(file_path, 'rb') as f:
                part = MIMEBase(maintype, subtype)
                part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(file_path)}"')
                msg.attach(part)
        except Exception as e:
            logger.error("Error attaching file '{}': {}", file_path, e)
    try:
        with smtplib.SMTP(host, port) as server:
            server.sendmail(from_addr, recipients, msg.as_string())
        logger.debug("Email sent.")
    except Exception as e:
        logger.error("Error sending email: {}", e)


def formatUrl(logger, url: str, rootUrl: str) -> str:
    """
    Format URL adding rootUrl if necessary.

    :param url (str): URL to format.
    :param rootUrl (str): URL base to prefix, if url is relative.
    :return str: URL formateada.
    """
    logger.trace("Processing URL: {}, rootUrl: {}", url, rootUrl)
    if url == None:
        return ""
    if url.startswith("http"):
        return url
    if url in [ "*", "+" ]:
        return "*"
    return f"{rootUrl}{url}"


def getUserSessions(environment: str, realm: str, identifier: str, config: dict) -> dict:
    """Retrieves all of a user's sessions in a given environment and realm

    Args:
        environment (str)
        realm (str)
        identifier (str): May be a username or user's UUID
        config (dict): Inherited config for the Keycloak Admin

    Returns:
        dict: _description_
    """
    # Validate identifier integrity
    if not identifier:
        return {
            "success": False,
            "message": "Username or UUID not provided."
        }
    logger.debug("Identifier is valid")
    
    # Define identifier type
    id_type = ""
    try:
        uuid.UUID(identifier)
        id_type = "UUID"
    except ValueError:
        id_type = "username"

    logger.debug("ID Type {}", id_type)
    
    kc_admin = getKeycloakAdmin(
        logger=logger,
        environment=environment,
        realmName=realm,
        config=config
    )
    
    if id_type == "username":
        identifier = kc_admin.get_user_id(identifier)
    logger.debug("ID is {}", identifier)
    
    try:
        sessions = kc_admin.get_sessions(identifier)
        for session in sessions:
            session["start"] = datetime.fromtimestamp(session["start"] / 1000).strftime("%Y-%m-%d %H:%M")
            session["lastAccess"] = datetime.fromtimestamp(session["lastAccess"] / 1000).strftime("%Y-%m-%d %H:%M")
        logger.trace("Online Sessions: {}", sessions)

        for client in kc_admin.get_clients():
            for session in kc_admin.sherpa_get_user_client_offlinesessions(user_id=identifier, client_id=client["clientId"]):
                if "start" in session:
                    session["start"] = datetime.fromtimestamp(session["start"] / 1000).strftime("%Y-%m-%d %H:%M")
                if "lastAccess" in session:
                    session["lastAccess"] = datetime.fromtimestamp(session["lastAccess"] / 1000).strftime("%Y-%m-%d %H:%M")
                sessions.append({
                    **session,
                    "is_offline_session": True,
                    "clientId": client["clientId"]
                })
        return {
            "sessions": sessions,
            "success": True,
            "message": "OK"
        }
    except Exception as e:
        logger.error(e)
        return {
            "sessions": None,
            "success": False,
            "message": e
        }


def _delete_all_offline_sessions(kc_admin, user_id: str, realm: str, config: dict, environment: str, username: str = None):
    """Helper function to delete all offline sessions for a user across all clients and realms
    
    Args:
        kc_admin: SherpaKeycloakAdmin instance (for the current realm)
        user_id: User UUID in the current realm
        realm: Realm name
        config: Configuration dict
        environment: Environment name
        username: Optional username to find user in other realms
    """
    server_url = config.get("environments", {}).get(environment, {}).get("keycloak_url", "")
    normalized_server_url = server_url.rstrip('/')
    access_token = _get_admin_access_token(server_url)
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    
    realms_to_check = [realm]
    if realm != "master":
        realms_to_check.append("master")
    
    for target_realm in realms_to_check:
        try:
            target_user_id = user_id
            target_kc_admin = kc_admin
            
            if target_realm != realm:
                target_kc_admin = getKeycloakAdmin(logger=logger, environment=environment, realmName=target_realm, config=config)
                if username:
                    try:
                        target_user_id = target_kc_admin.get_user_id(username)
                        if target_user_id is None:
                            logger.debug("User {} not found in realm {} (get_user_id returned None)", username, target_realm)
                            continue
                        logger.debug("Found user {} in realm {} with ID {}", username, target_realm, target_user_id)
                    except Exception as e:
                        logger.debug("User {} not found in realm {}: {}", username, target_realm, e)
                        continue
                else:
                    logger.debug("No username provided, skipping realm {}", target_realm)
                    continue
            
            if not target_user_id:
                logger.debug("No valid user_id for realm {}, skipping", target_realm)
                continue
            
            clients = target_kc_admin.get_clients()
            deleted_count = 0
            for client in clients:
                client_id = client.get("clientId")
                if client_id:
                    try:
                        offline_sessions = target_kc_admin.sherpa_get_user_client_offlinesessions(user_id=target_user_id, client_id=client_id)
                        for offline_session in offline_sessions:
                            try:
                                target_kc_admin.delete_session(offline_session.get('id'), isOffline=True)
                                deleted_count += 1
                                logger.debug("Deleted offline session {} for client {} in realm {}", offline_session.get('id'), client_id, target_realm)
                            except Exception as e:
                                logger.debug("Error deleting offline session {}: {}", offline_session.get('id'), e)
                                try:
                                    client_uuid = target_kc_admin.get_client_id(client_id)
                                    delete_url = f"{normalized_server_url}/admin/realms/{target_realm}/users/{target_user_id}/offline-sessions/{client_uuid}"
                                    delete_response = requests.delete(delete_url, headers=headers, verify=False)
                                    if delete_response.status_code in [200, 204]:
                                        deleted_count += len(offline_sessions)
                                        logger.debug("Deleted all {} offline sessions for client {} in realm {} using direct endpoint", len(offline_sessions), client_id, target_realm)
                                        break
                                except Exception as e2:
                                    logger.warning("Both methods failed for client {} in realm {}: {}", client_id, target_realm, e2)
                    except Exception as e:
                        logger.warning("Error processing offline sessions for client {} in realm {}: {}", client_id, target_realm, e)
            
            if deleted_count > 0:
                logger.info("Deleted {} offline sessions in realm {}", deleted_count, target_realm)
        except Exception as e:
            logger.warning("Error deleting offline sessions in realm {}: {}", target_realm, e)


def killSession(environment: str, realm: str, identifier: str, session_id: str, config: dict, is_offline_session: bool = False, client_id: str = None) -> dict:
    """Kills a specific user session in a given environment and realm

    Args:
        environment (str)
        realm (str)
        identifier (str): May be a username or user's UUID
        session_id (str): Session ID to kill
        config (dict): Inherited config for the Keycloak Admin
        is_offline_session (bool): Whether this is an offline session
        client_id (str): Client ID for offline sessions (required for offline sessions)

    Returns:
        dict: Result with success status and message
    """
    if not identifier or not session_id:
        return {"success": False, "message": "Username/UUID or session ID not provided."}
    
    kc_admin = getKeycloakAdmin(logger=logger, environment=environment, realmName=realm, config=config)
    
    username = None
    try:
        uuid.UUID(identifier)
        try:
            username = kc_admin.get_user(identifier).get("username")
        except Exception:
            pass
    except ValueError:
        username = identifier
        identifier = kc_admin.get_user_id(identifier)
    
    try:
        server_url = config.get("environments", {}).get(environment, {}).get("keycloak_url", "")
        access_token = _get_admin_access_token(server_url)
        headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        
        if is_offline_session:
            return _kill_offline_session(kc_admin, identifier, session_id, client_id, realm, server_url, headers)
        else:
            return _kill_online_session(kc_admin, identifier, session_id, realm, server_url, headers, config, environment, username)
    except requests.exceptions.HTTPError as e:
        logger.error("HTTP error killing session {}: {}", session_id, e)
        return {"success": False, "message": f"HTTP Error: {str(e)}"}
    except Exception as e:
        logger.error("Error killing session {}: {}", session_id, e)
        return {"success": False, "message": str(e)}


def _get_admin_access_token(server_url: str) -> str:
    """Get admin access token for Keycloak Admin API"""
    token_url = f"{server_url}/realms/master/protocol/openid-connect/token"
    token_response = requests.post(token_url, data={
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": "admin",
        "password": "admin"
    }, verify=False)
    token_response.raise_for_status()
    return token_response.json()["access_token"]


def _kill_offline_session(kc_admin, user_id: str, session_id: str, client_id: str, realm: str, server_url: str, headers: dict) -> dict:
    """Kill a specific offline session (and online session with same ID)"""
    if not client_id:
        return {"success": False, "message": "Client ID is required for offline sessions"}
    
    normalized_server_url = server_url.rstrip('/')
    
    try:
        online_delete_url = f"{normalized_server_url}/admin/realms/{realm}/sessions/{session_id}"
        online_response = requests.delete(online_delete_url, headers=headers, verify=False)
        if online_response.status_code in [200, 204]:
            logger.debug("Deleted online session {} (same ID as offline)", session_id)
    except Exception as e:
        logger.debug("Online session {} not found or already deleted: {}", session_id, e)
    
    try:
        kc_admin.delete_session(session_id, isOffline=True)
        logger.debug("Successfully deleted offline session {} for client {} using delete_session", session_id, client_id)
        return {"success": True, "message": "Offline session killed successfully"}
    except Exception as e:
        logger.debug("delete_session failed, trying direct endpoint: {}", e)
        try:
            client_uuid = kc_admin.get_client_id(client_id)
            offline_delete_url = f"{normalized_server_url}/admin/realms/{realm}/users/{user_id}/offline-sessions/{client_uuid}"
            offline_response = requests.delete(offline_delete_url, headers=headers, verify=False)
            if offline_response.status_code in [200, 204]:
                logger.debug("Successfully deleted offline session {} for client {} using direct endpoint", session_id, client_id)
                return {"success": True, "message": "Offline session killed successfully"}
            offline_response.raise_for_status()
        except Exception as e2:
            logger.error("Both methods failed to delete offline session {}: {}", session_id, e2)
            return {"success": False, "message": f"Failed to delete offline session: {str(e2)}"}


def _kill_online_session(kc_admin, user_id: str, session_id: str, realm: str, server_url: str, headers: dict, config: dict, environment: str, username: str) -> dict:
    """Kill a specific online session (and offline sessions with same ID)"""
    normalized_server_url = server_url.rstrip('/')
    delete_url = f"{normalized_server_url}/admin/realms/{realm}/sessions/{session_id}"
    delete_response = requests.delete(delete_url, headers=headers, verify=False)
    
    if delete_response.status_code in [403, 404]:
        logout_url = f"{normalized_server_url}/admin/realms/{realm}/users/{user_id}/logout"
        requests.post(logout_url, headers=headers, verify=False).raise_for_status()
        _delete_all_offline_sessions(kc_admin, user_id, realm, config, environment, username)
        return {"success": True, "message": "All user sessions closed successfully"}
    
    delete_response.raise_for_status()
    
    try:
        clients = kc_admin.get_clients()
        for client in clients:
            client_id = client.get("clientId")
            if client_id:
                try:
                    offline_sessions = kc_admin.sherpa_get_user_client_offlinesessions(user_id=user_id, client_id=client_id)
                    for offline_session in offline_sessions:
                        if offline_session.get('id') == session_id:
                            try:
                                kc_admin.delete_session(session_id, isOffline=True)
                                logger.debug("Deleted offline session {} for client {} (same ID as online)", session_id, client_id)
                                break
                            except Exception as e:
                                logger.debug("Error deleting offline session {} for client {}: {}", session_id, client_id, e)
                except Exception as e:
                    logger.debug("Error checking/deleting offline session for client {}: {}", client_id, e)
    except Exception as e:
        logger.debug("Error deleting offline sessions with ID {}: {}", session_id, e)
    
    logger.debug("Successfully deleted online session {} and related offline sessions", session_id)
    return {"success": True, "message": "Session killed successfully"}


def killAllSessions(environment: str, realm: str, identifier: str, config: dict) -> dict:
    """Kills all user sessions (online and offline) in a given environment and realm

    Args:
        environment (str)
        realm (str)
        identifier (str): May be a username or user's UUID
        config (dict): Inherited config for the Keycloak Admin

    Returns:
        dict: Result with success status and message
    """
    if not identifier:
        return {"success": False, "message": "Username/UUID not provided."}
    
    kc_admin = getKeycloakAdmin(logger=logger, environment=environment, realmName=realm, config=config)
    
    username = None
    try:
        uuid.UUID(identifier)
        try:
            username = kc_admin.get_user(identifier).get("username")
        except Exception:
            pass
    except ValueError:
        username = identifier
        identifier = kc_admin.get_user_id(identifier)
    
    try:
        server_url = config.get("environments", {}).get(environment, {}).get("keycloak_url", "")
        access_token = _get_admin_access_token(server_url)
        headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        
        logout_url = f"{server_url}/admin/realms/{realm}/users/{identifier}/logout"
        logout_response = requests.post(logout_url, headers=headers, verify=False)
        logout_response.raise_for_status()
        
        _delete_all_offline_sessions(kc_admin, identifier, realm, config, environment, username)
        logger.debug("Successfully deleted all offline sessions for user {}", identifier)
        
        return {"success": True, "message": "All user sessions (online and offline) closed successfully"}
    except requests.exceptions.HTTPError as e:
        logger.error("HTTP error killing all sessions for user {}: {}", identifier, e)
        return {"success": False, "message": f"HTTP Error: {str(e)}"}
    except Exception as e:
        logger.error("Error killing all sessions for user {}: {}", identifier, e)
        return {"success": False, "message": str(e)}


# Create a single logger instance
logger = Logger(
    "sherpa-ciam-home", 
    os.environ.get("LOG_LEVEL"), 
    "/tmp/python-flask.log"
)

# Create a single config instance
config = getConfig(logger=logger)
