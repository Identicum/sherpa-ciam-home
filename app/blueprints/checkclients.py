from flask import Blueprint, render_template
from utils import *

checkclients_bp = Blueprint('checkclients', __name__)

logger = Logger(os.path.basename(__file__), os.environ.get("LOG_LEVEL"), "/tmp/python-flask.log")

@checkclients_bp.route('/checkclients/<env>', methods=["GET"])
def checkclientsEnv(env):
    warns = getEnvWarns(env)
    logger.debug("checkclientsEnv({}). warns: {}", env, warns)
    return render_template('checkclients.html', realms=getRealms(logger), environments=getEnvironments(logger), env=env, warns=warns, realmName="All Realms")


@checkclients_bp.route('/checkclients/<env>/<realmName>', methods=["GET"])
def checkclientsEnvRealm(env, realmName):
    warns = getRealmWarns(env, realmName)
    logger.debug("checkclientsEnvRealm({}). warns: {}", env, warns)
    return render_template('checkclients.html', realms=getRealms(logger), environments=getEnvironments(logger), env=env, warns=warns, realmName=realmName)


def getEnvWarns(env):
    envWarns = []
    for realmName in getRealms(logger):
        realmWarns = getRealmWarns(env, realmName)
        for realmWarn in realmWarns:
            envWarns.append(realmWarn)
    return envWarns


def getRealmWarns(env, realmName):
    realmWarns = []
    for client in getClients(env, realmName):
        normalized_client = getClient(env, realmName, client["clientId"])
        clientWarns = getClientWarns(env, realmName, normalized_client)
        for clientWarn in clientWarns:
            logger.trace("Adding client warning: {}", clientWarn)
            realmWarns.append(clientWarn)
            logger.trace("Realm warns: {}", realmWarns)
    logger.trace("getRealmWarns({}, {}). response: {}", env, realmName, realmWarns)
    return realmWarns


def getClientWarns(env, realmName, client):
    logger.trace("getClientWarns({}, {}, {})", env, realmName, client.get("name"))

    if client["enabled"] is False:
        logger.debug("Client is disabled, no warnings will be generated.")
        return []

    # TAG
    match client["tag"]:
        case "[KEYCLOAK_NATIVE]":
            logger.debug("Native client, do nothing.")
            return []
        case "[TAG_MISSING]":
            return [getWarn(client, "WARN", "Client has no tag.")]
        case "[TAG_INVALID]":
            return [getWarn(client, "WARN", "Client tag is invalid: " + client["tag"])]

    clientWarns = []

    for warn in checkOwnerEmail(client):
        clientWarns.append(warn)

    for warn in checkAccessTokenLifespan(client):
        clientWarns.append(warn)

    for warn in checkRedirectUrls(client, env):
        clientWarns.append(warn)

    for warn in checkPostLogoutRedirectUrls(client, env):
        clientWarns.append(warn)

    for warn in checkWebOrigins(client):
        clientWarns.append(warn)

    for warn in checkFrontChannelLogout(client):
        clientWarns.append(warn)

    for warn in checkAccessType(client):
        clientWarns.append(warn)

    for warn in checkGrants(client):
        clientWarns.append(warn)

    realm = getRealm(env, realmName)
    for warn in checkSessionTimeout(client, realm):
        clientWarns.append(warn)

    logger.trace("getClientWarns response. client_name: {}, response: {}", client.get("client_name"), clientWarns)
    return clientWarns


def getWarn(client, level, issue_description):
    """
    Returns a warning dictionary for a client.
    
    :param client: Client object
    :param level: Warning level (e.g., "WARN", "ERROR")
    :param issue_description: Description of the issue
    :return: Dictionary with warning details
    """
    return dict(
        realmName=client["realm_name"],
        client_id=client["client_id"],
        tag=client["tag"],
        name=client["name"],
        description=client["description"],
        issue_level=level,
        issue_description=issue_description
    )


def checkOwnerEmail(client):
    logger.trace("checkOwnerEmail({})", client.get("client_id"))
    if client.get("owner_email") == "":
        return [getWarn(client, "WARN", "Client does not have an owner email.")]
    else:
        return []


def checkAccessTokenLifespan(client):
    logger.trace("checkAccessTokenLifespan({})", client.get("client_id"))
    access_token_lifespan = client["access_token_lifespan"]
    logger.trace("access_token_lifespan: {}, type: {}", access_token_lifespan, type(access_token_lifespan))
    if client["tag"] == "[CLIENT_CREDENTIALS]":
        if access_token_lifespan is None or isinstance(access_token_lifespan, str) or int(access_token_lifespan) < 1800:
            return [getWarn(client, "WARN", "This client should have an access token lifespan of (at least) 1800 seconds.")]
    return []


def checkRedirectUrls(client, env):
    redirect_urls = client["redirect_uris"]
    redirect_urls_count = len(redirect_urls)

    tag = client["tag"]
    if client["tag"] == "[IDP_INTERNAL]":
        return []
    if client["tag"] in [ "[CLIENT_CREDENTIALS]", "[ROPC]" ]:
        if redirect_urls_count > 0:
            issue_description = "This client should not have redirect_url values, but has {}.".format(redirect_urls_count)
            logger.debug("Returning issue '{}' for client '{}'", issue_description, client["client_id"])
            return [getWarn(client, "WARN", issue_description)]
        else:
            return []

    if redirect_urls_count == 0:
        return [getWarn(client, "WARN", "This client should have redirect_url values, but has none.")]

    absolute_redirect_urls_count = 0
    for redirect_url in redirect_urls:
        if not redirect_url.startswith("/"):
            absolute_redirect_urls_count += 1

    if absolute_redirect_urls_count > 1 and env != "dev":
        return [getWarn(client, "WARN", "This client should have up to 1 absolute redirect_url value, but has {}.".format(redirect_urls_count))]

    warns = []
    for redirect_url in redirect_urls:
        if tag == "[MOBILE]":
            if redirect_url.startswith("http"):
                return [getWarn(client, "WARN", "This client's redirect_url should not start with http.")]
        else:
            if (env != "dev") and (not redirect_url.startswith("http")) and (not redirect_url.startswith("/")):
                return [getWarn(client, "WARN", "This client's redirect_url should start with 'http' or '/'.")]
        if env != "dev":
            if "localhost" in redirect_url:
                return [getWarn(client, "WARN", "This client has a redirect_url that contains localhost.")]
            if "*" in redirect_url or "+" in redirect_url:
                return [getWarn(client, "WARN", "This client has a redirect_url that contains wildcard characters.")]
    return warns


def checkFrontChannelLogout(client):
    """
    Check front channel logout settings.

    :param client (dict): Normalized Client object.
    :return: List of warnings or empty list.
    """
    if client["frontchannel_logout_enabled"]:
        if client["frontchannel_logout_url"] == "":
            return [getWarn(client, "WARN", "This client has frontchannel_logout enabled but does not have a frontchannel_logout_url.")]
        else:
            return []
    else:
        if client["frontchannel_logout_url"] == "":
            return []
        else:
            return [getWarn(client, "WARN", "This client has frontchannel_logout disabled but has a frontchannel_logout_url.")]


def checkAccessType(client):
    """
    Verify access type, PKCE, etc.

    :param client (dict): Normalized Client object.
    :return: List of warnings or empty list.
    """
    warns = []
    if client["tag"] in [ "[MOBILE]", "[SPA_PUBLIC]" ]:
        if client["access_type"] != "PUBLIC":
            warns.append(getWarn(client, "WARN", "This client should be PUBLIC."))
        if client["pkce_code_challenge_method"] is None:
            warns.append(getWarn(client, "WARN", "This client should have PKCE enabled."))
    else:
        if client["access_type"] != "CONFIDENTIAL":
            warns.append(getWarn(client, "WARN", "This client should be CONFIDENTIAL."))
        if client["pkce_code_challenge_method"] is not None:
            warns.append(getWarn(client, "WARN", "This client should have PKCE disabled."))
    return warns


def checkGrants(client):
    """
    Verify Grants (flows).

    :param client (dict): Normalized Client object.
    :return: List of warnings or empty list.
    """
    warns = []
    if client["implicit_flow"]:
        warns.append(getWarn(client, "WARN", "This client should have implicit flow disabled."))
    match client["tag"]:
        case "[CLIENT_CREDENTIALS]":
            if client["authorization_code_flow"]:
                warns.append(getWarn(client, "WARN", "This client should have standard flow disabled."))
            if client["ropc_flow"]:
                warns.append(getWarn(client, "WARN", "This client should have direct access grants disabled."))
            if not client["client_credentials_flow"]:
                warns.append(getWarn(client, "WARN", "This client should have service accounts enabled."))
        case "[IDP_INTERNAL]":
            logger.debug("No controls for IDP_INTERNAL.")
        case "[ROPC]":
            if client["authorization_code_flow"]:
                warns.append(getWarn(client, "WARN", "This client should have standard flow disabled."))
            if not client["ropc_flow"]:
                warns.append(getWarn(client, "WARN", "This client should have direct access grants enabled."))
            if client["client_credentials_flow"]:
                warns.append(getWarn(client, "WARN", "This client should have service accounts disabled."))
        case _:
            if not client["authorization_code_flow"]:
                warns.append(getWarn(client, "WARN", "This client should have standard flow enabled."))
            if client["ropc_flow"]:
                warns.append(getWarn(client, "WARN", "This client should have direct access grants disabled."))
            if client["client_credentials_flow"]:
                warns.append(getWarn(client, "WARN", "This client should have service accounts disabled."))
    return warns


def checkWebOrigins(client):
    """
    Verify Web origins.

    :param client (dict): Normalized Client object.
    :return: List of warnings or empty list.
    """
    warns = []
    web_origins_count = len(client["web_origins"])
    if client["tag"] == "[SPA_PUBLIC]":
        if web_origins_count > 1:
            warns.append(getWarn(client, "WARN", "This client should only have 1 web origins but has {}.".format(web_origins_count)))
        elif web_origins_count == 0:
            warns.append(getWarn(client, "WARN", "This client should have 1 web origins but has none."))
    else:
        if web_origins_count > 0:
            warns.append(getWarn(client, "WARN", "This client should not have web origins but has {}.".format(web_origins_count)))
    return warns


def checkPostLogoutRedirectUrls(client, env):
    """
    Verify post_logout_redirect_url values.

    :param client (dict): Normalized Client object.
    :param env (str): Environment.
    :return: List of warnings or empty list.
    """
    client_post_logout_redirect_urls_count = len(client["post_logout_redirect_uris"])
    
    if client["tag"] == "[IDP_INTERNAL]":
        logger.debug("No controls for IDP_INTERNAL.")
        return []
    
    if client["tag"] in [ "[CLIENT_CREDENTIALS]", "[MOBILE]", "[ROPC]" ]:
        if client_post_logout_redirect_urls_count > 0:
            return [getWarn(client, "WARN", "This client should not have post_logout_redirect_url, but has {}.".format(client_post_logout_redirect_urls_count))]
    else:
        if not env == "dev":
            if client_post_logout_redirect_urls_count == 0:
                return [getWarn(client, "WARN", "This client should have post_logout_redirect_url, but has none.")]
            elif client_post_logout_redirect_urls_count > 1:
                return [getWarn(client, "WARN", "This client should have only one post_logout_redirect_url, but has {}.".format(client_post_logout_redirect_urls_count))]
    return []


def checkSessionTimeout(client, realm):
    """
    Verify session timeouts

    :param client (dict): Normalized Client object.
    :param realm (dict): Realm object.
    :return: List of warnings or empty list.
    """
    warns = []
    effective_client_session_idle = client["effective_client_session_idle"]
    realm_sso_session_idle_timeout = realm["ssoSessionIdleTimeout"]
    logger.debug("checkSessionTimeout(): client: {}, effective_client_session_idle: {} ({}), realm_sso_session_idle_timeout: {} ({})", client["client_id"], effective_client_session_idle, type(effective_client_session_idle), realm_sso_session_idle_timeout, type(realm_sso_session_idle_timeout))
    if effective_client_session_idle > realm_sso_session_idle_timeout:
        warns.append(getWarn(client, "WARN", "This client has a session timeout greater than the Realm SSO idle timeout."))
    return warns