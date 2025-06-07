from flask import Blueprint, render_template
from utils import *

checkclients_bp = Blueprint('checkclients', __name__)


@checkclients_bp.route('/checkclients/<env>', methods=["GET"])
def checkclientsEnv(env):
    warns = getEnvWarns(env)
    logger.debug("checkclientsEnv({}). warns: {}", env, warns)
    return render_template('checkclients.html', realms=getRealms(), environments=getEnvironments(), env=env, warns=warns, realmName="All Realms")


@checkclients_bp.route('/checkclients/<env>/<realmName>', methods=["GET"])
def checkclientsEnvRealm(env, realmName):
    warns = getRealmWarns(env, realmName)
    logger.debug("checkclientsEnvRealm({}). warns: {}", env, warns)
    return render_template('checkclients.html', realms=getRealms(), environments=getEnvironments(), env=env, warns=warns, realmName=realmName)


def getEnvWarns(env):
    envWarns = []
    for realmName in getRealms():
        realmWarns = getRealmWarns(env, realmName)
        for realmWarn in realmWarns:
            envWarns.append(realmWarn)
    return envWarns


def getRealmWarns(env, realmName):
    realmWarns = []
    for client in getClients(env, realmName):
        normalized_client = getClient(env, realmName, client["clientId"])
        clientWarns = getClientWarns(normalized_client, env)
        for clientWarn in clientWarns:
            logger.trace("Adding client warning: {}", clientWarn)
            realmWarns.append(clientWarn)
            logger.trace("Realm warns: {}", realmWarns)
    logger.trace("getRealmWarns({}, {}). response: {}", env, realmName, realmWarns)
    return realmWarns


def getClientWarns(client, env):
    logger.trace("getWarns(). client_name: {}", client.get("name"))

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

    for warn in checkFrontChannelLogout(client):
        clientWarns.append(warn)

    for warn in checkAccessType(client):
        clientWarns.append(warn)

    for warn in checkGrants(client):
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
    absolute_redirect_urls_count = 0
    tag = client["tag"]
    
    if client["tag"] == "[IDP_INTERNAL]":
        return []

    for redirect_url in redirect_urls:
        if not redirect_url.startswith("/"):
            absolute_redirect_urls_count += 1

    if client["tag"] in [ "[CLIENT_CREDENTIALS]", "[ROPC]" ]:
        if redirect_urls_count > 0:
            issue_description = "This client should not have redirect_url values, but has {}.".format(redirect_urls_count)
            logger.debug("Returning issue '{}' for client '{}'", issue_description, client["client_id"])
            return [getWarn(client, "WARN", issue_description)]

    if redirect_urls_count == 0:
            issue_description = "This client should have redirect_url values, but has none."
            logger.debug("Returning issue '{}' for client '{}'", issue_description, client["client_id"])
            return [getWarn(client, "WARN", issue_description)]
    
    warns = []
    if absolute_redirect_urls_count > 1 and env != "dev":
        issue_description = "This client should have up to 1 absolute redirect_url value, but has {}.".format(redirect_urls_count)
        logger.debug("Returning issue '{}' for client '{}'", issue_description, client["client_id"])
        return [getWarn(client, "WARN", issue_description)]

    for redirect_url in redirect_urls:
        if tag == "[MOBILE]":
            if redirect_url.startswith("http"):
                issue_description = "This client's redirect_url should not start with http."
                logger.debug("Returning issue '{}' for client '{}'", issue_description, client["client_id"])
                return [getWarn(client, "WARN", issue_description)]
        else:
            if (env != "dev") and (not redirect_url.startswith("http")) and (not redirect_url.startswith("/")):
                issue_description = "This client's redirect_url should start with 'http' or '/'."
                logger.debug("Returning issue '{}' for client '{}'", issue_description, client["client_id"])
                return [getWarn(client, "WARN", issue_description)]

        if env != "dev":
            if "localhost" in redirect_url:
                issue_description = "This client has a redirect_url that contains localhost."
                logger.debug("Returning issue '{}' for client '{}'", issue_description, client["client_id"])
                return [getWarn(client, "WARN", issue_description)]
            if "*" in redirect_url or "+" in redirect_url:
                issue_description = "This client has a redirect_url that contains wildcard characters."
                logger.debug("Returning issue '{}' for client '{}'", issue_description, client["client_id"])
                return [getWarn(client, "WARN", issue_description)]

    return warns


def checkFrontChannelLogout(client):
    """
    Check fron channel logout settings.

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
    if client["tag"] in [ "[MOBILE]", "[SPA_PUBLIC]" ]:
        if client["access_type"] != "PUBLIC":
            return [getWarn(client, "WARN", "This client should be PUBLIC.")]
        if client["pkce_code_challenge_method"] is None:
            return [getWarn(client, "WARN", "This client should have PKCE enabled.")]
    else:
        if client["access_type"] != "CONFIDENTIAL":
            return [getWarn(client, "WARN", "This client should be CONFIDENTIAL.")]
        if client["pkce_code_challenge_method"] is not None:
            return [getWarn(client, "WARN", "This client should have PKCE disabled.")]
    return []


def checkGrants(client):
    """
    Verify Client Grants (flows).

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