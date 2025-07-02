#!/usr/bin/env python3

import argparse
import json
import os
import sys
from sherpa.utils.basics import Logger
import utils


def getEnvWarns(logger: Logger, env: str) -> list:
    """Returns a list of warnings regarding all of a provided `environment`'s realms

    Args:
		logger (Logger): Logger instance
        env (str): Environment name

    Returns:
        list: Warnings for all realms in the environment
    """
    envWarns = []
    for realmName in utils.getRealms(logger, env):
        realmWarns = getRealmWarns(logger, env, realmName)
        for realmWarn in realmWarns:
            envWarns.append(realmWarn)
    return envWarns


def getRealmWarns(logger: Logger, env: str, realmName: str) -> list:
    """Returns a list of warnings regarding a provided `realm` in a given `environment`

    Args:
		logger (Logger): Logger instance
        env (str): Environment name
        realmName (str): Realm name

    Returns:
        list: _description_
    """
    realmWarns = []
    for client in utils.getClients(env, realmName):
        normalized_client = utils.getClient(env, realmName, client["clientId"])
        clientWarns = getClientWarns(logger, env, realmName, normalized_client)
        for clientWarn in clientWarns:
            logger.trace("Adding client warning: {}", clientWarn)
            realmWarns.append(clientWarn)
            logger.trace("Realm warns: {}", realmWarns)
    logger.trace("getRealmWarns({}, {}). response: {}", env, realmName, realmWarns)
    return realmWarns


def getClientWarns(logger: Logger, env: str, realmName: str, client: dict) -> list:
    """ # TODO: Add support for SAML clients.
    # SAML clients are not supported yet.
    return warns
    
    Gathers and returns a list of a given `client` in the provided `realm`'s active warnings

    Args:
		logger (Logger): Logger instance
        env (str): Environment name
        realmName (str): Realm name
        client (dict): Client Object

    Returns:
        list: Client's warnings.
    """
    logger.trace("getClientWarns({}, {}, {})", env, realmName, client.get("name"))

    if client["enabled"] is False:
        logger.debug("Client is disabled, no warnings will be generated.")
        return []

    clientWarns = []

    if client["tag"]=="[KEYCLOAK_NATIVE]":
        logger.debug("Native client, do nothing.")
        return []
    else:
        for warn in checkTag(logger, client):
            clientWarns.append(warn)

    if client["name"]=="":
        clientWarns.append(getWarn(logger, client, "WARN", "Client has no name."))

    for warn in checkOwnerEmail(logger, client):
        clientWarns.append(warn)

    for warn in checkRedirectUrls(logger, client, env):
        clientWarns.append(warn)

    for warn in checkWebOrigins(logger, client):
        clientWarns.append(warn)

    if client["type"] == "openid-connect":
        for warn in checkAccessTokenLifespan(logger, client):
            clientWarns.append(warn)
        for warn in checkPostLogoutRedirectUrls(logger, client, env):
            clientWarns.append(warn)
        for warn in checkAccessType(logger, client):
            clientWarns.append(warn)
        for warn in checkGrants(logger, client):
                clientWarns.append(warn)
        for warn in checkFrontChannelLogout(logger, client):
            clientWarns.append(warn)
        realm = utils.getRealm(env, realmName)
        for warn in checkSessionTimeout(logger, client, realm):
            clientWarns.append(warn)

    logger.trace("getClientWarns response. client_name: {}, response: {}", client.get("client_name"), clientWarns)
    return clientWarns



def getWarn(logger: Logger, client: dict, level: str, issue_description: str) -> dict:
    """Returns a warning dictionary for a given client.
    
    Args:
		logger (Logger): Logger instance
        client (dict): Client object
        level (str): Warning level (e.g., "WARN", "ERROR")
        issue_description (str): Description of the issue
    
    Returns:
        dict: Dictionary with warning details
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


def checkTag(logger: Logger, client: dict) -> list:
    """Checks the tag and verifies with client.type

    Args:
		logger (Logger): Logger instance
        client (dict): Normalized Client Object

    Returns:
        list: Respective warnings. Empty list otherwise.
    """
    logger.trace("checkTag({})", client.get("client_id"))
    warns = []

    if client["type"]=="saml" and client["tag"]!="[SAML]":
        warns.append(getWarn(logger, client, "WARN", "Tag should be [SAML]."))

    if client["type"]=="openid-connect" and client["tag"]=="[SAML]":
        warns.append(getWarn(logger, client, "WARN", "Tag should NOT be [SAML]."))

    if client["tag"]=="[TAG_MISSING]":
        warns.append(getWarn(logger, client, "WARN", "Client has no tag."))

    if client["tag"]=="[TAG_INVALID]":
        warns.append(getWarn(logger, client, "WARN", "Client tag is invalid: " + client["tag"]))
        
    return warns


def checkOwnerEmail(logger: Logger, client: dict) -> list:
    """Checks if a given client has an Owner Email set up. Returns a warning if not.

    Args:
		logger (Logger): Logger instance
        client (dict): Normalized Client Object

    Returns:
        list: Respective warning should the email not be set. Empty list otherwise.
    """
    logger.trace("checkOwnerEmail({})", client.get("client_id"))
    if client.get("owner_email") == "":
        return [getWarn(logger, client, "WARN", "Client does not have an owner email.")]
    else:
        return []


def checkAccessTokenLifespan(logger: Logger, client: dict) -> list:
    """Checks if a given client has an accessTokenLifespan set up. Returns a warning if not.

    Args:
		logger (Logger): Logger instance
        client (dict): Normalized Client Object

    Returns:
        list: Respective warning should the accessTokenLifespan not be set. Empty list otherwise.
    """
    logger.trace("checkAccessTokenLifespan({})", client.get("client_id"))
    access_token_lifespan = client["access_token_lifespan"]
    logger.trace("access_token_lifespan: {}, type: {}", access_token_lifespan, type(access_token_lifespan))
    if client["tag"] == "[CLIENT_CREDENTIALS]":
        if access_token_lifespan is None or isinstance(access_token_lifespan, str) or int(access_token_lifespan) < 1800:
            return [getWarn(logger, client, "WARN", "This client should have an access token lifespan of (at least) 1800 seconds.")]
    return []


def checkRedirectUrls(logger: Logger, client: dict, env: str) -> list:
    """Checks if a given client has Redirect URLs set up. Returns a warning if not.

    Args:
		logger (Logger): Logger instance
        client (dict): Normalized Client Object
        env (str): Environment name - Used to check for specific cases where a warning is not needed.

    Returns:
        list: Respective warning should the Redirect URLs be invalid or blank. Empty list otherwise.
    """
    redirect_urls = client["redirect_uris"]
    redirect_urls_count = len(redirect_urls)

    tag = client["tag"]
    if client["tag"] == "[IDP_INTERNAL]":
        return []
    if client["tag"] in [ "[CLIENT_CREDENTIALS]", "[ROPC]" ]:
        if redirect_urls_count > 0:
            issue_description = "This client should not have redirect_url values, but has {}.".format(redirect_urls_count)
            logger.debug("Returning issue '{}' for client '{}'", issue_description, client["client_id"])
            return [getWarn(logger, client, "WARN", issue_description)]
        else:
            return []

    if redirect_urls_count == 0:
        return [getWarn(logger, client, "WARN", "This client should have redirect_url values, but has none.")]

    absolute_redirect_urls_count = 0
    for redirect_url in redirect_urls:
        if not redirect_url.startswith("/"):
            absolute_redirect_urls_count += 1

    if absolute_redirect_urls_count > 1 and env != "dev":
        return [getWarn(logger, client, "WARN", "This client should have up to 1 absolute redirect_url value, but has {}.".format(redirect_urls_count))]

    warns = []
    for redirect_url in redirect_urls:
        if tag == "[MOBILE]":
            if redirect_url.startswith("http"):
                return [getWarn(logger, client, "WARN", "This client's redirect_url should not start with http.")]
        else:
            if (env != "dev") and (not redirect_url.startswith("http")) and (not redirect_url.startswith("/")):
                return [getWarn(logger, client, "WARN", "This client's redirect_url should start with 'http' or '/'.")]
        if env != "dev":
            if "localhost" in redirect_url:
                return [getWarn(logger, client, "WARN", "This client has a redirect_url that contains localhost.")]
            if "*" in redirect_url or "+" in redirect_url:
                return [getWarn(logger, client, "WARN", "This client has a redirect_url that contains wildcard characters.")]
    return warns


def checkFrontChannelLogout(logger: Logger, client: dict) -> list:
    """Checks if a given client has FrontChannelLogout set up properly. Returns a warning if not.

    Args:
		logger (Logger): Logger instance
        client (dict): Normalized Client Object

    Returns:
        list: Respective warning should the client not have FrontChannelLogout set up properly. Empty list otherwise
    """
    if client["frontchannel_logout_enabled"]:
        if client["frontchannel_logout_url"] == "":
            return [getWarn(logger, client, "WARN", "This client has frontchannel_logout enabled but does not have a frontchannel_logout_url.")]
        else:
            return []
    else:
        if client["frontchannel_logout_url"] == "":
            return []
        else:
            return [getWarn(logger, client, "WARN", "This client has frontchannel_logout disabled but has a frontchannel_logout_url.")]


def checkAccessType(logger: Logger, client: dict) -> list:
    """Checks if a given client has AccessType set up properly. Returns a list of warnings if not.

    Args:
		logger (Logger): Logger instance
        client (dict): Normalized Client Object

    Returns:
        list: Respective warning should the client not have AccessType set up properly. Empty list otherwise.
    """
    warns = []
    if client["tag"] in [ "[MOBILE]", "[SPA_PUBLIC]" ]:
        if client["access_type"] != "PUBLIC":
            warns.append(getWarn(logger, client, "WARN", "This client should be PUBLIC."))
        if client["pkce_code_challenge_method"] is None:
            warns.append(getWarn(logger, client, "WARN", "This client should have PKCE enabled."))
    else:
        if client["access_type"] != "CONFIDENTIAL":
            warns.append(getWarn(logger, client, "WARN", "This client should be CONFIDENTIAL."))
        if client["pkce_code_challenge_method"] is not None:
            warns.append(getWarn(logger, client, "WARN", "This client should have PKCE disabled."))
    return warns


def checkGrants(logger: Logger, client: dict) -> list:
    """Checks if a given client has Grants set up properly. Returns a list of warnings if not.

    Args:
		logger (Logger): Logger instance
        client (dict): Normalized Client Object

    Returns:
        list: Respective list of warnings should Grants not be properly set up. Empty list otherwise.
    """
    
    """
    Verify Grants (flows).

    :param client (dict): Normalized Client object.
    :return: List of warnings should Grants not be set up properly, empty list otherwise.
    """
    
    warns = []
    if client["implicit_flow"]:
        warns.append(getWarn(logger, client, "WARN", "This client should have implicit flow disabled."))
    match client["tag"]:
        case "[CLIENT_CREDENTIALS]":
            if client["authorization_code_flow"]:
                warns.append(getWarn(logger, client, "WARN", "This client should have standard flow disabled."))
            if client["ropc_flow"]:
                warns.append(getWarn(logger, client, "WARN", "This client should have direct access grants disabled."))
            if not client["client_credentials_flow"]:
                warns.append(getWarn(logger, client, "WARN", "This client should have service accounts enabled."))
        case "[IDP_INTERNAL]":
            logger.debug("No controls for IDP_INTERNAL.")
        case "[ROPC]":
            if client["authorization_code_flow"]:
                warns.append(getWarn(logger, client, "WARN", "This client should have standard flow disabled."))
            if not client["ropc_flow"]:
                warns.append(getWarn(logger, client, "WARN", "This client should have direct access grants enabled."))
            if client["client_credentials_flow"]:
                warns.append(getWarn(logger, client, "WARN", "This client should have service accounts disabled."))
        case _:
            if not client["authorization_code_flow"]:
                warns.append(getWarn(logger, client, "WARN", "This client should have standard flow enabled."))
            if client["ropc_flow"]:
                warns.append(getWarn(logger, client, "WARN", "This client should have direct access grants disabled."))
            if client["client_credentials_flow"]:
                warns.append(getWarn(logger, client, "WARN", "This client should have service accounts disabled."))
    return warns


def checkWebOrigins(logger: Logger, client: dict) -> list:
    """Checks if a given Client's Web Origins are set up propertly. Returns a list of warnings if not

    Args:
		logger (Logger): Logger instance
        client (dict): Normalized Client Object

    Returns:
        list: List of warnings should Web Origins not be set up properly, empty list otherwise.
    """
    warns = []
    web_origins_count = len(client["web_origins"])
    if client["tag"] == "[SPA_PUBLIC]":
        if web_origins_count > 1:
            warns.append(getWarn(logger, client, "WARN", "This client should only have 1 web origins but has {}.".format(web_origins_count)))
        elif web_origins_count == 0:
            warns.append(getWarn(logger, client, "WARN", "This client should have 1 web origins but has none."))
    else:
        if web_origins_count > 0:
            warns.append(getWarn(logger, client, "WARN", "This client should not have web origins but has {}.".format(web_origins_count)))
    return warns


def checkPostLogoutRedirectUrls(logger: Logger, client: dict, env: str) -> list:
    """Checks if a given Client's PostLogoutRedirectUrls are set up properly. Returns a list of warnings if not.

    Args:
		logger (Logger): Logger instance
        client (dict): Normalized Client Object
        env (str): Environment name

    Returns:
        list: List of warnings should PostLogoutRedirectUrls not be set up properly, empty list otherwise.
    """
    client_post_logout_redirect_urls_count = len(client["post_logout_redirect_uris"])
    
    if client["tag"] == "[IDP_INTERNAL]":
        logger.debug("No controls for IDP_INTERNAL.")
        return []
    
    if client["tag"] in [ "[CLIENT_CREDENTIALS]", "[MOBILE]", "[ROPC]" ]:
        if client_post_logout_redirect_urls_count > 0:
            return [getWarn(logger, client, "WARN", "This client should not have post_logout_redirect_url, but has {}.".format(client_post_logout_redirect_urls_count))]
    else:
        if not env == "dev":
            if client_post_logout_redirect_urls_count == 0:
                return [getWarn(logger, client, "WARN", "This client should have post_logout_redirect_url, but has none.")]
            elif client_post_logout_redirect_urls_count > 1:
                return [getWarn(logger, client, "WARN", "This client should have only one post_logout_redirect_url, but has {}.".format(client_post_logout_redirect_urls_count))]
    return []


def checkSessionTimeout(logger: Logger, client: str, realm: str) -> list:
    """Checks if a given Client's SessionTimeout is set up properly. Returns a list of warnings if not.

    Args:
		logger (Logger): Logger instance
        client (str): Normalized Client Object
        realm (str): Realm name
    
    Returns:
        list: List of warnings should SessionTimeout not be set up properly, empty list otherwise.
    """
    warns = []
    effective_client_session_idle = client["effective_client_session_idle"]
    realm_sso_session_idle_timeout = realm["ssoSessionIdleTimeout"]
    logger.debug("checkSessionTimeout(): client: {}, effective_client_session_idle: {} ({}), realm_sso_session_idle_timeout: {} ({})", client["client_id"], effective_client_session_idle, type(effective_client_session_idle), realm_sso_session_idle_timeout, type(realm_sso_session_idle_timeout))
    if effective_client_session_idle > realm_sso_session_idle_timeout:
        warns.append(getWarn(logger, client, "WARN", "This client has a session timeout greater than the Realm SSO idle timeout."))
    return warns


def store_warns(logger: Logger, warns: list, output_file_path: str):
	"""Saves warns to a JSON file

	Args:
		logger (Logger): Logger instance
		warns (list): List of warnings
		output_file_path (str): **File** Path in which to save the JSON Plan
	"""
	metadata = { "timestamp": utils.get_local_datetime() }
	output_content = { "metadata": metadata, "warns": warns }
	logger.info("Storing warns into: {}", output_file_path)
	with open(output_file_path, 'w') as f:
		json.dump(output_content, f, indent=4)


def run(logger: Logger, output_path: str, environment: str) -> list:
	"""Runs CheckClients Report Generation for a given Environment

	Args:
		logger (Logger): Logger instance
		output_path (str): **Directory** Path in which to save the JSON output
		environment (str): Environment in which to run Diff Report Generation

	Returns:
		str: Process output
	"""
	logger.info("Checking Client for environment: {}", environment)
	output_file_path = "{}/checkclients_{}.json".format(output_path, environment)
	env_warns = getEnvWarns(logger, environment)
	store_warns(logger, env_warns, output_file_path)
	return ""


def main(arguments):
	logger = Logger(os.path.basename(__file__), os.environ.get("LOG_LEVEL"), "/tmp/checkclients_report.log")
	parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('output_path', type=str, help="Path to checkclients_*.json files.")
	args = parser.parse_args(arguments)
	for environment in utils.getEnvironments(logger):
		run(logger, args.output_path, environment)
	logger.info("{} finished.".format(os.path.basename(__file__)))


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))