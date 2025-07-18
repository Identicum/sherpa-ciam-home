#!/usr/bin/env python3

import argparse
import json
import os
import sys
from sherpa.utils.basics import Logger
import utils


def getEnvWarns(logger: Logger, environment: str, config: dict) -> list:
    """Returns a list of warnings regarding all of a provided `environment`'s realms

    Args:
		logger (Logger): Logger instance
        environment (str): Environment name
        config (dict): JSON configuration

    Returns:
        list: Warnings for all realms in the environment
    """
    envWarns = []
    for realmName in utils.getRealms(logger=logger, environment=environment, config=config):
        realmWarns = getRealmWarns(logger=logger, environment=environment, realmName=realmName, config=config)
        for realmWarn in realmWarns:
            envWarns.append(realmWarn)
    return envWarns


def getRealmWarns(logger: Logger, environment: str, realmName: str, config: dict) -> list:
    """Returns a list of warnings regarding a provided `realm` in a given `environment`

    Args:
		logger (Logger): Logger instance
        environment (str): Environment name
        realmName (str): Realm name
        config (dict): JSON configuration

    Returns:
        list: List of realm warnings
    """
    realmWarns = []
    for client in utils.getClients(logger=logger, environment=environment, realmName=realmName, config=config):
        normalizedClient = utils.getNormalizedClient(logger=logger, environment=environment, realmName=realmName, client_id=client["clientId"], config=config)
        clientWarns = getClientWarns(logger=logger, environment=environment, realmName=realmName, normalizedClient=normalizedClient, config=config)
        for clientWarn in clientWarns:
            logger.trace("Adding client warning: {}", clientWarn)
            realmWarns.append(clientWarn)
            logger.trace("Realm warns: {}", realmWarns)
    logger.trace("getRealmWarns({}, {}). response: {}", environment, realmName, realmWarns)
    return realmWarns


def getClientWarns(logger: Logger, environment: str, realmName: str, normalizedClient: dict, config: dict) -> list:
    """ # TODO: Add support for SAML clients.
    # SAML clients are not supported yet.
    return warns
    
    Gathers and returns a list of a given `client` in the provided `realm`'s active warnings

    Args:
		logger (Logger): Logger instance
        environment (str): Environment name
        realmName (str): Realm name
        normalizedClient (dict): Normalized Client object
        config (dict): JSON configuration

    Returns:
        list: Client's warnings.
    """
    logger.trace("getClientWarns({}, {}, {})", environment, realmName, normalizedClient.get("name"))

    if normalizedClient["enabled"] is False:
        logger.debug("Client is disabled, no warnings will be generated.")
        return []

    clientWarns = []

    if normalizedClient["tag"]=="[KEYCLOAK_NATIVE]":
        logger.debug("Native client, do nothing.")
        return []
    else:
        for warn in checkTag(logger=logger, normalizedClient=normalizedClient):
            clientWarns.append(warn)

    if normalizedClient["name"]=="":
        clientWarns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="Client has no name."))

    for warn in checkOwnerEmail(logger=logger, normalizedClient=normalizedClient):
        clientWarns.append(warn)

    for warn in checkRedirectUrls(logger=logger, normalizedClient=normalizedClient, environment=environment):
        clientWarns.append(warn)

    for warn in checkWebOrigins(logger=logger, normalizedClient=normalizedClient):
        clientWarns.append(warn)

    if normalizedClient["type"] == "openid-connect":
        for warn in checkAccessTokenLifespan(logger=logger, normalizedClient=normalizedClient):
            clientWarns.append(warn)
        for warn in checkAccessType(logger=logger, normalizedClient=normalizedClient):
            clientWarns.append(warn)
        for warn in checkFrontChannelLogout(logger=logger, normalizedClient=normalizedClient):
            clientWarns.append(warn)
        for warn in checkGrants(logger=logger, normalizedClient=normalizedClient):
                clientWarns.append(warn)
        for warn in checkPostLogoutRedirectUrls(logger=logger, normalizedClient=normalizedClient, environment=environment):
            clientWarns.append(warn)
        realm = utils.getRealm(logger=logger, environment=environment, realmName=realmName, config=config)
        for warn in checkSessionTimeout(logger=logger, normalizedClient=normalizedClient, realm=realm):
            clientWarns.append(warn)
        for warn in checkScopes(logger=logger, normalizedClient=normalizedClient):
                clientWarns.append(warn)
        for warn in checkMappers(logger=logger, normalizedClient=normalizedClient):
                clientWarns.append(warn)

    logger.trace("getClientWarns response. client_name: {}, response: {}", normalizedClient.get("client_name"), clientWarns)
    return clientWarns


def getWarn(logger: Logger, normalizedClient: dict, issueLevel: str, issueDescription: str) -> dict:
    """Returns a warning dictionary for a given client.
    
    Args:
		logger (Logger): Logger instance
        normalizedClient (dict): Normalized Client object
        level (str): Warning level (e.g., "WARN", "ERROR")
        issueDescription (str): Description of the issue
    
    Returns:
        dict: Dictionary with warning details
    """
    return dict(
        realmName=normalizedClient["realm_name"],
        client_id=normalizedClient["client_id"],
        tag=normalizedClient["tag"],
        name=normalizedClient["name"],
        description=normalizedClient["description"],
        issueLevel=issueLevel,
        issueDescription=issueDescription
    )


def checkTag(logger: Logger, normalizedClient: dict) -> list:
    """Checks the tag and verifies with client.type

    Args:
		logger (Logger): Logger instance
        client (dict): Normalized Client Object

    Returns:
        list: Respective warnings. Empty list otherwise.
    """
    logger.trace("checkTag({})", normalizedClient.get("client_id"))
    warns = []

    if normalizedClient["type"]=="saml" and normalizedClient["tag"]!="[SAML]":
        warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="Tag should be [SAML]."))

    if normalizedClient["type"]=="openid-connect" and normalizedClient["tag"]=="[SAML]":
        warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="Tag should NOT be [SAML]."))

    if normalizedClient["tag"]=="[TAG_MISSING]":
        warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="Client has no tag."))

    if normalizedClient["tag"]=="[TAG_INVALID]":
        warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="Client tag is invalid: " + normalizedClient["tag"]))
        
    return warns


def checkOwnerEmail(logger: Logger, normalizedClient: dict) -> list:
    """Checks if a given client has an Owner Email set up. Returns a warning if not.

    Args:
		logger (Logger): Logger instance
        client (dict): Normalized Client Object

    Returns:
        list: Respective warning should the email not be set. Empty list otherwise.
    """
    logger.trace("checkOwnerEmail({})", normalizedClient.get("client_id"))
    if normalizedClient.get("owner_email") == "":
        return [getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="Client does not have an owner email.")]
    else:
        return []


def checkAccessTokenLifespan(logger: Logger, normalizedClient: dict) -> list:
    """Checks if a given client has an accessTokenLifespan set up. Returns a warning if not.

    Args:
		logger (Logger): Logger instance
        client (dict): Normalized Client Object

    Returns:
        list: Respective warning should the accessTokenLifespan not be set. Empty list otherwise.
    """
    logger.trace("checkAccessTokenLifespan({})", normalizedClient.get("client_id"))
    access_token_lifespan = normalizedClient["access_token_lifespan"]
    logger.trace("access_token_lifespan: {}, type: {}", access_token_lifespan, type(access_token_lifespan))
    if normalizedClient["tag"] == "[CLIENT_CREDENTIALS]":
        if access_token_lifespan is None or isinstance(access_token_lifespan, str) or int(access_token_lifespan) < 1800:
            return [getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have an access token lifespan of (at least) 1800 seconds.")]
    return []


def checkRedirectUrls(logger: Logger, normalizedClient: dict, environment: str) -> list:
    """Checks if a given client has Redirect URLs set up. Returns a warning if not.

    Args:
		logger (Logger): Logger instance
        client (dict): Normalized Client Object
        environment (str): Environment name

    Returns:
        list: Respective warning should the Redirect URLs be invalid or blank. Empty list otherwise.
    """
    redirectUrls = normalizedClient["redirect_uris"]
    redirectUrlsCount = len(redirectUrls)

    tag = normalizedClient["tag"]
    if normalizedClient["tag"] == "[IDP_INTERNAL]":
        return []
    if normalizedClient["tag"] in [ "[CLIENT_CREDENTIALS]", "[ROPC]" ]:
        if redirectUrlsCount > 0:
            issueDescription = "This client should not have redirect_url values, but has {}.".format(redirectUrlsCount)
            logger.trace("Returning issue '{}' for client '{}'", issueDescription, normalizedClient["client_id"])
            return [getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription=issueDescription)]
        else:
            return []

    if redirectUrlsCount == 0:
        return [getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have redirect_url values, but has none.")]

    absolute_redirect_urls_count = 0
    for redirectUrl in redirectUrls:
        if not redirectUrl.startswith("/"):
            absolute_redirect_urls_count += 1

    if absolute_redirect_urls_count > 1 and environment != "dev":
        return [getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have up to 1 absolute redirect_url value, but has {}.".format(redirectUrlsCount))]

    warns = []
    for redirectUrl in redirectUrls:
        if tag == "[MOBILE]":
            if redirectUrl.startswith("http"):
                return [getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client's redirect_url should not start with http.")]
        else:
            if (environment != "dev") and (not redirectUrl.startswith("http")) and (not redirectUrl.startswith("/")):
                return [getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client's redirect_url should start with 'http' or '/'.")]
        if environment != "dev":
            if "localhost" in redirectUrl:
                return [getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client has a redirect_url that contains localhost.")]
            if "*" in redirectUrl or "+" in redirectUrl:
                return [getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client has a redirect_url that contains wildcard characters.")]
    return warns


def checkFrontChannelLogout(logger: Logger, normalizedClient: dict) -> list:
    """Checks if a given client has FrontChannelLogout set up properly. Returns a warning if not.

    Args:
		logger (Logger): Logger instance
        client (dict): Normalized Client Object

    Returns:
        list: Respective warning should the client not have FrontChannelLogout set up properly. Empty list otherwise
    """
    if normalizedClient["frontchannel_logout_enabled"]:
        if normalizedClient["frontchannel_logout_url"] == "":
            return [getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client has frontchannel_logout enabled but does not have a frontchannel_logout_url.")]
        else:
            return []
    else:
        if normalizedClient["frontchannel_logout_url"] == "":
            return []
        else:
            return [getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client has frontchannel_logout disabled but has a frontchannel_logout_url.")]


def checkAccessType(logger: Logger, normalizedClient: dict) -> list:
    """Checks if a given client has AccessType set up properly. Returns a list of warnings if not.

    Args:
		logger (Logger): Logger instance
        client (dict): Normalized Client Object

    Returns:
        list: Respective warning should the client not have AccessType set up properly. Empty list otherwise.
    """
    warns = []
    if normalizedClient["tag"] in [ "[MOBILE]", "[SPA_PUBLIC]" ]:
        if normalizedClient["access_type"] != "PUBLIC":
            warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should be PUBLIC."))
        if normalizedClient["pkce_code_challenge_method"] is None:
            warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have PKCE enabled."))
    else:
        if normalizedClient["access_type"] != "CONFIDENTIAL":
            warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should be CONFIDENTIAL."))
        if normalizedClient["pkce_code_challenge_method"] is not None:
            warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have PKCE disabled."))
    return warns


def checkGrants(logger: Logger, normalizedClient: dict) -> list:
    """Checks if a given client has Grants set up properly. Returns a list of warnings if not.

    Args:
		logger (Logger): Logger instance
        client (dict): Normalized Client Object

    Returns:
        list: Respective list of warnings should Grants not be properly set up. Empty list otherwise.
    """
    warns = []
    if normalizedClient["implicit_flow"]:
        warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have implicit flow disabled."))
    match normalizedClient["tag"]:
        case "[CLIENT_CREDENTIALS]":
            if normalizedClient["authorization_code_flow"]:
                warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have standard flow disabled."))
            if normalizedClient["ropc_flow"]:
                warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have direct access grants disabled."))
            if not normalizedClient["client_credentials_flow"]:
                warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have service accounts enabled."))
        case "[IDP_INTERNAL]" | "[NATIVE]":
            logger.debug("No controls for {}.", normalizedClient["tag"])
        case "[ROPC]":
            if normalizedClient["authorization_code_flow"]:
                warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have standard flow disabled."))
            if not normalizedClient["ropc_flow"]:
                warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have direct access grants enabled."))
            if normalizedClient["client_credentials_flow"]:
                warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have service accounts disabled."))
        case _:
            if not normalizedClient["authorization_code_flow"]:
                warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have standard flow enabled."))
            if normalizedClient["ropc_flow"]:
                warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have direct access grants disabled."))
            if normalizedClient["client_credentials_flow"]:
                warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have service accounts disabled."))
    return warns


def checkScopes(logger: Logger, normalizedClient: dict) -> list:
    """Checks if a given client has Scopes set up properly. Returns a list of warnings if not.

    Args:
		logger (Logger): Logger instance
        client (dict): Normalized Client Object

    Returns:
        list: Respective list of warnings should Scopes not be properly set up. Empty list otherwise.
    """
    warns = []
    match normalizedClient["tag"]:
        case "[CLIENT_CREDENTIALS]":
            for mandatoryScope in ["basic", "roles", "service_account"]:
                if mandatoryScope not in normalizedClient["default_scopes"]:
                    warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have {} scope.".format(mandatoryScope)))
        case _:
            logger.trace("No controls for {}.", normalizedClient["tag"])
    return warns


def checkMappers(logger: Logger, normalizedClient: dict) -> list:
    """Checks if a given client has Protocol Mappers set up properly. Returns a list of warnings if not.

    Args:
		logger (Logger): Logger instance
        client (dict): Normalized Client Object

    Returns:
        list: Respective list of warnings should Protocol Mappers not be properly set up. Empty list otherwise.
    """
    warns = []
    for protocolMapper in normalizedClient["protocol_mappers"]:
        warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client has protocol mapper: {}.".format(protocolMapper["name"])))
    return warns


def checkWebOrigins(logger: Logger, normalizedClient: dict) -> list:
    """Checks if a given Client's Web Origins are set up propertly. Returns a list of warnings if not

    Args:
		logger (Logger): Logger instance
        normalizedClient (dict): Normalized Client Object

    Returns:
        list: List of warnings should Web Origins not be set up properly, empty list otherwise.
    """
    warns = []
    web_origins_count = len(normalizedClient["web_origins"])
    if normalizedClient["tag"] == "[SPA_PUBLIC]":
        if web_origins_count > 1:
            warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should only have 1 web origins but has {}.".format(web_origins_count)))
        elif web_origins_count == 0:
            warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have 1 web origins but has none."))
    else:
        if web_origins_count > 0:
            warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should not have web origins but has {}.".format(web_origins_count)))
    return warns


def checkPostLogoutRedirectUrls(logger: Logger, normalizedClient: dict, environment: str) -> list:
    """Checks if a given Client's PostLogoutRedirectUrls are set up properly. Returns a list of warnings if not.

    Args:
		logger (Logger): Logger instance
        normalizedClient (dict): Normalized Client Object
        environment (str): Environment name

    Returns:
        list: List of warnings should PostLogoutRedirectUrls not be set up properly, empty list otherwise.
    """
    client_post_logout_redirect_urls_count = len(normalizedClient["post_logout_redirect_uris"])
    
    if normalizedClient["tag"] == "[IDP_INTERNAL]":
        logger.debug("No controls for IDP_INTERNAL.")
        return []
    
    if normalizedClient["tag"] in [ "[CLIENT_CREDENTIALS]", "[MOBILE]", "[ROPC]" ]:
        if client_post_logout_redirect_urls_count > 0:
            return [getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should not have post_logout_redirect_url, but has {}.".format(client_post_logout_redirect_urls_count))]
    else:
        if not environment == "dev":
            if client_post_logout_redirect_urls_count == 0:
                return [getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have post_logout_redirect_url, but has none.")]
            elif client_post_logout_redirect_urls_count > 1:
                return [getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client should have only one post_logout_redirect_url, but has {}.".format(client_post_logout_redirect_urls_count))]
    return []


def checkSessionTimeout(logger: Logger, normalizedClient: str, realm: str) -> list:
    """Checks if a given Client's SessionTimeout is set up properly. Returns a list of warnings if not.

    Args:
		logger (Logger): Logger instance
        normalizedClient (str): Normalized Client Object
        realm (str): Realm name
    
    Returns:
        list: List of warnings should SessionTimeout not be set up properly, empty list otherwise.
    """
    warns = []
    effective_client_session_idle = normalizedClient["effective_client_session_idle"]
    realm_sso_session_idle_timeout = realm["ssoSessionIdleTimeout"]
    logger.debug("checkSessionTimeout(): client: {}, effective_client_session_idle: {} ({}), realm_sso_session_idle_timeout: {} ({})", normalizedClient["client_id"], effective_client_session_idle, type(effective_client_session_idle), realm_sso_session_idle_timeout, type(realm_sso_session_idle_timeout))
    if effective_client_session_idle > realm_sso_session_idle_timeout:
        warns.append(getWarn(logger=logger, normalizedClient=normalizedClient, issueLevel="WARN", issueDescription="This client has a session timeout greater than the Realm SSO idle timeout."))
    return warns


def storeWarns(logger: Logger, warns: list, outputFilePath: str):
	"""Saves warns to a JSON file

	Args:
		logger (Logger): Logger instance
		warns (list): List of warnings
		output_file_path (str): **File** Path in which to save the JSON Plan
	"""
	metadata = { "timestamp": utils.getLocalDatetime() }
	outputContent = { "metadata": metadata, "warns": warns }
	logger.info("Storing warns into: {}", outputFilePath)
	with open(outputFilePath, 'w') as f:
		json.dump(outputContent, f, indent=4)


def run(logger: Logger, outputPath: str, environment: str, config: dict) -> list:
	"""Runs CheckClients Report Generation for a given Environment

	Args:
		logger (Logger): Logger instance
		outputPath (str): **Directory** Path in which to save the JSON output
		environment (str): Environment in which to run Diff Report Generation
		config (dict): JSON configuration

	Returns:
		str: Process output
	"""
	logger.info("Checking Client for environment: {}", environment)
	outputFilePath = "{}/checkclients_{}.json".format(outputPath, environment)
	environmentWarns = getEnvWarns(logger=logger, environment=environment, config=config)
	storeWarns(logger=logger, warns=environmentWarns, outputFilePath=outputFilePath)
	return ""


def main(arguments):
	logger = Logger(os.path.basename(__file__), os.environ.get("LOG_LEVEL"), "/tmp/checkclients_report.log")
	parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('outputPath', type=str, help="Path to checkclients_*.json files.")
	args = parser.parse_args(arguments)
	config = utils.getConfig(logger=logger)
	for environment in utils.getEnvironments(logger=logger, config=config):
		run(logger=logger, outputPath=args.outputPath, environment=environment, config=config)
	logger.info("{} finished.".format(os.path.basename(__file__)))


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))