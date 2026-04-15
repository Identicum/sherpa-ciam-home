from flask import session
import jwt
import os
import requests
from sherpa.utils.basics import Properties
from sherpa.utils.basics import Logger
import time

ROLES_CLAIM = os.environ.get('OIDC_ROLES_CLAIM', 'sherpa_ciam_home_roles')


def buildRole(environment: str, module: str) -> str:
    """Build a role name from an environment and module name.
    
    Args:
        environment (str): Environment name (e.g. 'local', 'dev', 'prod')
        module (str): Module/blueprint name (e.g. 'deployments', 'clientinfo')

    Returns:
        str: Role name in the format '{environment}_{module}'
    """
    return f"{environment}_{module}"


def storeResponseInSession(logger: Logger, token_response: dict) -> None:
    """
    Persist token_endpoint response in session.
    """
    logger.debug("Starting.")
    storeTokensInSession(logger=logger, token_response=token_response)
    storeUsernameInSession(logger=logger, token_response=token_response)
    storeRolesInSession(logger=logger, token_response=token_response)
    logger.trace("session contents: {}", dict(session))


def storeUsernameInSession(logger: Logger, token_response: dict) -> None:
    """
    Persist username in session.
    """
    logger.trace("Starting, token_response: {}", token_response)
    userinfo = token_response.get('userinfo', {})
    username = (
        userinfo.get('preferred_username')
        or userinfo.get('email')
        or userinfo.get('sub')
    )
    if username is None:
        logger.debug("Could not extract username from userinfo: {}", userinfo)
        id_token = token_response.get('id_token', {})
        id_token_json = jwt.decode(id_token, options={"verify_signature": False})
        username = (
            id_token_json.get('preferred_username')
            or id_token_json.get('email')
            or id_token_json.get('sub')
        )
        if username is None:
            logger.debug("Could not extract username from id_token: {}", id_token_json)
            access_token = token_response.get('access_token', {})
            access_token_json = jwt.decode(access_token, options={"verify_signature": False})
            username = (
                access_token_json.get('preferred_username')
                or access_token_json.get('email')
                or access_token_json.get('sub')
                or "unknown_user"
            )
    session['username'] = username
    logger.debug("Username stored in session: '{}'", username)


def storeRolesInSession(logger: Logger, token_response: dict) -> None:
    """
    Persist roles in session.
    """
    logger.trace("Starting.")
    userinfo = token_response.get('userinfo', {})
    roles = userinfo.get(ROLES_CLAIM)
    if roles is None:
        logger.trace("Could not extract roles from userinfo: {}", userinfo)
        id_token = token_response.get('id_token', {})
        id_token_json = jwt.decode(id_token, options={"verify_signature": False})
        roles = id_token_json.get(ROLES_CLAIM)
        if roles is None:
            logger.trace("Could not extract roles from id_token: {}", id_token_json)
            access_token = token_response.get('access_token', {})
            access_token_json = jwt.decode(access_token, options={"verify_signature": False})
            roles = ( access_token_json.get(ROLES_CLAIM) or [] )
    session['roles'] = roles
    logger.debug("Roles stored in session: '{}'", roles)


def storeTokensInSession(logger: Logger, token_response: dict) -> None:
    """
    Persist tokens and expiration in session.
    """
    logger.debug("Starting.")
    if 'access_token' in token_response:
        session['access_token'] = token_response['access_token']
        if 'expires_in' in token_response:
            session['access_token_expiration'] = time.time() + int(token_response['expires_in'])
    if 'refresh_token' in token_response:
        session['refresh_token'] = token_response['refresh_token']
        if 'refresh_expires_in' in token_response:
            session['refresh_token_expiration'] = time.time() + int(token_response['refresh_expires_in'])
    logger.trace("session contents: {}", dict(session))


def isAccessTokenExpired() -> bool:
    """
    Return True if the access token is missing or about to expire.
    Uses a 30-second safety margin to account for clock skew.
    """
    expires_at = session.get('access_token_expiration')
    if not expires_at:
        return True
    return time.time() >= (expires_at - 30)


def isRefreshTokenExpired() -> bool:
    """
    Return True if the refresh token has expired or is about to expire.

    Keycloak includes 'refresh_expires_in' (seconds) in the token response.
    Authlib does not compute an absolute expiry for it, so we derive it from
    '_obtained_at', which we store at token-save time. Uses a 30-second margin.
    Returns False if the required fields are absent, deferring to the IdP.
    """
    expires_at = session.get('refresh_token_expiration')
    if not expires_at:
        return True
    return time.time() >= (expires_at - 30)


def refreshToken(logger: Logger, discovery_document: dict) -> bool:
    """
    Attempt to renew the access token using the refresh token (RFC 6749 §6).
    Clears cached userinfo on success so it is re-fetched with the new token.
    Returns True on success, False on any failure.
    """
    logger.trace("Starting token refresh.")
    refresh_token = session.get('refresh_token')
    if not refresh_token:
        logger.debug("No refresh token found in session.")
        return False
    if isRefreshTokenExpired():
        logger.debug("Refresh token has expired.")
        return False
    try:
        token_response = requests.post(
            discovery_document['token_endpoint'],
            data={
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
                'client_id': os.environ.get('OIDC_CLIENT_ID'),
                'client_secret': os.environ.get('OIDC_CLIENT_SECRET'),
            },
            timeout=10,
        )
        if token_response.status_code >= 400:
            logger.debug("Token refresh rejected by IdP (HTTP {}).", token_response.status_code)
            return False
        storeTokensInSession(logger=logger, token_response=token_response.json())
        session.pop('username', None)
        session.pop('userinfo', None)
        logger.debug("Token refreshed successfully.")
        return True
    except Exception as e:
        logger.error("Unexpected error during token refresh: {}", e)
        return False


def ensureValidToken(logger: Logger, discovery_document: dict) -> bool:
    """
    Verify the session token and renew it silently if expired.

    Returns:
      True  — a valid access token is available.
      False — no session exists or renewal failed.
    """
    logger.trace("Ensuring valid token.")
    if not session.get('token'):
        return False
    if not isAccessTokenExpired():
        return True
    logger.debug("Access token expired. Attempting renewal.")
    return refreshToken(logger, discovery_document)


def hasRole(logger: Logger, required_role: str) -> bool:
    """
    Return True if the user session has the required role.
    """
    logger.trace("Ensuring session has role: '{}'", required_role)
    roles = session.get('roles', [])
    return required_role in roles


def getCurrentAccessToken(discovery_document: dict):
    """Return a valid access token for the logged-in user, or None. Refreshes if expired."""
    if not ensureValidToken(discovery_document):
        return None
    return session.get('access_token')
