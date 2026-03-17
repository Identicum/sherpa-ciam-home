from flask import Flask, Blueprint, redirect, render_template, request, session, url_for
from authlib.integrations.flask_client import OAuth
from functools import wraps
import importlib
import os
import time
import requests
from sherpa.keycloak.keycloak_lib import SherpaKeycloakOpenID
import utils

app = Flask(__name__)

issuer = os.environ.get('IDP_BASE_URL') + '/realms/' + os.environ.get('OIDC_REALM')
discovery_endpoint = issuer + '/.well-known/openid-configuration'
response = requests.get(discovery_endpoint)
response.raise_for_status()
discovery_document = response.json()

app.config.update({
    'SECRET_KEY': os.environ.get('SECRET_KEY', 'default-secret-key-change-me'),
})

oauth = OAuth(app)
oauth.register(
    name='oidc',
    client_id=os.environ.get('OIDC_CLIENT_ID'),
    client_secret=os.environ.get('OIDC_CLIENT_SECRET'),
    client_kwargs={'scope': 'openid email profile'},
    authorize_url=discovery_document['authorization_endpoint'],
    access_token_url=discovery_document['token_endpoint'],
    jwks_uri=discovery_document['jwks_uri'],
)


# ---------- Token helpers ----------

def _get_token() -> dict:
    """Return the token dict stored in the session, or an empty dict if absent."""
    return session.get('token') or {}

def _get_refresh_token() -> str | None:
    """Return the refresh_token string from the session, or None."""
    return _get_token().get('refresh_token')

def _get_access_token() -> str | None:
    """Return the access_token string from the session, or None."""
    return _get_token().get('access_token')

def _is_access_token_expired() -> bool:
    """
    Return True if the access token is missing or about to expire.
    Uses a 30-second safety margin to account for clock skew.
    """
    expires_at = _get_token().get('expires_at')
    if not expires_at:
        return True
    return time.time() >= (expires_at - 30)

def _is_refresh_token_expired() -> bool:
    """
    Return True if the refresh token has expired or is about to expire.

    Keycloak includes 'refresh_expires_in' (seconds) in the token response.
    Authlib does not compute an absolute expiry for it, so we derive it from
    '_obtained_at', which we store at token-save time. Uses a 30-second margin.
    Returns False if the required fields are absent, deferring to the IdP.
    """
    token = _get_token()
    refresh_expires_in = token.get('refresh_expires_in')
    obtained_at = token.get('_obtained_at')
    if not refresh_expires_in or not obtained_at:
        return False
    return time.time() >= (obtained_at + int(refresh_expires_in) - 30)

def _save_token(token: dict) -> None:
    """
    Normalize and persist a token dict to the session.
    Computes 'expires_at' from 'expires_in' if not already present,
    and records '_obtained_at' for refresh token expiry calculation.
    """
    if 'expires_in' in token and 'expires_at' not in token:
        token['expires_at'] = time.time() + int(token['expires_in'])
    token['_obtained_at'] = time.time()
    session['token'] = token

def _do_refresh() -> bool:
    """
    Attempt to renew the access token using the refresh token (RFC 6749 §6).
    Clears cached userinfo on success so it is re-fetched with the new token.
    Returns True on success, False on any failure.
    """
    refresh_token = _get_refresh_token()
    if not refresh_token:
        utils.logger.debug("No refresh token found in session.")
        return False

    if _is_refresh_token_expired():
        utils.logger.debug("Refresh token has expired.")
        return False

    try:
        resp = requests.post(
            discovery_document['token_endpoint'],
            data={
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
                'client_id': os.environ.get('OIDC_CLIENT_ID'),
                'client_secret': os.environ.get('OIDC_CLIENT_SECRET'),
            },
            timeout=10,
        )
        if resp.status_code >= 400:
            utils.logger.debug("Token refresh rejected by IdP (HTTP {}).", resp.status_code)
            return False

        _save_token(resp.json())
        session.pop('username', None)
        session.pop('userinfo', None)
        utils.logger.debug("Token refreshed successfully.")
        return True

    except Exception as e:
        utils.logger.debug("Unexpected error during token refresh: {}", e)
        return False

def _idp_logout(refresh_token: str) -> None:
    """
    Revoke the IdP session by calling Keycloak's logout endpoint.
    Failures are logged but do not raise.
    """
    try:
        SherpaKeycloakOpenID(
            logger=utils.logger,
            properties=utils.properties,
            server_url=os.environ.get('IDP_BASE_URL'),
            realm_name=os.environ.get('OIDC_REALM'),
            client_id=os.environ.get('OIDC_CLIENT_ID'),
            client_secret_key=os.environ.get('OIDC_CLIENT_SECRET'),
        ).logout(refresh_token=refresh_token)
        utils.logger.debug("IdP session revoked.")
    except Exception as e:
        error_str = str(e)
        if 'Session not active' in error_str or ('200' in error_str and 'Logging out' in error_str):
            utils.logger.debug("IdP session was already inactive (expected when session expires server-side).")
        else:
            utils.logger.warn("Failed to revoke IdP session: {}", e)

def _ensure_valid_token() -> bool:
    """
    Verify the session token and renew it silently if expired.

    Returns:
      True  — a valid access token is available.
      False — no session exists or renewal failed.
    """
    if not session.get('token'):
        return False
    if not _is_access_token_expired():
        return True
    utils.logger.debug("Access token expired. Attempting renewal.")
    return _do_refresh()


# ---------- Userinfo ----------

def store_username_in_session() -> None:
    """
    Resolve and cache the authenticated user's display name in session['username'].
    Tries the userinfo endpoint first; falls back to cached ID token claims.
    """
    if 'username' in session:
        return
    token = session.get('token')
    if not token:
        return
    try:
        userinfo = oauth.oidc.userinfo(token=token)
        session['userinfo'] = dict(userinfo)
        session['username'] = (
            session['userinfo'].get('preferred_username')
            or session['userinfo'].get('email')
            or session['userinfo'].get('sub')
        )
        return
    except Exception:
        pass
    claims = session.get('claims') or {}
    session['username'] = (
        claims.get('preferred_username')
        or claims.get('email')
        or claims.get('sub')
    )


# ---------- Auth decorator ----------

def make_require_oidc_login():
    """
    Return a decorator that enforces OIDC authentication on a route.
    Silently renews an expired access token when possible; otherwise performs
    a full logout and redirects to /login.
    Assigned to utils.require_oidc_login so blueprints can use it via @utils.require_oidc_login.
    """
    def require_oidc_login(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('token'):
                return redirect('/login')
            store_username_in_session()
            return f(*args, **kwargs)
        return decorated_function
    return require_oidc_login

utils.require_oidc_login = make_require_oidc_login()


def get_valid_access_token():
    """Return a valid access token for the logged-in user, or None. Refreshes if expired."""
    if not _ensure_valid_token():
        return None
    return _get_access_token()


utils.get_valid_access_token = get_valid_access_token

MESSAGES = utils.load_messages()

@app.context_processor
def inject_messages():
    return dict(messages=MESSAGES)

# ---------- Middlewares ----------
@app.before_request
def check_session():
    """
    If the user has an active session but the token cannot be renewed,
    clear the session so they return to an unauthenticated state.
    Does not redirect, allowing access to public routes.
    """
    if request.endpoint == 'static':
        return None
    if not session.get('token'):
        return None

    refresh_token = _get_refresh_token()
    result = _ensure_valid_token()
    if result is not True:
        if refresh_token:
            _idp_logout(refresh_token)
        session.clear()

# ---------- Routes ----------

@app.route('/', methods=['GET'])
def index():
    store_username_in_session()
    return render_template('index.html', utils=utils)


@app.route('/health', methods=['GET'])
def getHealth():
    return 'OK'


@app.route('/login')
def login():
    configured = os.environ.get('OIDC_REDIRECT_URI')
    redirect_uri = configured if configured else url_for('oidc_callback', _external=True)
    return oauth.oidc.authorize_redirect(redirect_uri)


@app.route('/oidc_callback')
def oidc_callback():
    """Exchange the authorization code for tokens and establish the local session."""
    token = oauth.oidc.authorize_access_token()
    _save_token(token)
    try:
        claims = oauth.oidc.parse_id_token(token, nonce=session.get('nonce'))
        session['claims'] = dict(claims)
    except Exception:
        session.pop('claims', None)
    store_username_in_session()
    return redirect('/')


@app.route('/homeLogout')
@utils.require_oidc_login
def homeLogout():
    """Log out the user from both the local session and the IdP."""
    refresh_token = _get_refresh_token()
    session.clear()
    utils.logger.debug("Local session cleared.")
    if refresh_token:
        _idp_logout(refresh_token)
    return redirect('/logoutSuccess')


@app.route('/logoutSuccess')
def logout_success():
    """Handle the post-logout redirect."""
    return redirect('/')


# ---------- Blueprint loader ----------

blueprints_dir = 'blueprints'
blueprint_path = os.path.join(os.path.dirname(__file__), blueprints_dir)

for filename in os.listdir(blueprint_path):
    if filename.endswith('.py') and not filename.startswith('__'):
        module_name = filename[:-3]
        try:
            module = importlib.import_module(f'blueprints.{module_name}')
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, Blueprint):
                    app.register_blueprint(attr)
                    print(f"Blueprint '{attr.name}' registered from {filename}")
                    break
        except Exception as e:
            print(f"Error loading {filename}: {e}")


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')