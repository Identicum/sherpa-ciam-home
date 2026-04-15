import auth_utils
from flask import Blueprint, Flask, redirect, render_template, request, session, url_for
from authlib.integrations.flask_client import OAuth
from functools import wraps
import importlib
import os
import requests
from sherpa.keycloak.keycloak_lib import SherpaKeycloakOpenID
from sherpa.utils.basics import Logger
from sherpa.utils.basics import Properties
import utils

app = Flask(__name__)

app.properties = Properties("/local.properties", "/local.properties")
app.logger = Logger(
    name="sherpa-home-main", 
    log_level=os.environ.get("LOG_LEVEL"), 
    log_path="/tmp/python-flask.log",
    stdout=False
)
app.json_config = utils.getConfig(logger=app.logger)
app.messages = utils.load_messages()
app.unrestricted_environments = os.environ.get('UNRESTRICTED_ENVIRONMENTS', 'local').split(',')

issuer = os.environ.get('IDP_BASE_URL') + '/realms/' + os.environ.get('OIDC_REALM')
discovery_endpoint = issuer + '/.well-known/openid-configuration'
response = requests.get(discovery_endpoint)
response.raise_for_status()
app.discovery_document = response.json()

app.config.update({
    'SECRET_KEY': os.environ.get('SECRET_KEY', 'default-secret-key-change-me'),
})

oauth = OAuth(app)
oauth.register(
    name='oidc',
    client_id=os.environ.get('OIDC_CLIENT_ID'),
    client_secret=os.environ.get('OIDC_CLIENT_SECRET'),
    client_kwargs={'scope': 'openid email profile'},
    authorize_url=app.discovery_document['authorization_endpoint'],
    access_token_url=app.discovery_document['token_endpoint'],
    jwks_uri=app.discovery_document['jwks_uri'],
)


def _idp_logout(refresh_token: str) -> None:
    """
    Revoke the IdP session by calling Keycloak's logout endpoint.
    Failures are logged but do not raise.
    """
    try:
        SherpaKeycloakOpenID(
            logger=app.logger,
            properties=utils.properties,
            server_url=os.environ.get('IDP_BASE_URL'),
            realm_name=os.environ.get('OIDC_REALM'),
            client_id=os.environ.get('OIDC_CLIENT_ID'),
            client_secret_key=os.environ.get('OIDC_CLIENT_SECRET'),
        ).logout(refresh_token=refresh_token)
        app.logger.debug("IdP session revoked.")
    except Exception as e:
        error_str = str(e)
        if 'Session not active' in error_str or ('200' in error_str and 'Logging out' in error_str):
            app.logger.debug("IdP session was already inactive (expected when session expires server-side).")
        else:
            app.logger.warn("Failed to revoke IdP session: {}", e)


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
            if not session.get('access_token'):
                return redirect('/login')
            return f(*args, **kwargs)
        return decorated_function
    return require_oidc_login

utils.require_oidc_login = make_require_oidc_login()


@app.context_processor
def inject_messages():
    return dict(messages=app.messages)

# ---------- Middlewares ----------
@app.before_request
def check_session():
    """
    If the user has an active session but the token cannot be renewed,
    clear the session so they return to an unauthenticated state.
    Does not redirect, allowing access to public routes.
    """
    app.logger.trace("Checking session. Endpoint: {}", request.endpoint)
    if request.endpoint in ['static', 'health']:
        return None
    if not session.get('access_token'):
        app.logger.debug("Access token not found. No session present.")
        return None
    if auth_utils.isAccessTokenExpired():
        if auth_utils.isRefreshTokenExpired():
            app.logger.debug("Refresh token expired, clearing session.")
            session.clear()
            return None
        else:
            app.logger.debug("Access token expired, attempting to refresh.")
            if not auth_utils.refreshToken(logger=app.logger, discovery_document=app.discovery_document):
                app.logger.warn("Failed to refresh access token, clearing session.")
                session.clear()
                return None

# ---------- Routes ----------
@app.route('/', methods=['GET'])
def index():
    app.logger.trace("Starting")
    return render_template('index.html', logger=app.logger, config=app.json_config, utils=utils)


@app.route('/health', methods=['GET'])
def health():
    app.logger.trace("Starting")
    return 'OK'


@app.route('/login')
def login():
    app.logger.trace("Starting")
    configured = os.environ.get('OIDC_REDIRECT_URI')
    redirect_uri = configured if configured else url_for('oidc_callback', _external=True)
    return oauth.oidc.authorize_redirect(redirect_uri)


@app.route('/oidc_callback')
def oidc_callback():
    """Exchange the authorization code for tokens and establish the local session."""
    app.logger.trace("OIDC callback initiated.")
    token_response = oauth.oidc.authorize_access_token()
    auth_utils.storeResponseInSession(logger=app.logger, token_response=token_response)
    app.logger.debug("OIDC callback processed, session: {}", session)
    return redirect('/')


@app.route('/homeLogout')
@utils.require_oidc_login
def home_logout():
    """Log out the user from both the local session and the IdP."""
    app.logger.trace("Starting")
    refresh_token = session.get('refresh_token')
    session.clear()
    app.logger.debug("Local session cleared.")
    if refresh_token:
        _idp_logout(refresh_token)
    return redirect('/logoutSuccess')


@app.route('/logoutSuccess')
def logout_success():
    """Handle the post-logout redirect."""
    app.logger.trace("Starting")
    return redirect('/')


# ---------- Blueprint loader ----------

blueprints_dir = 'blueprints'
blueprint_path = os.path.join(os.path.dirname(__file__), blueprints_dir)
app.logger.trace("Processing blueprints")
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