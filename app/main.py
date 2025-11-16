import importlib
from flask import Flask, Blueprint, redirect, render_template, session
from flask_oidc import OpenIDConnect
from functools import wraps
from keycloak import KeycloakOpenID
import os
import utils
import requests

app = Flask(__name__)


issuer = os.environ.get('IDP_BASE_URL') + '/realms/' + os.environ.get('OIDC_REALM')
discovery_endpoint = issuer + '/.well-known/openid-configuration'
response = requests.get(discovery_endpoint)
response.raise_for_status()
discovery_doocument = response.json()

app.config.update({
    'SECRET_KEY': os.environ.get('SECRET_KEY', 'default-secret-key-change-me'),
    'OIDC_CLIENT_SECRETS': {
        'web': {
            'client_id': os.environ.get('OIDC_CLIENT_ID'),
            'client_secret': os.environ.get('OIDC_CLIENT_SECRET'),
            'auth_uri': discovery_doocument['authorization_endpoint'],
            'token_uri': discovery_doocument['token_endpoint'],
            'userinfo_uri': discovery_doocument['userinfo_endpoint'],
            'issuer': issuer
        }
    },
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OVERWRITE_REDIRECT_URI': os.environ.get('OIDC_REDIRECT_URI'),
    'OIDC_OPENID_REALM': os.environ.get('OIDC_REALM'),
    'OIDC_SCOPES': ['openid', 'email', 'profile']
})
oidc = OpenIDConnect(app)

def store_username_in_session(oidc):
    if oidc.user_loggedin and 'username' not in session:
        session['username'] = oidc.user_getfield('preferred_username')

def make_require_oidc_login(oidc):
    def require_oidc_login(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not oidc.user_loggedin:
                return oidc.redirect_to_auth_server()
            store_username_in_session(oidc)
            return f(*args, **kwargs)
        return decorated_function
    return require_oidc_login
utils.require_oidc_login = make_require_oidc_login(oidc)

# Load messages at startup
MESSAGES = utils.load_messages()

# Context processor to inject messages into all templates
@app.context_processor
def inject_messages():
    return dict(messages=MESSAGES)

@app.route('/', methods=["GET"])
def index():
    store_username_in_session(oidc)
    return render_template(
        "index.html",
        utils=utils
    )


@app.route('/health', methods=["GET"])
def getHealth():
    return 'OK'


@app.route('/login')
def login():
    return oidc.redirect_to_auth_server()


@app.route('/homeLogout')
@oidc.require_login
def homeLogout():
    refresh_token = oidc.get_refresh_token()
    utils.logger.debug("refresh_token: {}", refresh_token)
    oidc.logout()
    session.clear()
    utils.logger.debug("Local session logged out.")
    keycloak_openid = KeycloakOpenID(server_url="http://idp:8080/",
                                 client_id=os.environ.get('OIDC_CLIENT_ID'),
                                 realm_name=os.environ.get('OIDC_REALM'),
                                 client_secret_key=os.environ.get('OIDC_CLIENT_SECRET'))
    utils.logger.debug("Logging out IDP session.")
    keycloak_openid.logout(refresh_token=refresh_token)
    # post_logout_redirect_uri = os.environ.get('APP_BASE_URL') + url_for('logout_success')
    # utils.logger.debug("Redirecting to post_logout_redirect_uri: {}.", post_logout_redirect_uri)
    return redirect("/logout")


@app.route('/logoutSuccess')
def logout_success():
    """Handle logout callback from IDP"""
    return redirect('/')


# Dynamically load blueprints from ./blueprints dir
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
