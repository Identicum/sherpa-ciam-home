import importlib
from flask import Flask, render_template, Blueprint
from flask_oidc import OpenIDConnect
import os
import utils
import requests

app = Flask(__name__)

def get_oidc_config():
    """Fetch OIDC configuration from well-known endpoint"""
    issuer = os.environ.get('OIDC_ISSUER')
    if not issuer:
        raise ValueError("OIDC_ISSUER environment variable is required")
    
    try:
        well_known_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
        response = requests.get(well_known_url)
        response.raise_for_status()
        config = response.json()
        
        return {
            'auth_uri': config['authorization_endpoint'],
            'token_uri': config['token_endpoint'],
            'userinfo_uri': config['userinfo_endpoint'],
        }
    except requests.RequestException as e:
        print(f"Error fetching OIDC configuration: {e}")
        # Fallback to environment variables if provided
        return {
            'auth_uri': os.environ.get('OIDC_AUTH_URI'),
            'token_uri': os.environ.get('OIDC_TOKEN_URI'),
            'userinfo_uri': os.environ.get('OIDC_USERINFO_URI'),
        }

# Fetch OIDC configuration
oidc_endpoints = get_oidc_config()

app.config.update({
    'SECRET_KEY': os.environ.get('SECRET_KEY', 'default-secret-key-change-me'),
    'OIDC_CLIENT_SECRETS': {
        'web': {
            'client_id': os.environ.get('OIDC_CLIENT_ID'),
            'client_secret': os.environ.get('OIDC_CLIENT_SECRET'),
            'auth_uri': oidc_endpoints['auth_uri'],
            'token_uri': oidc_endpoints['token_uri'],
            'userinfo_uri': oidc_endpoints['userinfo_uri'],
            'issuer': os.environ.get('OIDC_ISSUER')
        }
    },
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OVERWRITE_REDIRECT_URI': os.environ.get('OIDC_REDIRECT_URI', 'http://localhost:5000/oidc_callback'),
    'OIDC_OPENID_REALM': os.environ.get('OIDC_REALM', 'your-realm'),
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
})
oidc = OpenIDConnect(app)
utils.require_oidc_login = utils.make_require_oidc_login(oidc)

# Load messages at startup
MESSAGES = utils.load_messages()

# Context processor to inject messages into all templates
@app.context_processor
def inject_messages():
    return dict(messages=MESSAGES)

@app.route('/', methods=["GET"])
def index():
    """Renders Index Page with user info

    Returns:
        Template: Rendered Index Page HTML
    """
    logger = utils.getLogger()
    config = utils.getConfig(logger=logger)
    # user_info = oidc.user_getinfo(['email', 'sub', 'name'])
    return render_template(
        "index.html",
        utils=utils,
        config=config
        # ,
        # user_info=user_info
    )


@app.route('/health', methods=["GET"])
def getHealth():
    """Healthcheck Endpoint

    Returns:
        str: Signs of Life
    """
    return 'OK'

@app.route('/login')
def login():
    """Trigger OIDC login"""
    return oidc.redirect_to_auth_server()

@app.route('/logout')
def logout():
    """Logout and clear session"""
    oidc.logout()
    return 'Logged out'

# Dinamycly load blueprints from ./blueprints dir
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
