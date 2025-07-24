from blueprints.links import links_bp
from blueprints.clientinfo import clientinfo_bp
from blueprints.clientsactivity import clientsactivity_bp
from blueprints.checkclients import checkclients_bp
from blueprints.terraformcheck import terraformcheck_bp
from blueprints.clientcreation import clientcreation_bp
from flask import Flask, render_template
import os
import utils

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-secret-key'

# Load messages at startup
MESSAGES = utils.load_messages()

# Context processor to inject messages into all templates
@app.context_processor
def inject_messages():
    return dict(messages=MESSAGES)

@app.route('/', methods=["GET"])
def index():
    """Renders Index Page

    Returns:
        Template: Rendered Index Page HTML
    """
    logger = utils.getLogger()
    config = utils.getConfig(logger=logger)
    return render_template(
        "index.html",
        utils=utils,
        config=config
    )


@app.route('/health', methods=["GET"])
def getHealth():
    """Healthcheck Endpoint

    Returns:
        str: Signs of Life
    """
    return 'OK'


app.register_blueprint(links_bp)
app.register_blueprint(clientinfo_bp)
app.register_blueprint(clientsactivity_bp)
app.register_blueprint(checkclients_bp)
app.register_blueprint(terraformcheck_bp)
app.register_blueprint(clientcreation_bp)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
