from blueprints.links import links_bp
from blueprints.clientinfo import clientinfo_bp
from blueprints.checkclients import checkclients_bp
from blueprints.terraformcheck import terraformcheck_bp
from flask import Flask, render_template
from sherpa.utils.basics import Logger
import utils

app = Flask(__name__)

@app.route('/', methods=["GET"])
def index():
    """Renders Index Page

    Returns:
        Template: Rendered Index Page HTML
    """
    return render_template("index.html", utils=utils)


@app.route('/health', methods=["GET"])
def getHealth():
    """Healthcheck Endpoint

    Returns:
        str: Signs of Life
    """
    return 'OK'


app.register_blueprint(links_bp)
app.register_blueprint(clientinfo_bp)
app.register_blueprint(checkclients_bp)
app.register_blueprint(terraformcheck_bp)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
