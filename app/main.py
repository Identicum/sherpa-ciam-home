from blueprints.links import links_bp
from sherpa.utils.basics import Logger
from blueprints.clientinfo import clientinfo_bp
from blueprints.checkclients import checkclients_bp
from blueprints.terraformcheck import terraformcheck_bp
from flask import Flask, render_template
from utils import *

app = Flask(__name__)

logger = Logger(os.path.basename(__file__), os.environ.get("LOG_LEVEL"), "/tmp/python-flask.log")

@app.route('/', methods=["GET"])
def index():
    return render_template("index.html", realms=getRealms(logger), environments=getEnvironments(logger))


@app.route('/health', methods=["GET"])
def getHealth():
    return 'OK'


app.register_blueprint(links_bp)
app.register_blueprint(clientinfo_bp)
app.register_blueprint(checkclients_bp)
app.register_blueprint(terraformcheck_bp)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
