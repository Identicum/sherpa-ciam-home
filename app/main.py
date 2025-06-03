from blueprints.links import links_bp
from blueprints.clientinfo import clientinfo_bp
from blueprints.checkclients import checkclients_bp
from flask import Flask, render_template
from utils import *

app = Flask(__name__)

@app.route('/', methods=["GET"])
def index():
    return render_template("index.html", realms=getRealms(), environments=getEnvironments())

@app.route('/health', methods=["GET"])
def getHealth():
    return 'OK'

app.register_blueprint(links_bp)
app.register_blueprint(clientinfo_bp)
app.register_blueprint(checkclients_bp)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
