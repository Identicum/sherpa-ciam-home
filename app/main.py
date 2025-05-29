from blueprints.links import links_bp
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
