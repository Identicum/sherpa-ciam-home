import json
from flask import Blueprint, render_template
from utils import *

links_bp = Blueprint('links', __name__)

logger = Logger(os.path.basename(__file__), os.environ.get("LOG_LEVEL"), "/tmp/python-flask.log")

with open('/data/links.json') as linksFile:
    linksJson = json.load(linksFile)


@links_bp.route('/links/<env>', methods=["GET"])
def links(env):
    links = linksJson.get(env, [])
    return render_template(
        'links.html',
        realms=getRealms(logger),
        environments=getEnvironments(logger),
        links=links,
        env=env
    )

