from flask import Blueprint, render_template
import json
import utils

links_bp = Blueprint('links', __name__)

with open('/data/links.json') as linksFile:
    linksJson = json.load(linksFile)


@links_bp.route('/links/<env>', methods=["GET"])
def links(env: str):
    """Renders URL List Page

    Args:
        env (str): Environment Name

    Returns:
        Template: URL List Page Rendered HTML Page
    """
    links = linksJson.get(env, [])
    return render_template(
        'links.html',
        utils=utils,
        links=links,
        env=env
    )

