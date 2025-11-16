from flask import Blueprint, render_template
import json
import utils

links_bp = Blueprint('links', __name__)


@links_bp.route('/links/<environment>', methods=["GET"])
def links(environment: str):
    """Renders URL List Page

    Args:
        environment (str): Environment Name

    Returns:
        Template: URL List Page Rendered HTML Page
    """
    with open('/conf/links.json') as linksFile:
        linksJson = json.load(linksFile)
    links = linksJson.get(environment, [])
    return render_template(
        'links.html',
        utils=utils,
        links=links,
        environment=environment
    )

