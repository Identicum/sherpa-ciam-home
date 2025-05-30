from flask import Blueprint, render_template
from utils import *

clientinfo_bp = Blueprint('clientinfo', __name__)

@clientinfo_bp.route('/clientinfo/<env>/<realm>', methods=["GET"])
def clientinfo_list(env, realm):
    clients = getClients(env, realm)
    return render_template('clientinfo_list.html', realms=getRealms(), environments=getEnvironments(), env=env, realm=realm, clients=clients)

@clientinfo_bp.route('/clientinfo/<env>/<realm>/<client_id>', methods=["GET"])
def clientinfo_detail(env, realm, client_id):
    client = getClient(env, realm, client_id)
    return render_template('clientinfo_list.html', realms=getRealms(), environments=getEnvironments(), env=env, realm=realm, client_id=client_id, client=client)
