from flask import Blueprint, render_template
from utils import *

clientinfo_bp = Blueprint('clientinfo', __name__)

@clientinfo_bp.route('/clientinfo/<env>/<realmName>', methods=["GET"])
def clientinfo_list(env, realmName):
    clients = getClients(env, realmName)
    return render_template(
        'clientinfo_list.html',
        realms=getRealms(),
        environments=getEnvironments(),
        env=env,
        realmName=realmName,
        clients=clients
    )

@clientinfo_bp.route('/clientinfo/<env>/<realmName>/<client_id>', methods=["GET"])
def clientinfo_detail(env, realmName, client_id):
    client = getClient(env, realmName, client_id)
    logger.trace("client: {}", client)
    realm = getRealm(env, realmName)
    # logger.trace("realm: {}", realm)
    return render_template(
        'clientinfo_detail.html',
        realms=getRealms(),
        environments=getEnvironments(),
        env=env,
        realm=realm,
        client=client
    )
