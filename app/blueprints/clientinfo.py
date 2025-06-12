from flask import Blueprint, render_template
from utils import *

clientinfo_bp = Blueprint('clientinfo', __name__)

logger = Logger(os.path.basename(__file__), os.environ.get("LOG_LEVEL"), "/tmp/python-flask.log")

@clientinfo_bp.route('/clientinfo/<env>', methods=["GET"])
def clientinfo_list_realms(env: str):
    """Renders 'Client Info' Realm list template

    Args:
        env (str): Environment name

    Returns:
        Template: Realm list rendered HTML Page
    """
    return render_template(
        'clientinfo_list_realms.html',
        realms=getRealms(logger),
        environments=getEnvironments(logger),
        env=env
    )


@clientinfo_bp.route('/clientinfo/<env>/<realmName>', methods=["GET"])
def clientinfo_list(env: str, realmName: str):
    """Renders 'Client Info' Realm's Clients list Template

    Args:
        env (str): Environment name
        realmName (str): Realm name

    Returns:
        Template: 'Client Info' Realm's Client List Rendered HTML Page
    """
    clients = getClients(env, realmName)
    return render_template(
        'clientinfo_list.html',
        realms=getRealms(logger),
        environments=getEnvironments(logger),
        env=env,
        realmName=realmName,
        clients=clients
    )


@clientinfo_bp.route('/clientinfo/<env>/<realmName>/<client_id>', methods=["GET"])
def clientinfo_detail(env: str, realmName: str, client_id: str):
    """Renders 'Client Info' Client Detail Page
 
    Args:
        env (str): Environment name
        realmName (str): Realm name
        client_id (str): Client ID

    Returns:
        Template: 'Client Info' Client Detail Rendered HTML Page
    """
    client = getClient(env, realmName, client_id)
    logger.trace("client: {}", client)
    realm = getRealm(env, realmName)
    # logger.trace("realm: {}", realm)
    return render_template(
        'clientinfo_detail.html',
        realms=getRealms(logger),
        environments=getEnvironments(logger),
        env=env,
        realm=realm,
        client=client
    )
