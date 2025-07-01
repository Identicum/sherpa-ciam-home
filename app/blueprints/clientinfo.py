from flask import Blueprint, render_template
import checkclients_report
import utils

clientinfo_bp = Blueprint('clientinfo', __name__)

logger = utils.logger

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
        utils=utils,
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
    clients = utils.getClients(env, realmName)
    return render_template(
        'clientinfo_list.html',
        utils=utils,
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
    client = utils.getClient(env, realmName, client_id)
    logger.trace("client: {}", client)
    realm = utils.getRealm(env, realmName)
    warns = checkclients_report.getClientWarns(logger=logger, env=env, realmName=realmName, client=client)
    return render_template(
        'clientinfo_detail.html',
        utils=utils,
        env=env,
        realm=realm,
        client=client,
        warns=warns
    )
