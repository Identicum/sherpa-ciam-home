from flask import Blueprint, render_template
import checkclients_report
import utils

clientinfo_bp = Blueprint('clientinfo', __name__)


@clientinfo_bp.route('/clientinfo/<environment>', methods=["GET"])
def clientinfo_list_realms(environment: str):
    """Renders 'Client Info' Realm list template

    Args:
        environment (str): Environment name

    Returns:
        Template: Realm list rendered HTML Page
    """
    logger = utils.getLogger()
    data = utils.getData(logger=logger)
    return render_template(
        'clientinfo_list_realms.html',
        utils=utils,
        environment=environment,
        data=data
    )


@clientinfo_bp.route('/clientinfo/<environment>/<realmName>', methods=["GET"])
def clientinfo_list(environment: str, realmName: str):
    """Renders 'Client Info' Realm's Clients list Template

    Args:
        environment (str): Environment name
        realmName (str): Realm name

    Returns:
        Template: 'Client Info' Realm's Client List Rendered HTML Page
    """
    logger = utils.getLogger()
    data = utils.getData(logger=logger)
    clients = utils.getClients(logger=logger, environment=environment, realmName=realmName, data=data)
    return render_template(
        'clientinfo_list.html',
        utils=utils,
        environment=environment,
        realmName=realmName,
        clients=clients,
        data=data
    )


@clientinfo_bp.route('/clientinfo/<environment>/<realmName>/<client_id>', methods=["GET"])
def clientinfo_detail(environment: str, realmName: str, client_id: str):
    """Renders 'Client Info' Client Detail Page
 
    Args:
        environment (str): Environment name
        realmName (str): Realm name
        client_id (str): Client ID

    Returns:
        Template: 'Client Info' Client Detail Rendered HTML Page
    """
    logger = utils.getLogger()
    data = utils.getData(logger=logger)
    normalizedClient = utils.getClient(logger=logger, environment=environment, realmName=realmName, client_id=client_id, data=data)
    logger.trace("client: {}", normalizedClient)
    realm = utils.getRealm(logger=logger, environment=environment, realmName=realmName, data=data)
    warns = checkclients_report.getClientWarns(logger=logger, environment=environment, realmName=realmName, normalizedClient=normalizedClient, data=data)
    return render_template(
        'clientinfo_detail.html',
        utils=utils,
        environment=environment,
        realm=realm,
        normalizedClient=normalizedClient,
        warns=warns,
        data=data
    )
