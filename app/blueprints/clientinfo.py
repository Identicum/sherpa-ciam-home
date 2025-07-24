from flask import Blueprint, render_template, request
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
    config = utils.getConfig(logger=logger)
    return render_template(
        'clientinfo_list_realms.html',
        utils=utils,
        config=config,
        environment=environment
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
    config = utils.getConfig(logger=logger)
    clients = utils.getClients(logger=logger, environment=environment, realmName=realmName, config=config)
    return render_template(
        'clientinfo_list.html',
        utils=utils,
        config=config,
        environment=environment,
        realmName=realmName,
        clients=clients
    )


@clientinfo_bp.route('/clientinfo/<environment>/<realmName>/<client_id>', methods=["GET", "POST"])
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
    config = utils.getConfig(logger=logger)
    normalizedClient = utils.getNormalizedClient(logger=logger, environment=environment, realmName=realmName, client_id=client_id, config=config)
    logger.trace("client: {}", normalizedClient)
    realm = utils.getRealm(logger=logger, environment=environment, realmName=realmName, config=config)
    warns = checkclients_report.getClientWarns(logger=logger, environment=environment, realmName=realmName, normalizedClient=normalizedClient, config=config)
    secretVerification = ""
    if request.method == "POST":
        form_secret = request.form.get("secret", "")
        logger.trace("Processing form submission with secret: {}", form_secret)
        if form_secret and form_secret.strip()==normalizedClient.get('client_secret'):
            secretVerification = "OK"
        else:
            secretVerification = "INCORRECT"
    logger.debug("secretVerification: {}", secretVerification)
    return render_template(
        'clientinfo_detail.html',
        utils=utils,
        config=config,
        environment=environment,
        realm=realm,
        normalizedClient=normalizedClient,
        warns=warns,
        secretVerification=secretVerification
    )


@clientinfo_bp.route('/clientinfo/<environment>/<realmName>/<client_id>/sendclientinfo', methods=["GET"])
def clientinfo_send(environment: str, realmName: str, client_id: str):
    """Send Client information to owner
 
    Args:
        environment (str): Environment name
        realmName (str): Realm name
        client_id (str): Client ID

    Returns:
        Feedback page once email was sent.
    """
    logger = utils.getLogger()
    config = utils.getConfig(logger=logger)
    normalizedClient = utils.getNormalizedClient(logger=logger, environment=environment, realmName=realmName, client_id=client_id, config=config)
    logger.trace("client: {}", normalizedClient)
    realm = utils.getRealm(logger=logger, environment=environment, realmName=realmName, config=config)

    to_addr = normalizedClient["owner_email"]
    subject = "IDP - Client info - {}".format(environment)
    body = render_template(
        'email/clientinfo.html',
        utils=utils,
        config=config,
        environment=environment,
        realm=realm,
        normalizedClient=normalizedClient
    )
    email_status = "OK"
    try :
        utils.smtpSend(logger=logger, subject=subject, body=body, to_addr=to_addr)
    except Exception as e:
        logger.error("Error sending email: {}", e)
        email_status = "ERROR"
    return render_template(
        'clientinfo_sendemail_feedback.html',
        utils=utils,
        config=config,
        environment=environment,
        realm=realm,
        normalizedClient=normalizedClient,
        email_status=email_status
    )
