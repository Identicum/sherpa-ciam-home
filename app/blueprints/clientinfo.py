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
    utils.logger.debug("Rendering clientinfo realm list for environment: {}", environment)
    return render_template(
        'clientinfo_list_realms.html',
        utils=utils,
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
    clients = utils.getClients(logger=utils.logger, environment=environment, realmName=realmName, config=utils.config)
    utils.logger.debug("Rendering clientinfo Client list for environment: {}, realm: {}", environment, realmName)
    return render_template(
        'clientinfo_list.html',
        utils=utils,
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
    normalizedClient = utils.getNormalizedClient(logger=utils.logger, environment=environment, realmName=realmName, client_id=client_id, config=utils.config)
    utils.logger.trace("client: {}", normalizedClient)
    realm = utils.getRealm(logger=utils.logger, environment=environment, realmName=realmName, config=utils.config)
    warns = checkclients_report.getClientWarns(logger=utils.logger, environment=environment, realmName=realmName, normalizedClient=normalizedClient, config=utils.config)
    secretVerification = ""
    if request.method == "POST":
        form_secret = request.form.get("secret", "")
        utils.logger.trace("Processing form submission with secret: {}", form_secret)
        if form_secret and form_secret.strip()==normalizedClient.get('client_secret'):
            secretVerification = "OK"
        else:
            secretVerification = "INCORRECT"
    utils.logger.debug("secretVerification: {}", secretVerification)
    utils.logger.debug("Rendering clientinfo Client detail for environment: {}, realm: {}, client_id: {}", environment, realmName, client_id)
    return render_template(
        'clientinfo_detail.html',
        utils=utils,
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
    normalizedClient = utils.getNormalizedClient(logger=utils.logger, environment=environment, realmName=realmName, client_id=client_id, config=utils.config)
    utils.logger.trace("client: {}", normalizedClient)
    realm = utils.getRealm(logger=utils.logger, environment=environment, realmName=realmName, config=utils.config)

    to_addr = normalizedClient["owner_email"]
    subject = "IDP - Client info - {}".format(environment)
    body = render_template(
        'email/clientinfo.html',
        utils=utils,
        environment=environment,
        realm=realm,
        normalizedClient=normalizedClient
    )
    email_status = "OK"
    try :
        utils.smtpSend(logger=utils.logger, subject=subject, body=body, to_addr=to_addr)
    except Exception as e:
        utils.logger.error("Error sending email: {}", e)
        email_status = "ERROR"
    return render_template(
        'clientinfo_sendemail_feedback.html',
        utils=utils,
        environment=environment,
        realm=realm,
        normalizedClient=normalizedClient,
        email_status=email_status
    )
