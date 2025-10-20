from flask import Blueprint, render_template, request
import json
import utils

user_sessions_lookup_bp = Blueprint('user-sessions-lookup', __name__)


@user_sessions_lookup_bp.route('/user-sessions-lookup/<environment>', methods=["GET"])
def user_sessions_lookup_realm_list(environment: str):
    """Renders Realm List for User Sessions Lookup Form

    Returns:
        Template: Rendered HTML page with Realms list, each leading to it's corresponding User Sessions Lookup Form
    """
    logger = utils.getLogger()
    config = utils.getConfig(logger=logger)

    return render_template(
        'user_sessions_lookup_list_realms.html',
        utils=utils,
        environment=environment,
        config=config
    )

@user_sessions_lookup_bp.route('/user-sessions-lookup/<environment>/<realm>', methods=["GET"])
def user_sessions_lookup_form(environment: str, realm: str):
    """Renders User Sessions Lookup Form for the provided Environment and Realm

    Returns:
        Template: Rendered HTML page with User Sessions Lookup Form.
    """
    logger = utils.getLogger()
    config = utils.getConfig(logger=logger)

    # Render form
    logger.info(f"No Incluye identifier")
    return render_template(
        'user_sessions_lookup_form.html',
        environment=environment,
        realm=realm,
        utils=utils,
        config=config
    )


@user_sessions_lookup_bp.route('/user-sessions-lookup/<environment>/<realm>/<identifier>', methods=["GET"])
def user_sessions_lookup_detail(environment: str, realm: str, identifier: str):
    """Renders the User Sessions Lookup result page for the provided Environment, Realm and Provided User

    Returns:
        Template: Rendered HTML page containing the User Session Lookup Result
    """
    logger = utils.getLogger()
    config = utils.getConfig(logger=logger)

    # Fetch user's sessions
    response = utils.getUserSessions(environment, realm, identifier, config)
    logger.info(f"getUserSessions: {response}")
    return render_template(
        'user_sessions_lookup_detail.html',
        utils=utils,
        success=response.get('success', False),
        sessions=response.get('sessions', []),
        message=response.get('message', ''),
        config=config,
        identifier=identifier
    )
