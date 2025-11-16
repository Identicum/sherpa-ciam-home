from flask import Blueprint, render_template, request
import json
import utils

user_sessions_lookup_bp = Blueprint('user-sessions-lookup', __name__)


@user_sessions_lookup_bp.route('/user-sessions-lookup/<environment>', methods=["GET"])
@utils.require_oidc_login
def user_sessions_lookup_realm_list(environment: str):
    """Renders Realm List for User Sessions Lookup Form

    Returns:
        Template: Rendered HTML page with Realms list, each leading to it's corresponding User Sessions Lookup Form
    """
    return render_template(
        'user_sessions_lookup_list_realms.html',
        utils=utils,
        environment=environment
    )

@user_sessions_lookup_bp.route('/user-sessions-lookup/<environment>/<realm>', methods=["GET"])
@utils.require_oidc_login
def user_sessions_lookup_form(environment: str, realm: str):
    """Renders User Sessions Lookup Form for the provided Environment and Realm

    Returns:
        Template: Rendered HTML page with User Sessions Lookup Form.
    """
    # Render form
    utils.logger.info(f"No Incluye identifier")
    return render_template(
        'user_sessions_lookup_form.html',
        environment=environment,
        realm=realm,
        utils=utils
    )


@user_sessions_lookup_bp.route('/user-sessions-lookup/<environment>/<realm>/<identifier>', methods=["GET"])
@utils.require_oidc_login
def user_sessions_lookup_detail(environment: str, realm: str, identifier: str):
    """Renders the User Sessions Lookup result page for the provided Environment, Realm and Provided User

    Returns:
        Template: Rendered HTML page containing the User Session Lookup Result
    """
    # Fetch user's sessions
    response = utils.getUserSessions(environment, realm, identifier, utils.config)
    utils.logger.info(f"getUserSessions: {response}")
    return render_template(
        'user_sessions_lookup_detail.html',
        utils=utils,
        success=response.get('success', False),
        sessions=response.get('sessions', []),
        message=response.get('message', ''),
        identifier=identifier
    )
