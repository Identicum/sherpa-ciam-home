import auth_utils
from flask import Blueprint, current_app, render_template, request, redirect, url_for, flash
import utils
import requests

user_sessions_bp = Blueprint('user-sessions', __name__)

@user_sessions_bp.before_request
def check_tests_role():
    """Enforce role-based access for all sessions routes."""
    environment = request.view_args.get('environment')
    if environment in current_app.unrestricted_environments:
        return None
    if environment and not auth_utils.hasRole(logger=current_app.logger, required_role=auth_utils.buildRole(environment, 'user-sessions')):
        return render_template('403.html', logger=current_app.logger, config=current_app.json_config, utils=utils), 403


@user_sessions_bp.route('/user-sessions/<environment>', methods=["GET"])
@utils.require_oidc_login
def user_sessions_realm_list(environment: str):
    """Renders Realm List for User Sessions Lookup Form

    Returns:
        Template: Rendered HTML page with Realms list, each leading to it's corresponding User Sessions Lookup Form
    """
    return render_template(
        'user_sessions_list_realms.html',
        logger=current_app.logger,
        config=current_app.json_config,
        utils=utils,
        environment=environment
    )


@user_sessions_bp.route('/user-sessions/<environment>/<realm>', methods=["GET"])
@utils.require_oidc_login
def user_sessions_form(environment: str, realm: str):
    """Renders User Sessions Lookup Form for the provided Environment and Realm

    Returns:
        Template: Rendered HTML page with User Sessions Lookup Form.
    """
    return render_template(
        'user_sessions_form.html',
        logger=current_app.logger,
        config=current_app.json_config,
        utils=utils,
        environment=environment,
        realm=realm
    )


@user_sessions_bp.route('/user-sessions/<environment>/<realm>/<userIdentifier>', methods=["GET"])
@utils.require_oidc_login
def user_sessions_detail(environment: str, realm: str, userIdentifier: str):
    """Renders the User Sessions Lookup result page for the provided Environment, Realm and Provided User

    Returns:
        Template: Rendered HTML page containing the User Session Lookup Result
    """
    base_url = (current_app.json_config.get("environments", {}).get(environment, {}).get("iamcrud_api_base_url"))
    access_token = auth_utils.getCurrentAccessToken(logger=current_app.logger, discovery_document=current_app.discovery_document)
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json", "X-Realm": realm}
    params = {"userId": userIdentifier}

    user_search_response = requests.get(f"{base_url}/v1/users/search", headers=headers, params={"username": userIdentifier})
    user = user_search_response.json()[0]
    username = user["username"]
    user_id = user["identifier"]

    iamcrud_response = requests.get(f"{base_url}/v1/sessions", headers=headers, params=params)

    payload = iamcrud_response.json()
    sessions = payload if isinstance(payload, list) else []
    sessions = [user_session for user_session in sessions if isinstance(user_session, dict)]

    response = {"success": iamcrud_response.ok, "sessions": sessions, "message": "OK" if iamcrud_response.ok else str(payload)}
    current_app.logger.trace(f"User sessions: {response}")
    can_update = auth_utils.hasRole(logger=current_app.logger, required_role=f"{realm.upper()}_UPDATE_USERS")
    return render_template(
        'user_sessions_detail.html',
        logger=current_app.logger,
        config=current_app.json_config,
        utils=utils,
        success=response.get('success', False),
        sessions=response.get('sessions', []),
        message=response.get('message', ''),
        userIdentifier=userIdentifier,
        username=username,
        userId=user_id,
        canUpdate=can_update,
        environment=environment,
        realm=realm
    )


@user_sessions_bp.route('/user-sessions/<environment>/<realm>/<userIdentifier>/kill-session', methods=["POST"])
@utils.require_oidc_login
def kill_session(environment: str, realm: str, userIdentifier: str):
    """Kills a specific user session

    Returns:
        Redirect: Redirects back to the user sessions detail page
    """
    if not auth_utils.hasRole(logger=current_app.logger, required_role=f"{realm.upper()}_UPDATE_USERS"):
        current_app.logger.warn("User without role attempted to kill a session")
        flash(current_app.messages['usersesssions.kill_session_forbidden'], 'error')
        return redirect(url_for('user-sessions.user_sessions_detail', environment=environment, realm=realm, userIdentifier=userIdentifier))

    session_id = request.form.get('session_id')
    if not session_id:
        flash(current_app.messages['usersesssions.kill_session_error'], 'error')
        return redirect(url_for('user-sessions.user_sessions_detail', environment=environment, realm=realm, userIdentifier=userIdentifier))

    base_url = (current_app.json_config.get("environments", {}).get(environment, {}).get("iamcrud_api_base_url"))
    access_token = auth_utils.getCurrentAccessToken(logger=current_app.logger, discovery_document=current_app.discovery_document)
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json", "X-Realm": realm}
    iamcrud_response = requests.delete(f"{base_url}/v1/sessions/{session_id}", headers=headers)

    if iamcrud_response.ok:
        flash(current_app.messages['usersesssions.kill_session_success'], 'success')
    else:
        current_app.logger.error(f"Error killing session {session_id}: HTTP {iamcrud_response.status_code} - {iamcrud_response.text}")
        flash(current_app.messages['usersesssions.kill_session_error'], 'error')

    return redirect(url_for('user-sessions.user_sessions_detail', environment=environment, realm=realm, userIdentifier=userIdentifier))


@user_sessions_bp.route('/user-sessions/<environment>/<realm>/<userIdentifier>/kill-all-sessions', methods=["POST"])
@utils.require_oidc_login
def kill_all_sessions(environment: str, realm: str, userIdentifier: str):
    """Kills all user sessions

    Returns:
        Redirect: Redirects back to the user sessions detail page
    """
    if not auth_utils.hasRole(logger=current_app.logger, required_role=f"{realm.upper()}_UPDATE_USERS"):
        current_app.logger.warn(f"User without role attempted to kill all sessions for user {userIdentifier}")
        flash(current_app.messages['usersesssions.kill_all_sessions_forbidden'], 'error')
        return redirect(url_for('user-sessions.user_sessions_detail', environment=environment, realm=realm, userIdentifier=userIdentifier))

    base_url = (current_app.json_config.get("environments", {}).get(environment, {}).get("iamcrud_api_base_url"))
    access_token = auth_utils.getCurrentAccessToken(logger=current_app.logger, discovery_document=current_app.discovery_document)
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json", "X-Realm": realm}
    params = {"userId": userIdentifier}
    iamcrud_response = requests.delete(f"{base_url}/v1/sessions", headers=headers, params=params)

    if iamcrud_response.ok:
        flash(current_app.messages['usersesssions.kill_all_sessions_success'], 'success')
    else:
        current_app.logger.error(f"Error killing all sessions for user {userIdentifier}: HTTP {iamcrud_response.status_code} - {iamcrud_response.text}")
        flash(current_app.messages['usersesssions.kill_all_sessions_error'], 'error')

    return redirect(url_for('user-sessions.user_sessions_detail', environment=environment, realm=realm, userIdentifier=userIdentifier))
