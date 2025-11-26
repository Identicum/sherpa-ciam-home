from flask import Blueprint, render_template, request, redirect, url_for, flash
import json
import uuid
import utils

MESSAGES = utils.load_messages()

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
        identifier=identifier,
        environment=environment,
        realm=realm
    )


@user_sessions_lookup_bp.route('/user-sessions-lookup/<environment>/<realm>/<identifier>/kill-session', methods=["POST"])
@utils.require_oidc_login
def kill_session(environment: str, realm: str, identifier: str):
    """Kills a specific user session

    Returns:
        Redirect: Redirects back to the user sessions detail page
    """
    session_id = request.form.get('session_id')
    is_offline_session = request.form.get('is_offline_session', 'false').lower() == 'true'
    
    if not session_id:
        flash(MESSAGES.get('usersessionslookup.kill_session_error', 'Error al eliminar sesión') + ': Session ID not provided', 'error')
        return redirect(url_for('user-sessions-lookup.user_sessions_lookup_detail', 
                              environment=environment, realm=realm, identifier=identifier))
    
    try:
        kc_admin = utils.getKeycloakAdmin(logger=utils.logger, environment=environment, realmName=realm, config=utils.config)
        kc_admin.delete_session(session_id, isOffline=is_offline_session)
        
        if not is_offline_session:
            try:
                try:
                    uuid.UUID(identifier)
                    user_id = identifier
                except ValueError:
                    user_id = kc_admin.get_user_id(identifier)
                
                clients = kc_admin.get_clients()
                for client in clients:
                    client_id_for_check = client.get("clientId")
                    if client_id_for_check:
                        try:
                            offline_sessions = kc_admin.sherpa_get_user_client_offlinesessions(user_id=user_id, client_id=client_id_for_check)
                            for offline_session in offline_sessions:
                                if offline_session.get('id') == session_id:
                                    try:
                                        kc_admin.delete_session(session_id, isOffline=True)
                                        break
                                    except Exception:
                                        pass
                        except Exception:
                            pass
            except Exception:
                pass
        
        flash(MESSAGES.get('usersessionslookup.kill_session_success', 'Sesión eliminada exitosamente'), 'success')
    except Exception as e:
        utils.logger.error("Error killing session {}: {}", session_id, e)
        error_msg = MESSAGES.get('usersessionslookup.kill_session_error', 'Error al eliminar sesión')
        flash(f'{error_msg}: {str(e)}', 'error')
    
    return redirect(url_for('user-sessions-lookup.user_sessions_lookup_detail', 
                          environment=environment, realm=realm, identifier=identifier))


@user_sessions_lookup_bp.route('/user-sessions-lookup/<environment>/<realm>/<identifier>/kill-all-sessions', methods=["POST"])
@utils.require_oidc_login
def kill_all_sessions(environment: str, realm: str, identifier: str):
    """Kills all user sessions

    Returns:
        Redirect: Redirects back to the user sessions detail page
    """
    try:
        kc_admin = utils.getKeycloakAdmin(logger=utils.logger, environment=environment, realmName=realm, config=utils.config)
        kc_admin.sherpa_logout_user_sessions(username=identifier)
        
        try:
            uuid.UUID(identifier)
            user_id = identifier
        except ValueError:
            user_id = kc_admin.get_user_id(identifier)
        
        clients = kc_admin.get_clients()
        for client in clients:
            client_keycloak_id = client.get("id")
            if client_keycloak_id:
                try:
                    kc_admin.logout_user_client_offlinesessions(user_id=user_id, client_id=client_keycloak_id)
                except Exception:
                    pass
        
        flash(MESSAGES.get('usersessionslookup.kill_all_sessions_success', 'Todas las sesiones eliminadas exitosamente'), 'success')
    except Exception as e:
        utils.logger.error("Error killing all sessions for user {}: {}", identifier, e)
        error_msg = MESSAGES.get('usersessionslookup.kill_all_sessions_error', 'Error al eliminar sesiones')
        flash(f'{error_msg}: {str(e)}', 'error')
    
    return redirect(url_for('user-sessions-lookup.user_sessions_lookup_detail', 
                          environment=environment, realm=realm, identifier=identifier))
