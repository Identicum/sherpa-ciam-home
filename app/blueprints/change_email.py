"""Change Email: consumes IAM CRUD API to update user email."""
import auth_utils
from exceptions import ServiceException, UserNotFoundError
from flask import Blueprint, current_app, redirect, render_template, request, url_for
import requests
import utils


change_email_bp = Blueprint("change-email", __name__)

@change_email_bp.before_request
def check_change_email_role():
    """Enforce role-based access for all change email routes."""
    environment = request.view_args.get('environment')
    if environment in current_app.unrestricted_environments:
        return None
    if environment and not auth_utils.hasRole(logger=current_app.logger, required_role=auth_utils.buildRole(environment, 'change-email')):
        return render_template('403.html', logger=current_app.logger, config=current_app.json_config, utils=utils), 403


def search_user(base_url: str, realm: str, access_token: str, target_user: str) -> str:
    """Resolve target_user (username, UUID or email) to user id via IAM CRUD. Raises if not found."""
    headers = {"X-Realm": realm, "Authorization": f"Bearer {access_token}"}
    for param, value in [("username", target_user), ("identifier", target_user)]:
        r = requests.get(f"{base_url}/v1/users/search", params={param: value}, headers=headers)
        if r.status_code == 404:
            continue
        if not r.ok:
            raise ServiceException(f"IAM server error (HTTP {r.status_code}).")
        data = r.json()
        if isinstance(data, list) and len(data) > 0:
            user = data[0]
            return user["identifier"]
    r = requests.get(f"{base_url}/v1/users", params={"emailAddress": target_user}, headers=headers)
    if r.status_code != 404:
        if not r.ok:
            raise ServiceException(f"IAM server error (HTTP {r.status_code}).")
        data = r.json()
        if isinstance(data, list) and len(data) > 0:
            user = data[0]
            return user["identifier"]
    raise UserNotFoundError(target_user)


def change_email(base_url: str, realm: str, access_token: str, user_id: str, new_email: str) -> None:
    """Call IAM CRUD PATCH /v1/users/{id}/change-email. Raises on non-204."""
    url = f"{base_url}/v1/users/{user_id}/change-email"
    headers = {"X-Realm": realm, "Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    r = requests.patch(url, json={"emailAddress": new_email}, headers=headers)
    if r.status_code != 204:
        try:
            err = r.json()
            msg = err.get("message") or r.text
        except Exception:
            msg = r.text or f"HTTP {r.status_code}"
        raise ServiceException(msg or f"HTTP {r.status_code}")


@change_email_bp.route("/change-email/<environment>", methods=["GET"])
@utils.require_oidc_login
def change_email_realms(environment: str):
    """Show realm list for Change Email for the given environment."""
    return render_template(
        "change_email_list_realms.html",
        logger=current_app.logger,
        config=current_app.json_config,
        utils=utils,
        environment=environment,
    )


@change_email_bp.route("/change-email/<environment>/<realm>", methods=["GET"])
@utils.require_oidc_login
def change_email_form(environment: str, realm: str):
    """Show email change form for the given realm."""
    return render_template(
        "change_email_form.html",
        logger=current_app.logger,
        config=current_app.json_config,
        utils=utils,
        environment=environment,
        realm=realm,
    )


@change_email_bp.route("/change-email/<environment>/<realm>", methods=["POST"])
@utils.require_oidc_login
def change_email_submit(environment: str, realm: str):
    """Send email change form: resolve user, call IAM CRUD change-email, redirect to result."""
    target_user = (request.form.get("target_user") or "").strip()
    new_email = (request.form.get("new_email") or "").strip()
    if not target_user or not new_email:
        return redirect(
            url_for("change-email.change_email_result", environment=environment, realm=realm, success=False, message=current_app.messages["changeemail.missing_user_or_new_email"])
        )
    env = (environment)
    config_environments = current_app.json_config["environments"]
    base_url = config_environments[env]["iamcrud_api_base_url"]
    if not base_url:
        return redirect(
            url_for("change-email.change_email_result", environment=environment, realm=realm, success=False, message=current_app.messages["changeemail.iamcrud_not_configured"])
        )
    access_token = auth_utils.getCurrentAccessToken(logger=current_app.logger, discovery_document=current_app.discovery_document)
    if not access_token:
        return redirect(
            url_for("change-email.change_email_result", environment=environment, realm=realm, success=False, message=current_app.messages["changeemail.session_token_error"])
        )
    try:
        user_id = search_user(base_url, realm, access_token, target_user)
        change_email(base_url, realm, access_token, user_id, new_email)
    except UserNotFoundError as e:
        message = current_app.messages["changeemail.user_not_found_with_target"].format(str(e))
        return redirect(
            url_for("change-email.change_email_result", environment=environment, realm=realm, success=False, message=message)
        )
    except ServiceException as e:
        return redirect(
            url_for("change-email.change_email_result", environment=environment, realm=realm, success=False, message=str(e))
        )
    return redirect(
        url_for("change-email.change_email_result", environment=environment, realm=realm, success=True, message=current_app.messages["changeemail.success"])
    )


@change_email_bp.route("/change-email/<environment>/result", methods=["GET"])
@utils.require_oidc_login
def change_email_result(environment: str):
    """Show email change result."""
    success = request.args.get("success", "false").lower() == "true"
    message = request.args.get("message", "")
    raw_code = request.args.get("status_code")
    status_code = int(raw_code) if raw_code and raw_code.isdigit() else None
    realm = request.args.get("realm")
    return render_template(
        "change_email_result.html",
        logger=current_app.logger,
        config=current_app.json_config,
        utils=utils,
        environment=environment,
        realm=realm,
        success=success,
        message=message,
        status_code=status_code,
    )
