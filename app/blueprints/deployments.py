from flask import Blueprint, redirect, render_template, request, url_for
import os
import utils

deployments_bp = Blueprint('deployments', __name__)


@deployments_bp.route('/deployments/<environment>', methods=["GET"])
@utils.require_oidc_login
def deployments_list(environment: str):
    """
    List deployments, trigger new executions

    Args:
        environment (str): Environment Name

    Returns:
        Template: Deployment list Rendered HTML Page
    """
    if environment == 'local':
        utils.logger.warn("Attempted access to local environment, redirecting to dev")
        return redirect(url_for('deployments.deployments_list', environment='dev'))
    
    artifacts = utils.getDeploymentArtifacts(logger=utils.logger, config=utils.config)
    return render_template(
        'deployments_list.html',
        utils=utils,
        environment=environment,
        artifacts=artifacts
    )


@deployments_bp.route('/deployments/<environment>/execute', methods=["POST"])
@utils.require_oidc_login
def deployments_execute(environment: str):
    """
    Requests deployment execution for the provided environment, writing a file to trigger the process.

    Args:
        environment (str): Environment name
    """
    artifact = request.form.get("artifact", None)
    if not artifact:
        utils.logger.error("No artifact provided for deployment")
        return redirect(url_for('deployments.deployments_list', environment=environment))
    
    pid_file_path = f"/data/deployments/{environment}.execute"
    os.makedirs(os.path.dirname(pid_file_path), exist_ok=True)
    
    with open(pid_file_path, "w") as pid_file:
        pid_file.write(artifact)
    utils.logger.debug(f"Deployment execution PID File created at: {pid_file_path} with content: {artifact}")
    return redirect(url_for('deployments.deployments_list', environment=environment))
