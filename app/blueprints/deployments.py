from flask import Blueprint, redirect, render_template, url_for
import os
import utils
import deployment_reports

deployments_bp = Blueprint('deployments', __name__)


@deployments_bp.route('/deployments/<environment>', methods=["GET"])
@utils.require_oidc_login
def deployments_list(environment: str):
    """
    List all artifacts with their last deployment status

    Args:
        environment (str): Environment Name

    Returns:
        Template: Deployment list Rendered HTML Page
    """
    if environment == 'local':
        utils.logger.warn("Attempted access to local environment, redirecting to dev")
        return redirect(url_for('deployments.deployments_list', environment='dev'))
    
    artifacts = deployment_reports.getDeploymentArtifacts(logger=utils.logger, config=utils.config)
    artifacts_status = deployment_reports.getArtifactsLastStatus(logger=utils.logger, environment=environment, artifacts=artifacts)
    
    return render_template(
        'deployments_list.html',
        utils=utils,
        environment=environment,
        artifacts=artifacts,
        artifacts_status=artifacts_status
    )


@deployments_bp.route('/deployments/<environment>/<artifact>', methods=["GET"])
@utils.require_oidc_login
def deployments_detail(environment: str, artifact: str):
    """
    Show deployment reports for a specific artifact and allow triggering new deployments

    Args:
        environment (str): Environment Name
        artifact (str): Artifact name

    Returns:
        Template: Deployment detail Rendered HTML Page
    """
    if environment == 'local':
        utils.logger.warn("Attempted access to local environment, redirecting to dev")
        return redirect(url_for('deployments.deployments_detail', environment='dev', artifact=artifact))
    
    deployment_status = deployment_reports.getDeploymentStatus(logger=utils.logger, environment=environment)
    reports = deployment_reports.getDeploymentReports(logger=utils.logger, environment=environment, artifact=artifact, include_logs=True)
    
    return render_template(
        'deployments_detail.html',
        utils=utils,
        environment=environment,
        artifact=artifact,
        deployment_status=deployment_status,
        reports=reports
    )


@deployments_bp.route('/deployments/<environment>/<artifact>/execute', methods=["POST"])
@utils.require_oidc_login
def deployments_execute(environment: str, artifact: str):
    """
    Requests deployment execution for the provided environment and artifact, writing a file to trigger the process.

    Args:
        environment (str): Environment name
        artifact (str): Artifact name
    """
    if environment == 'local':
        utils.logger.warn("Attempted access to local environment, redirecting to dev")
        return redirect(url_for('deployments.deployments_detail', environment='dev', artifact=artifact))
    
    pid_file_path = f"/data/deployment_reports/{environment}.execute"
    os.makedirs(os.path.dirname(pid_file_path), exist_ok=True)
    
    with open(pid_file_path, "w") as pid_file:
        pid_file.write(artifact)
    utils.logger.debug(f"Deployment execution PID File created at: {pid_file_path} with content: {artifact}")
    return redirect(url_for('deployments.deployments_detail', environment=environment, artifact=artifact))
