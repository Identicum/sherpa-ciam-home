from flask import Blueprint, redirect, render_template, url_for, request, Response
import os
from sherpa.utils.basics import Logger
import utils

deployments_bp = Blueprint('deployments', __name__)


def getDeploymentArtifacts(logger: Logger, config: dict) -> list:
    """Returns the list of deployment artifacts available from the configuration

    Args:
        logger (Logger): Sherpa Logger Instance
        config (dict): JSON configuration

    Returns:
        list: List of deployment artifacts
    """
    artifacts = config.get("deployment_artifacts", [])
    logger.trace("Deployment artifacts: {}", artifacts)
    return artifacts


def getDeploymentNodes(logger: Logger, environment: str, config: dict) -> list:
    """Returns the list of deployment nodes for the provided environment

    Args:
        logger (Logger): Sherpa Logger Instance
        environment (str): Environment name
        config (dict): JSON configuration

    Returns:
        list: List of deployment node IPs
    """
    env_config = config.get("environments", {}).get(environment, {})
    nodes = env_config.get("deployment_nodes", [])
    logger.trace("Deployment nodes for {}: {}", environment, nodes)
    return nodes


def getDeploymentStatus(logger: Logger, environment: str, artifact: str = None) -> str:
    """Get the deployment status for the provided environment and artifact

    Args:
        logger (Logger): Sherpa Logger Instance
        environment (str): Basic environment name to check for
        artifact (str, optional): Artifact name to check. If None, checks if any artifact is running

    Returns:
        str: execute / running / available
    """
    if artifact:
        deploy_execute_path = f"/data/deployment_reports/{environment}/{artifact}/deploy.execute"
        deploy_running_path = f"/data/deployment_reports/{environment}/{artifact}/deploy.running"
        if os.path.exists(deploy_running_path):
            logger.trace("Artifact {} in environment {} is running deployment.", artifact, environment)
            return "running"
        elif os.path.exists(deploy_execute_path):
            logger.trace("Artifact {} in environment {} is scheduled for deployment.", artifact, environment)
            return "execute"
    else:
        artifacts = getDeploymentArtifacts(logger, utils.config)
        for art in artifacts:
            deploy_execute_path = f"/data/deployment_reports/{environment}/{art}/deploy.execute"
            deploy_running_path = f"/data/deployment_reports/{environment}/{art}/deploy.running"
            if os.path.exists(deploy_running_path):
                logger.trace("Environment {} has a running deployment for artifact {}.", environment, art)
                return "running"
            elif os.path.exists(deploy_execute_path):
                logger.trace("Environment {} has a scheduled deployment for artifact {}.", environment, art)
                return "execute"
    logger.trace("Environment {} is available for deployment - No PID file found.", environment)
    return "available"


def getDeploymentReports(logger: Logger, environment: str, artifact: str = None, include_logs: bool = False):
    """Get list of deployment reports for the provided environment, optionally filtered by artifact

    Args:
        logger (Logger): Sherpa Logger Instance
        environment (str): Environment name
        artifact (str, optional): Artifact name to filter by. If None, returns all artifacts
        include_logs (bool, optional): If True, includes log content in the response

    Returns:
        list: List of tuples (timestamp, artifact, status, logs) or (timestamp, artifact, status) sorted by timestamp (most recent first)
    """
    REPORT_ENV_DIR = f"/data/deployment_reports/{environment}/"
    if not os.path.exists(REPORT_ENV_DIR):
        logger.debug("Deployment reports path '{}' not found or not configured.", REPORT_ENV_DIR)
        return []
    try:
        logger.debug(f"Returning list of deployment report filenames in directory {REPORT_ENV_DIR}")
        REPORTS_LIST = []
        if not os.path.isdir(REPORT_ENV_DIR):
            return []
        
        artifacts_to_check = [artifact] if artifact else os.listdir(REPORT_ENV_DIR)
        
        for artifact_name in artifacts_to_check:
            artifact_dir = os.path.join(REPORT_ENV_DIR, artifact_name)
            if not os.path.isdir(artifact_dir):
                continue
            for filename in os.listdir(artifact_dir):
                if filename.endswith('.log'):
                    timestamp = filename[:-4]
                    log_file_path = os.path.join(artifact_dir, filename)
                    if os.path.isfile(log_file_path):
                        try:
                            status = extractDeploymentStatusFromLog(logger, log_file_path)
                            if include_logs:
                                log_content = ""
                                try:
                                    with open(log_file_path, 'r', encoding='utf-8') as f:
                                        log_content = f.read()
                                except Exception as e:
                                    logger.warn(f"Could not read log content from {log_file_path}: {e}")
                                REPORTS_LIST.append((timestamp, artifact_name, status, log_content))
                            else:
                                REPORTS_LIST.append((timestamp, artifact_name, status))
                        except Exception as e:
                            logger.warn(f"Could not extract data from {log_file_path}: {e}")
                            continue
        logger.debug(f"Returning Deployment Reports: {REPORTS_LIST}")
        sorted_reports = sorted(REPORTS_LIST, reverse=True)
        if not artifact and len(sorted_reports) > 10:
            return sorted_reports[:10]
        if artifact and include_logs and len(sorted_reports) > 10:
            cleanupOldDeploymentReports(logger, environment, sorted_reports[10:])
            return sorted_reports[:10]
        return sorted_reports
    except Exception as e:
        logger.error("Error listing deployment reports: {}", e)
        return []


def extractDeploymentStatusFromLog(logger: Logger, log_file_path: str) -> str:
    """Extract deployment status from log file

    Args:
        logger (Logger): Sherpa Logger Instance
        log_file_path (str): Path to log file (e.g., /data/deployment_reports/{environment}/{artifact}/{timestamp}.log)

    Returns:
        str: success / failed
    """
    with open(log_file_path, 'r', encoding='utf-8') as f:
        log_content = f.read()
    if '|| ERROR ||' in log_content:
        logger.error("Deployment failed: {}", log_file_path)
        return "failed"
    else:
        logger.info("Deployment completed successfully: {}", log_file_path)
        return "success"


def cleanupOldDeploymentReports(logger: Logger, environment: str, old_reports: list):
    """Remove old deployment reports, keeping only the 10 most recent

    Args:
        logger (Logger): Sherpa Logger Instance
        environment (str): Environment name
        old_reports (list): List of tuples (timestamp, artifact, status) to remove
    """
    REPORT_ENV_DIR = f"/data/deployment_reports/{environment}/"
    for timestamp, artifact, _ in old_reports:
        log_file_path = os.path.join(REPORT_ENV_DIR, artifact, f"{timestamp}.log")
        try:
            if os.path.exists(log_file_path):
                os.remove(log_file_path)
                logger.info("Removed old deployment report: {}", log_file_path)
        except Exception as e:
            logger.error("Error removing old deployment report {}: {}", log_file_path, e)


def getArtifactsLastStatus(logger: Logger, environment: str, config: dict):
    """Get the last deployment status for each artifact

    Args:
        logger (Logger): Sherpa Logger Instance
        environment (str): Environment name
        config (dict): JSON configuration

    Returns:
        list: List of tuples (artifact, timestamp, status) sorted by artifact name
    """
    artifacts = getDeploymentArtifacts(logger, config)
    REPORT_ENV_DIR = f"/data/deployment_reports/{environment}/"
    artifacts_status = []
    
    if not os.path.exists(REPORT_ENV_DIR):
        logger.debug("Deployment reports path '{}' not found or not configured.", REPORT_ENV_DIR)
        return [(art, None, "unknown") for art in artifacts]
    
    try:
        for artifact_name in artifacts:
            artifact_dir = os.path.join(REPORT_ENV_DIR, artifact_name)
            if not os.path.isdir(artifact_dir):
                artifacts_status.append((artifact_name, None, "unknown"))
                continue
            
            last_timestamp = None
            last_status = "unknown"
            
            for filename in os.listdir(artifact_dir):
                if filename.endswith('.log'):
                    timestamp = filename[:-4]
                    log_file_path = os.path.join(artifact_dir, filename)
                    if os.path.isfile(log_file_path):
                        if last_timestamp is None or timestamp > last_timestamp:
                            last_timestamp = timestamp
                            try:
                                last_status = extractDeploymentStatusFromLog(logger, log_file_path)
                            except Exception as e:
                                logger.warn(f"Could not extract status from {log_file_path}: {e}")
                                last_status = "unknown"
            
            artifacts_status.append((artifact_name, last_timestamp, last_status))
        
        return sorted(artifacts_status, key=lambda x: x[0])
    except Exception as e:
        logger.error("Error getting artifacts last status: {}", e)
        return [(art, None, "unknown") for art in artifacts]


class DeploymentReports:
    getDeploymentArtifacts = staticmethod(getDeploymentArtifacts)
    getDeploymentNodes = staticmethod(getDeploymentNodes)
    getDeploymentStatus = staticmethod(getDeploymentStatus)
    getDeploymentReports = staticmethod(getDeploymentReports)
    getArtifactsLastStatus = staticmethod(getArtifactsLastStatus)

deployment_reports = DeploymentReports()


@deployments_bp.route('/deployments/<environment>', methods=["GET"])
@deployments_bp.route('/deployments/<environment>/<artifact>', methods=["GET"])
@utils.require_oidc_login
def deployments(environment: str, artifact: str = None):
    """
    Show deployment interface with artifact selector, deploy button and reports

    Args:
        environment (str): Environment Name
        artifact (str, optional): Artifact name

    Returns:
        Template: Deployment list Rendered HTML Page
    """
    if environment == 'local':
        utils.logger.warn("Attempted access to local environment, redirecting to dev")
        if artifact:
            return redirect(url_for('deployments.deployments', environment='dev', artifact=artifact))
        return redirect(url_for('deployments.deployments', environment='dev'))
    
    return render_template(
        'deployments.html',
        utils=utils,
        deployment_reports=deployment_reports,
        environment=environment,
        artifact=artifact
    )


@deployments_bp.route('/deployments/<environment>/<artifact>/<timestamp>', methods=["GET"])
@utils.require_oidc_login
def deployment_report(environment: str, artifact: str, timestamp: str):
    """
    Show detailed deployment report with logs for a specific deployment

    Args:
        environment (str): Environment Name
        artifact (str): Artifact name
        timestamp (str): Deployment timestamp

    Returns:
        Template: Deployment report detail Rendered HTML Page
    """
    if environment == 'local':
        utils.logger.warn("Attempted access to local environment, redirecting to dev")
        return redirect(url_for('deployments.deployment_report', environment='dev', artifact=artifact, timestamp=timestamp))
    
    log_file_path = f"/data/deployment_reports/{environment}/{artifact}/{timestamp}.log"
    
    from_artifact = request.args.get('from', 'all')
    
    if not os.path.exists(log_file_path):
        utils.logger.error("Deployment log not found: {}", log_file_path)
        if from_artifact == 'all':
            return redirect(url_for('deployments.deployments', environment=environment))
        return redirect(url_for('deployments.deployments', environment=environment, artifact=from_artifact))
    
    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            logs = f.read()
        
        status = extractDeploymentStatusFromLog(utils.logger, log_file_path)
        
        return render_template(
            'deployment_report.html',
            utils=utils,
            environment=environment,
            artifact=artifact,
            timestamp=timestamp,
            logs=logs,
            status=status,
            from_artifact=from_artifact
        )
    except Exception as e:
        utils.logger.error("Error reading deployment log {}: {}", log_file_path, e)
        return redirect(url_for('deployments.deployments', environment=environment, artifact=artifact))


@deployments_bp.route('/deployments/<environment>/<artifact>/<timestamp>/download', methods=["GET"])
@utils.require_oidc_login
def deployment_log_download(environment: str, artifact: str, timestamp: str):
    """
    Download deployment log file (.log).

    Args:
        environment (str): Environment name
        artifact (str): Artifact name
        timestamp (str): Deployment timestamp

    Returns:
        Response: Log file as attachment
    """
    log_file_path = f"/data/deployment_reports/{environment}/{artifact}/{timestamp}.log"
    with open(log_file_path, 'r', encoding='utf-8') as f:
        log_content = f.read()
    filename = f"deployment_{artifact}_{timestamp}.log"
    return Response(
        log_content,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )


@deployments_bp.route('/deployments/<environment>/execute', methods=["POST"])
@utils.require_oidc_login
def deployments_execute(environment: str):
    """
    Requests deployment execution for the provided environment and artifact, writing a file to trigger the process.

    Args:
        environment (str): Environment name
    """
    if environment == 'local':
        utils.logger.warn("Attempted access to local environment, redirecting to dev")
        return redirect(url_for('deployments.deployments', environment='dev'))
    
    artifact = request.form.get('artifact')
    if not artifact:
        utils.logger.error("No artifact provided for deployment")
        return redirect(url_for('deployments.deployments', environment=environment))
    
    selected_node = request.form.get('node')
    if not selected_node:
        utils.logger.error("No node provided for deployment")
        return redirect(url_for('deployments.deployments', environment=environment, artifact=artifact))
    
    pid_file_path = f"/data/deployment_reports/{environment}/{artifact}/deploy.execute"
    os.makedirs(os.path.dirname(pid_file_path), exist_ok=True)
    
    with open(pid_file_path, "w") as pid_file:
        pid_file.write(str(selected_node))
    utils.logger.debug(f"Deployment execution PID File created at: {pid_file_path} with content: {selected_node}")
    return redirect(url_for('deployments.deployments', environment=environment, artifact=artifact))