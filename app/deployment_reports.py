import os
from sherpa.utils.basics import Logger
import utils


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


def getDeploymentStatus(logger: Logger, environment: str) -> str:
    """Get the deployment status for the provided environment

    Args:
        logger (Logger): Sherpa Logger Instance
        environment (str): Basic environment name to check for

    Returns:
        str: running / available
    """
    if os.path.exists(f"/data/deployment_reports/{environment}.execute") or os.path.exists(f"/data/deployment_reports/{environment}.running"):
        logger.trace("Environment is running deployment.")
        return "running"
    logger.trace("Environment is available for deployment - No PID file found.")
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
            for timestamp_dir in os.listdir(artifact_dir):
                timestamp_path = os.path.join(artifact_dir, timestamp_dir)
                log_file_path = os.path.join(timestamp_path, "deployment.log")
                if os.path.isdir(timestamp_path) and os.path.isfile(log_file_path):
                    try:
                        status = extractDeploymentStatusFromLog(logger, log_file_path)
                        if include_logs:
                            log_content = ""
                            try:
                                with open(log_file_path, 'r', encoding='utf-8') as f:
                                    log_content = f.read()
                            except Exception as e:
                                logger.warn(f"Could not read log content from {log_file_path}: {e}")
                            REPORTS_LIST.append((timestamp_dir, artifact_name, status, log_content))
                        else:
                            REPORTS_LIST.append((timestamp_dir, artifact_name, status))
                    except Exception as e:
                        logger.warn(f"Could not extract data from {log_file_path}: {e}")
                        continue
        logger.debug(f"Returning Deployment Reports: {REPORTS_LIST}")
        sorted_reports = sorted(REPORTS_LIST, reverse=True)
        if artifact and len(sorted_reports) > 10:
            cleanupOldDeploymentReports(logger, environment, sorted_reports[10:])
            return sorted_reports[:10]
        return sorted_reports
    except Exception as e:
        logger.error("Error listing deployment reports: {}", e)
        return []


def getArtifactsLastStatus(logger: Logger, environment: str, artifacts: list) -> dict:
    """Get the last deployment status for each artifact in the provided list

    Args:
        logger (Logger): Sherpa Logger Instance
        environment (str): Environment name
        artifacts (list): List of artifact names

    Returns:
        dict: Dictionary mapping artifact name to its last status (timestamp, status) or None if no reports
    """
    REPORT_ENV_DIR = f"/data/deployment_reports/{environment}/"
    artifacts_status = {}
    
    if not os.path.exists(REPORT_ENV_DIR):
        logger.debug("Deployment reports path '{}' not found or not configured.", REPORT_ENV_DIR)
        for artifact in artifacts:
            artifacts_status[artifact] = None
        return artifacts_status
    
    try:
        for artifact_name in artifacts:
            artifact_dir = os.path.join(REPORT_ENV_DIR, artifact_name)
            if not os.path.isdir(artifact_dir):
                artifacts_status[artifact_name] = None
                continue
            
            timestamps = []
            for timestamp_dir in os.listdir(artifact_dir):
                timestamp_path = os.path.join(artifact_dir, timestamp_dir)
                log_file_path = os.path.join(timestamp_path, "deployment.log")
                if os.path.isdir(timestamp_path) and os.path.isfile(log_file_path):
                    timestamps.append(timestamp_dir)
            
            if not timestamps:
                artifacts_status[artifact_name] = None
                continue
            
            most_recent_timestamp = sorted(timestamps, reverse=True)[0]
            log_file_path = os.path.join(REPORT_ENV_DIR, artifact_name, most_recent_timestamp, "deployment.log")
            
            try:
                status = extractDeploymentStatusFromLog(logger, log_file_path)
                artifacts_status[artifact_name] = (most_recent_timestamp, status)
            except Exception as e:
                logger.warn(f"Could not extract status from {log_file_path}: {e}")
                artifacts_status[artifact_name] = None
        
        return artifacts_status
    except Exception as e:
        logger.error("Error getting artifacts last status: {}", e)
        for artifact in artifacts:
            if artifact not in artifacts_status:
                artifacts_status[artifact] = None
        return artifacts_status


def extractDeploymentStatusFromLog(logger: Logger, log_file_path: str) -> str:
    """Extract deployment status from log file

    Args:
        logger (Logger): Sherpa Logger Instance
        log_file_path (str): Path to deployment.log file

    Returns:
        str: success / failed / unknown
    """
    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            log_content = f.read()
        if 'logger.error' in log_content or ' - ERROR -' in log_content or ' ERROR ' in log_content:
            return "failed"
        elif 'logger.info' in log_content or ' - INFO -' in log_content or ' INFO ' in log_content:
            return "success"
        log_lower = log_content.lower()
        if any(keyword in log_lower for keyword in ['deployment completed successfully', 'finished', 'success']):
            return "success"
        elif any(keyword in log_lower for keyword in ['failed', 'error', 'exception', 'deployment failed']):
            return "failed"
        else:
            return "unknown"
    except Exception as e:
        logger.error("Error reading deployment log {}: {}", log_file_path, e)
        return "unknown"


def cleanupOldDeploymentReports(logger: Logger, environment: str, old_reports: list):
    """Remove old deployment reports, keeping only the 10 most recent

    Args:
        logger (Logger): Sherpa Logger Instance
        environment (str): Environment name
        old_reports (list): List of tuples (timestamp, artifact, status) to remove
    """
    REPORT_ENV_DIR = f"/data/deployment_reports/{environment}/"
    for timestamp, artifact, _ in old_reports:
        report_dir = os.path.join(REPORT_ENV_DIR, artifact, timestamp)
        try:
            if os.path.exists(report_dir):
                for root, dirs, files in os.walk(report_dir, topdown=False):
                    for file in files:
                        file_path = os.path.join(root, file)
                        os.remove(file_path)
                    for dir_name in dirs:
                        dir_path = os.path.join(root, dir_name)
                        os.rmdir(dir_path)
                os.rmdir(report_dir)
                logger.info("Removed old deployment report: {}", report_dir)
        except Exception as e:
            logger.error("Error removing old deployment report {}: {}", report_dir, e)
