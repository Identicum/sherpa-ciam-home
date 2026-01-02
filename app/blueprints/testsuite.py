from flask import Blueprint, render_template
import json
import utils

testsuite_bp = Blueprint('testsuite', __name__)


@testsuite_bp.route('/testsuite/<environment>', methods=["GET"])
@utils.require_oidc_login
def testsuite(environment: str):
    """Renders Test Suite for Environment

    Args:
        environment (str): Environment Name

    Returns:
        Template: Environment Test Suite HTML
    """
    LOGGER = utils.logger
    CUSTOM_EXEC_ENVS = utils.getCustomTestExecEnvNames(logger=LOGGER, environment=environment,config=utils.getConfig(LOGGER))
    return render_template(
        f'testsuite.html',
        utils=utils,
        environment=environment,
        exec_environments=CUSTOM_EXEC_ENVS
    )

@testsuite_bp.route('/testsuite/<environment>/report/<timestamp>', methods=["GET"])
@utils.require_oidc_login
def testreport_detail(environment: str, timestamp: str):
    """Renders Tests Report Page

    Args:
        environment (str): Environment Name
        timestamp (str): Test Execution Timestamp / Report File's Name

    Returns:
        Template: Test Report Rendered HTML Page
    """    
    
    json_report = {}
    error_message = None
    try:
        with open(f"/data/idp_testing_reports/{environment}/{timestamp}/report.json", "r") as json_report_file:
            json_report = json.load(json_report_file)
    except Exception as e:
        error_message = e

    return render_template(
        'testreport.html',
        utils=utils,
        json_report=json_report,
        error_message=error_message,
        environment=environment
    )

