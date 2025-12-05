from flask import Blueprint, render_template
import json
import utils

testsreport_bp = Blueprint('testsreport', __name__)


@testsreport_bp.route('/testreport/<environment>', methods=["GET"])
@utils.require_oidc_login
def testreport_list(environment: str):
    """Renders Test Report List by Environment

    Args:
        environment (str): Environment Name

    Returns:
        Template: Test Report List
    """
    return render_template(
        f'testreport_list.html',
        utils=utils,
        environment=environment
    )

@testsreport_bp.route('/testreport/<environment>/<timestamp>', methods=["GET"])
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

