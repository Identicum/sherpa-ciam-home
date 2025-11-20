from flask import Blueprint, render_template
import json
import utils

testsreport_bp = Blueprint('testsreports', __name__)


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
    
    return render_template(
        f'idp_testing_reports/{environment}/{timestamp}/index.html'
    )

