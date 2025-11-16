from flask import Blueprint, render_template
import terraformcheck_report
import json
import os
import utils

terraformcheck_bp = Blueprint('terraformcheck', __name__, template_folder='../templates')


@terraformcheck_bp.route('/terraformcheck/<environment>', methods=["GET"])
@utils.require_oidc_login
def terraformcheck_show_report(environment: str):
    """Renders 'Terraform Check' Diff Report Page

    Args:
        environment (str): Environment name

    Returns:
        Template: 'Terraform Check' Diff Report Rendered HTML Page
    """
    reportFilePath = "/data/terraformcheck_{}.json".format(environment)
    reportData = None
    errorMessage = None
    try:
        if os.path.exists(reportFilePath):
            with open(reportFilePath, 'r') as f:
                reportData = json.load(f)
        else:
            errorMessage = f"Report file not found: {reportFilePath}"
    except json.JSONDecodeError:
        errorMessage = f"Error decoding JSON from report file: {reportFilePath}"
    except Exception as e:
        errorMessage = f"An unexpected error occurred while reading {reportFilePath}: {str(e)}"
    return render_template(
        'terraformcheck.html',
        utils=utils,
        environment=environment,
        reportData=reportData,
        errorMessage=errorMessage
    )


@terraformcheck_bp.route('/terraformcheck/<environment>/generate', methods=["GET"])
def terraformcheck_generate_report(environment: str):
    """Renders Environment-Specific 'Terraform Check' Diff Report **GENERATION** Page

    Args:
        environment (str): Environment name

    Returns:
        Template: Environment-Specific 'Terraform Check' Diff Report **GENERATION** Rendered Page HTML
    """
    output = terraformcheck_report.run(
        logger=utils.logger,
        objectsPath="/terraform-objects",
        outputPath="/data",
        environment=environment,
        config=utils.config
    )
    return render_template(
        'terraformcheck_output.html',
        utils=utils,
        environment=environment,
        process_output=output
    )
