from flask import Blueprint, render_template
import checkclients_report
import json
import os
import utils

checkclients_bp = Blueprint('checkclients', __name__)


@checkclients_bp.route('/checkclients/<environment>', methods=["GET"])
def checkclients_show_report(environment: str):
    """Renders `Check Clients` template for all of a provided `environment`'s realms

    Args:
        environment (str): Environment name

    Returns:
        Template: Rendered Check Clients Page HTML
    """
    report_file_path = "/data/checkclients_{}.json".format(environment)
    reportData = None
    errorMessage = None
    warns = []
    metadata = {}
    logger = utils.getLogger()
    config = utils.getConfig(logger=logger)
    try:
        if os.path.exists(report_file_path):
            with open(report_file_path, 'r') as f:
                reportData = json.load(f)
                warns = reportData.get("warns", [])
                metadata = reportData.get("metadata", {})
        else:
            errorMessage = f"Report file not found: {report_file_path}"
    except json.JSONDecodeError:
        errorMessage = f"Error decoding JSON from report file: {report_file_path}"
    except Exception as e:
        errorMessage = f"An unexpected error occurred while reading {report_file_path}: {str(e)}"
        
    return render_template(
        'checkclients.html',
        utils=utils,
        config=config,
        environment=environment,
        warns=warns,
        metadata=metadata,
        realmName="All Realms",
        errorMessage=errorMessage
    )

@checkclients_bp.route('/checkclients/<environment>/generate', methods=["GET"])
def checkclient_generate_report(environment: str):
    """Renders Environment-Specific 'Terraform Check' Diff Report **GENERATION** Page

    Args:
        environment (str): Environment name

    Returns:
        Template: Environment-Specific 'Terraform Check' Diff Report **GENERATION** Rendered Page HTML
    """
    logger = utils.getLogger()
    config = utils.getConfig(logger=logger)
    processOutput = checkclients_report.run(
        logger=logger,
        outputPath="/data",
        environment=environment,
        config=config
    )
    return render_template(
        'terraformcheck_output.html',
        utils=utils,
        config=config,
        environment=environment,
        processOutput=processOutput
    )

