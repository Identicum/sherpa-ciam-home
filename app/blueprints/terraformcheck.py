from flask import Blueprint, render_template
import terraformcheck_report
import json
import os
import utils

terraformcheck_bp = Blueprint('terraformcheck', __name__, template_folder='../templates')


@terraformcheck_bp.route('/terraformcheck/<environment>', methods=["GET"])
def terraformcheck_report(environment: str):
    """Renders 'Terraform Check' Diff Report Page

    Args:
        environment (str): Environment name

    Returns:
        Template: 'Terraform Check' Diff Report Rendered HTML Page
    """
    reportFilePath = "/data/terraformcheck_{}.json".format(environment)
    reportData = None
    errorMessage = None
    logger = utils.getLogger()
    config = utils.getConfig(logger=logger)
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
        config=config,
        environment=environment,
        reportData=reportData,
        errorMessage=errorMessage
    )


@terraformcheck_bp.route('/terraformcheck/generate', methods=["GET"])
def terraform_generate_general_report():
    """Renders General 'Terraform Check' Diff Report **GENERATION** Page (All environments)

    Returns:
        Template: General 'Terraform Check' Diff Report **GENERATION** Rendered Page HTML
    """
    process_output = []
    logger = utils.getLogger()
    config = utils.getConfig()
    for environment in utils.getEnvironments(logger=logger, config=config):
        output = terraformcheck_report.run(
            logger=logger,
            objectsPath="/terraform-objects",
            outputPath="/data",
            environment=environment
        )
        process_output.append(output)
    return render_template(
        'terraformcheck_output.html',
        utils=utils,
        config=config,
        environment="All Environments",
        process_output=process_output
    )


@terraformcheck_bp.route('/terraformcheck/generate/<environment>', methods=["GET"])
def terraform_generate_report(environment: str):
    """Renders Environment-Specific 'Terraform Check' Diff Report **GENERATION** Page

    Args:
        environment (str): Environment name

    Returns:
        Template: Environment-Specific 'Terraform Check' Diff Report **GENERATION** Rendered Page HTML
    """
    logger = utils.getLogger()
    config = utils.getConfig(logger=logger)
    output = terraformcheck_report.run(
        logger=logger,
        objectsPath="/terraform-objects",
        outputPath="/data",
        environment=environment,
        config=config
    )
    return render_template(
        'terraformcheck_output.html',
        utils=utils,
        config=config,
        environment=environment,
        process_output=output
    )
