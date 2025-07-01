from flask import Blueprint, render_template
import gen_checkclients_report
import json
import os
import utils

checkclients_bp = Blueprint('checkclients', __name__)

logger = utils.logger

@checkclients_bp.route('/checkclients/<env>', methods=["GET"])
def checkclientsEnv(env: str):
    """Renders `Check Clients` template for all of a provided `environment`'s realms

    Args:
        env (str): Environment name

    Returns:
        Template: Rendered Check Clients Page HTML
    """
    report_file_path = "/data/checkclients_{}.json".format(env)
    report_data = None
    error_message = None
    warns = []

    try:
        if os.path.exists(report_file_path):
            with open(report_file_path, 'r') as f:
                report_data = json.load(f)
                warns = report_data.get("warns", [])
        else:
            error_message = f"Report file not found: {report_file_path}"
    except json.JSONDecodeError:
        error_message = f"Error decoding JSON from report file: {report_file_path}"
    except Exception as e:
        error_message = f"An unexpected error occurred while reading {report_file_path}: {str(e)}"
        
    return render_template(
        'checkclients.html',
        utils=utils,
        env=env,
        warns=warns,
        realmName="All Realms",
        error_message=error_message
    )

@checkclients_bp.route('/checkclients/<env>/generate', methods=["GET"])
def checkclientsEnvGenerate(env: str):
    """Renders Environment-Specific 'Terraform Check' Diff Report **GENERATION** Page

    Args:
        env (str): Environment name

    Returns:
        Template: Environment-Specific 'Terraform Check' Diff Report **GENERATION** Rendered Page HTML
    """
    output = gen_checkclients_report.run(
        logger=logger,
        output_path="/data",
        environment=env
    )
    return render_template(
        'terraformcheck_output.html',
        utils=utils,
        env=env,
        process_output=output,
    )

