from flask import Blueprint, render_template
import gen_tf_report
import json
import os
import utils

terraformcheck_bp = Blueprint('terraformcheck', __name__, template_folder='../templates')

logger = utils.logger

@terraformcheck_bp.route('/terraformcheck/<env>', methods=["GET"])
def terraform_check_report(env: str):
    """Renders 'Terraform Check' Diff Report Page

    Args:
        env (str): Environment name

    Returns:
        Template: 'Terraform Check' Diff Report Rendered HTML Page
    """
    report_file_path = "/data/terraform_check_{}.json".format(env)
    report_data = None
    error_message = None
    
    try:
        if os.path.exists(report_file_path):
            with open(report_file_path, 'r') as f:
                report_data = json.load(f)
        else:
            error_message = f"Report file not found: {report_file_path}"
    except json.JSONDecodeError:
        error_message = f"Error decoding JSON from report file: {report_file_path}"
    except Exception as e:
        error_message = f"An unexpected error occurred while reading {report_file_path}: {str(e)}"
        
    return render_template(
        'terraformcheck.html',
        utils=utils,
        env=env,
        report_data=report_data,
        error_message=error_message
    )


@terraformcheck_bp.route('/terraformcheck/generate', methods=["GET"])
def terraform_generate_general_report():
    """Renders General 'Terraform Check' Diff Report **GENERATION** Page (All environments)

    Returns:
        Template: General 'Terraform Check' Diff Report **GENERATION** Rendered Page HTML
    """
    process_output = []
    for env in utils.getEnvironments(logger):
        output = gen_tf_report.run(
            logger=logger,
            objects_path="/terraform-objects",
            output_path="/data",
            environment=env
        )
        process_output.append(output)
    return render_template(
        'terraformcheck_output.html',
        utils=utils,
        env="All Environments",
        process_output=process_output,
    )


@terraformcheck_bp.route('/terraformcheck/generate/<env>', methods=["GET"])
def terraform_generate_report(env: str):
    """Renders Environment-Specific 'Terraform Check' Diff Report **GENERATION** Page

    Args:
        env (str): Environment name

    Returns:
        Template: Environment-Specific 'Terraform Check' Diff Report **GENERATION** Rendered Page HTML
    """
    output = gen_tf_report.run(
        logger=logger,
        objects_path="/terraform-objects",
        output_path="/data",
        environment=env
    )
    return render_template(
        'terraformcheck_output.html',
        utils=utils,
        env=env,
        process_output=output,
    )
