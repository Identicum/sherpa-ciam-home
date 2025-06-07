from flask import Blueprint, render_template
from utils import getRealms, getEnvironments
import json
import os

terraformcheck_bp = Blueprint('terraformcheck', __name__, template_folder='../templates')


@terraformcheck_bp.route('/terraformcheck/<env>', methods=["GET"])
def terraform_check_report(env):
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
        realms=getRealms(),
        environments=getEnvironments(),
        env=env,
        report_data=report_data,
        error_message=error_message
    )
