from flask import Blueprint, render_template
import clientsactivity_report
import json
import os
import utils

clientsactivity_bp = Blueprint('clientsactivity', __name__)

logger = utils.logger

@clientsactivity_bp.route('/clientsactivity/<env>', methods=["GET"])
def clientsactivity_list_realms(env: str):
    """Renders 'Clients Activity' Realm list template

    Args:
        env (str): Environment name

    Returns:
        Template: Realm list rendered HTML Page
    """
    return render_template(
        'clientsactivity_list_realms.html',
        utils=utils,
        env=env
    )


@clientsactivity_bp.route('/clientsactivity/<env>/generate', methods=["GET"])
def clientsactivityEnvGenerate(env: str):
    """Renders Environment-Specific 'Clients activity' Report **GENERATION** Page

    Args:
        env (str): Environment name

    Returns:
        Template: Environment-Specific 'Clients activity' Report **GENERATION** Rendered Page HTML
    """
    output = clientsactivity_report.run(
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


@clientsactivity_bp.route('/clientsactivity/<env>/<realmName>', methods=["GET"])
def clientsactivity_list(env: str, realmName: str):
    """Renders 'Clients Activity' Realm's Clients list Template

    Args:
        env (str): Environment name
        realmName (str): Realm name

    Returns:
        Template: 'Client Info' Realm's Client List Rendered HTML Page
    """
    report_file_path = "/data/clientsactivity_{}.json".format(env)
    report_data = None
    error_message = None
    metadata = {}
    realm_activity_data = []
    
    try:
        if os.path.exists(report_file_path):
            with open(report_file_path, 'r') as f:
                report_data = json.load(f)
                metadata = report_data.get("metadata", {})
                realm_activity_data = report_data.get("activity", {}).get(realmName, [])
        else:
            error_message = f"Report file not found: {report_file_path}"
    except json.JSONDecodeError:
        error_message = f"Error decoding JSON from report file: {report_file_path}"
    except Exception as e:
        error_message = f"An unexpected error occurred while reading {report_file_path}: {str(e)}"
    return render_template(
        'clientsactivity_list.html',
        utils=utils,
        env=env,
        realmName=realmName,
        metadata=metadata,
        error_message=error_message,
        realm_activity_data=realm_activity_data
    )
