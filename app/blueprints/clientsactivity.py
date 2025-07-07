from flask import Blueprint, render_template
import clientsactivity_report
import json
import os
import utils

clientsactivity_bp = Blueprint('clientsactivity', __name__)


@clientsactivity_bp.route('/clientsactivity/<environment>', methods=["GET"])
def clientsactivity_list_realms(environment: str):
    """Renders 'Clients Activity' Realm list template

    Args:
        environment (str): Environment name

    Returns:
        Template: Realm list rendered HTML Page
    """
    logger = utils.getLogger()
    data = utils.getData(logger=logger)
    return render_template(
        'clientsactivity_list_realms.html',
        utils=utils,
        environment=environment,
        data=data
    )


@clientsactivity_bp.route('/clientsactivity/<environment>/generate', methods=["GET"])
def clientsactivityEnvGenerate(environment: str):
    """Renders Environment-Specific 'Clients activity' Report **GENERATION** Page

    Args:
        environment (str): Environment name

    Returns:
        Template: Environment-Specific 'Clients activity' Report **GENERATION** Rendered Page HTML
    """
    logger = utils.getLogger()
    data = utils.getData(logger=logger)
    processOutput = clientsactivity_report.run(
        logger=logger,
        outputPath="/data",
        environment=environment,
        data=data
    )
    return render_template(
        'terraformcheck_output.html',
        utils=utils,
        environment=environment,
        processOutput=processOutput,
        data=data
    )


@clientsactivity_bp.route('/clientsactivity/<environment>/<realmName>', methods=["GET"])
def clientsactivity_list(environment: str, realmName: str):
    """Renders 'Clients Activity' Realm's Clients list Template

    Args:
        environment (str): Environment name
        realmName (str): Realm name

    Returns:
        Template: 'Client Info' Realm's Client List Rendered HTML Page
    """
    reportFilePath = "/data/clientsactivity_{}.json".format(environment)
    reportData = None
    errorMessage = None
    metadata = {}
    realmActivityData = []
    logger = utils.getLogger()
    data = utils.getData(logger=logger)
    try:
        if os.path.exists(reportFilePath):
            with open(reportFilePath, 'r') as f:
                reportData = json.load(f)
                metadata = reportData.get("metadata", {})
                realmActivityData = reportData.get("activity", {}).get(realmName, [])
        else:
            errorMessage = f"Report file not found: {reportFilePath}"
    except json.JSONDecodeError:
        errorMessage = f"Error decoding JSON from report file: {reportFilePath}"
    except Exception as e:
        errorMessage = f"An unexpected error occurred while reading {reportFilePath}: {str(e)}"
    return render_template(
        'clientsactivity_list.html',
        utils=utils,
        environment=environment,
        realmName=realmName,
        metadata=metadata,
        errorMessage=errorMessage,
        realmActivityData=realmActivityData,
        data=data
    )
