import auth_utils
from flask import Blueprint, current_app, redirect, render_template, request, Response, send_from_directory, url_for
import json
import utils

tests_bp = Blueprint('tests', __name__)

@tests_bp.before_request
def check_tests_role():
    """Enforce role-based access for all deployments routes."""
    environment = request.view_args.get('environment')
    if environment in current_app.unrestricted_environments:
        return None
    if environment and not auth_utils.hasRole(logger=current_app.logger, required_role=auth_utils.buildRole(environment, 'tests')):
        return render_template('403.html', logger=current_app.logger, config=current_app.json_config, utils=utils), 403


@tests_bp.route('/tests/<environment>', methods=["GET"])
@utils.require_oidc_login
def tests_list(environment: str):
    """
    List tests results, trigger new executions

    Args:
        environment (str): Environment Name

    Returns:
        Template: Test list Rendered HTML Page
    """
    execution_options = current_app.json_config.get("environments", {}).get(environment, {}).get("testing_custom_envs", [])
    return render_template(
        'tests_list.html',
        logger=current_app.logger,
        config=current_app.json_config,
        utils=utils,
        environment=environment,
        execution_options=execution_options
    )


@tests_bp.route('/tests/<environment>/execute', methods=["POST"])
@utils.require_oidc_login
def tests_execute(environment: str):
    """
    Requests test execution for the provided environment, writing a file to trigger the process.

    Args:
        environment (str): Environment name
    """
    execution_option = request.form.get("execution_option", None)
    pid_file_path = f"/data/idp_testing_reports/{environment}.execute"
    with open(pid_file_path, "w") as pid_file:
        pid_file.write(execution_option)
    current_app.logger.debug(f"Test execution PID File created at: {pid_file_path} with content: {execution_option}")
    return redirect(url_for('tests.tests_list', environment=environment))


def _load_report(environment: str, timestamp: str) -> dict:
    """Load the raw pytest-json report from disk. Raises FileNotFoundError if missing."""
    report_path = f"/data/idp_testing_reports/{environment}/{timestamp}/report.json"
    with open(report_path, "r", encoding="utf-8") as json_report_file:
        return json.load(json_report_file)


@tests_bp.route('/tests/<environment>/report/<timestamp>', methods=["GET"])
@utils.require_oidc_login
def tests_report(environment: str, timestamp: str):
    """Renders the Test Report page."""
    raw_report = {}
    cases = []
    error_message = None
    try:
        raw_report = _load_report(environment, timestamp)
        cases = utils.parse_test_report(current_app.logger, raw_report, environment, timestamp)
    except FileNotFoundError:
        error_message = "Report not found"
    except Exception as e:
        current_app.logger.error("Error loading report {}/{}: {}", environment, timestamp, e)
        error_message = str(e)

    return render_template(
        'tests_detail.html',
        logger=current_app.logger,
        config=current_app.json_config,
        utils=utils,
        raw_report=raw_report,
        cases=cases,
        error_message=error_message,
        environment=environment,
        timestamp=timestamp,
    )


@tests_bp.route('/tests/<environment>/report/<timestamp>/data', methods=["GET"])
@utils.require_oidc_login
def tests_report_data(environment: str, timestamp: str):
    """Returns normalized test data as JSON for client-side sorting/filtering."""
    try:
        raw_report = _load_report(environment, timestamp)
        cases = utils.parse_test_report(current_app.logger, raw_report, environment, timestamp)
        return Response(
            json.dumps({"success": True, "tests": cases}),
            mimetype='application/json'
        )
    except FileNotFoundError:
        return Response(
            json.dumps({"success": False, "tests": [], "error": "Report not found"}),
            mimetype='application/json',
            status=404
        )
    except Exception as e:
        current_app.logger.error("Error loading report data {}/{}: {}", environment, timestamp, e)
        return Response(
            json.dumps({"success": False, "tests": [], "error": str(e)}),
            mimetype='application/json',
            status=500
        )


@tests_bp.route('/tests/<environment>/report/<timestamp>/images/<test_media_dir>/<filename>', methods=["GET"])
@utils.require_oidc_login
def tests_report_image(environment: str, timestamp: str, test_media_dir: str, filename: str):
    """
    Serves test report image files
    
    Args:
        environment (str): Environment Name
        timestamp (str): Test Execution Timestamp
        test_media_dir (str): Test media directory name (nombre de la carpeta de la prueba)
        filename (str): Image filename
        
    Returns:
        File: Image file
    """
    image_dir = f"/data/idp_testing_reports/{environment}/{timestamp}/{test_media_dir}"
    return send_from_directory(image_dir, filename, mimetype='image/png')


@tests_bp.route('/tests/<environment>/report/<timestamp>/download', methods=["GET"])
@utils.require_oidc_login
def tests_report_download(environment: str, timestamp: str):
    """
    Downloads test report JSON file with relationships removed.

    Args:
        environment (str): Environment Name
        timestamp (str): Test Execution Timestamp / Report File's Name

    Returns:
        Response: JSON report file as download
    """
    raw_report = _load_report(environment, timestamp)

    if "data" in raw_report:
        for item in raw_report["data"]:
            item.pop("relationships", None)

    json_string = json.dumps(raw_report, indent=2, ensure_ascii=False)
    return Response(
        json_string,
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename=report_{timestamp}.json'}
    )


@tests_bp.route('/tests/<environment>/metrics', methods=["GET"])
def metrics(environment: str):
    """
    Expose metrics for Prometheus scraping
    """
    output = []
    output.append('# HELP playwright_tests_info Metadata about the test execution.')
    output.append('# TYPE playwright_tests_info gauge')
    output.append('')
    output.append('# HELP playwright_tests_passed Number of tests that passed in this run.')
    output.append('# TYPE playwright_tests_passed gauge')
    output.append('')
    output.append('# HELP playwright_tests_failed Number of tests that failed in this run.')
    output.append('# TYPE playwright_tests_failed gauge')
    output.append('')
    output.append('# HELP playwright_tests_total Total number of tests executed in this run.')
    output.append('# TYPE playwright_tests_total gauge')
    output.append('')
    output.append('# HELP playwright_tests_duration Total time elapsed for the test execution in seconds.')
    output.append('# TYPE playwright_tests_duration gauge')
    output.append('')

    test_reports = utils.getTestReports(current_app.logger, environment)
    for run_id, exec_option, passed, failed, num_tests, duration in test_reports:
        unix_timestamp = utils.getReportTimestamp(run_id)
        output.append(f'playwright_tests_info{{run_id="{run_id}",exec_option="{exec_option}"}} 1  {unix_timestamp}')
        output.append(f'playwright_tests_passed{{run_id="{run_id}"}} {passed} {unix_timestamp}')
        output.append(f'playwright_tests_failed{{run_id="{run_id}"}} {failed} {unix_timestamp}')
        output.append(f'playwright_tests_total{{run_id="{run_id}"}} {num_tests} {unix_timestamp}')
        output.append(f'playwright_tests_duration{{run_id="{run_id}"}} {duration} {unix_timestamp}')
        output.append('')
    return Response("\n".join(output), mimetype='text/plain')

