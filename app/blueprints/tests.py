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


@tests_bp.route('/tests/<environment>/report/<timestamp>', methods=["GET"])
@utils.require_oidc_login
def tests_report(environment: str, timestamp: str):
    """
    Renders Tests Report Page

    Args:
        environment (str): Environment Name
        timestamp (str): Test Execution Timestamp / Report File's Name

    Returns:
        Template: Test Report Rendered HTML Page
    """    
    
    json_report = {}
    error_message = None
    try:
        with open(f"/data/idp_testing_reports/{environment}/{timestamp}/report.json", "r") as json_report_file:
            json_report = json.load(json_report_file)
        
        if json_report.get("included"):
            for test_object in json_report["included"]:
                test_attributes = test_object.get("attributes", {})
                test_call = test_attributes.get("call", {})
                test_metadata = test_call.get("metadata", {})
                
                test_outcome = test_attributes.get("outcome", "")
                call_outcome = test_call.get("outcome", "")
                
                if test_metadata.get("test_media_dir"):
                    test_media_dir = test_metadata["test_media_dir"]
                    current_app.logger.debug("Processing test with test_media_dir: '{}' (outcome: {})", test_media_dir, test_outcome)
                    
                    if test_outcome == "failed" or call_outcome == "failed":
                        failed_images = utils.getTestFailedImages(
                            logger=current_app.logger,
                            environment=environment,
                            timestamp=timestamp,
                            test_media_dir=test_media_dir
                        )
                        if failed_images:
                            current_app.logger.info("Adding {} failed images to test object (test_media_dir: '{}', images: {})", 
                                       len(failed_images), test_media_dir, failed_images)
                            if "metadata" not in test_object["attributes"]["call"]:
                                test_object["attributes"]["call"]["metadata"] = {}
                            test_object["attributes"]["call"]["metadata"]["failed_images"] = failed_images
                        else:
                            current_app.logger.warn("No failed images found for test_media_dir: '{}' (but test failed). Path checked: /data/idp_testing_reports/{}/{}/{}", 
                                       test_media_dir, environment, timestamp, test_media_dir)
                    else:
                        current_app.logger.debug("Test passed, skipping image search for test_media_dir: '{}'", test_media_dir)
                else:
                    current_app.logger.debug("Test object does not have test_media_dir in metadata (test: {}, outcome: {})", 
                               test_attributes.get("name", "unknown"), test_outcome)

        # Enrich each test with description from config mapping (or keep from report if present)
        utils.enrichTestsWithDescriptions(current_app.logger, json_report)
    except Exception as e:
        error_message = e

    return render_template(
        'tests_detail.html',
        logger=current_app.logger,
        config=current_app.json_config,
        utils=utils,
        json_report=json_report,
        error_message=error_message,
        environment=environment,
        timestamp=timestamp
    )


@tests_bp.route('/tests/<environment>/report/<timestamp>/data', methods=["GET"])
@utils.require_oidc_login
def tests_report_data(environment: str, timestamp: str):
    """
    Returns processed test report data as JSON for client-side sorting/filtering.
    
    Args:
        environment (str): Environment Name
        timestamp (str): Test Execution Timestamp
        
    Returns:
        JSON: Processed test data with sanitized fields for UI interaction
    """
    current_app.logger.debug(f"Getting data for test env: {environment}, timestamp: {timestamp}")
    try:
        with open(f"/data/idp_testing_reports/{environment}/{timestamp}/report.json", "r") as json_report_file:
            json_report = json.load(json_report_file)

        # Extract and process test data
        test_data = []
        if json_report.get("included"):
            for test_object in json_report["included"]:
                test_attributes = test_object.get("attributes", {})
                test_call = test_attributes.get("call", {})
                test_metadata = test_call.get("metadata", {})

                # Extract sortable/filterable fields
                test_entry = {
                    "id": test_object.get("id"),
                    "name": test_attributes.get("name", ""),
                    "folder": test_metadata.get("parent_directory", ""),
                    "file": test_metadata.get("file_name", ""),
                    "function": test_metadata.get("function_name", ""),
                    # test_display_name (deprecated)
                    "test_display_name": test_metadata.get("test_display_name", ""),
                    "outcome": test_attributes.get("outcome", ""),
                    "duration": test_attributes.get("duration", 0)
                }
                test_data.append(test_entry)
        return Response(
            json.dumps({"tests": test_data, "success": True}),
            mimetype='application/json'
        )
    except Exception as e:
        current_app.logger.error(f"Error loading test report data: {e}")
        return Response(
            json.dumps({"tests": [], "success": False, "error": str(e)}),
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
    report_path = f"/data/idp_testing_reports/{environment}/{timestamp}/report.json"
    with open(report_path, 'r', encoding='utf-8') as f:
        json_report = json.load(f)

    if "data" in json_report:
        for item in json_report["data"]:
            item.pop("relationships", None)

    # Include description for each test in downloaded JSON
    utils.enrichTestsWithDescriptions(current_app.logger, json_report)

    json_string = json.dumps(json_report, indent=2, ensure_ascii=False)
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

