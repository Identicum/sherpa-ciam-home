from flask import Blueprint, redirect, render_template, request, Response, send_from_directory, url_for
import json
import utils

tests_bp = Blueprint('tests', __name__)


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
    execution_options = utils.config.get("environments", {}).get(environment, {}).get("testing_custom_envs", [])
    return render_template(
        'tests_list.html',
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
    utils.logger.debug(f"Test execution PID File created at: {pid_file_path} with content: {execution_option}")
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
                    utils.logger.debug("Processing test with test_media_dir: '{}' (outcome: {})", test_media_dir, test_outcome)
                    
                    if test_outcome == "failed" or call_outcome == "failed":
                        failed_images = utils.getTestFailedImages(
                            logger=utils.logger,
                            environment=environment,
                            timestamp=timestamp,
                            test_media_dir=test_media_dir
                        )
                        if failed_images:
                            utils.logger.info("Adding {} failed images to test object (test_media_dir: '{}', images: {})", 
                                       len(failed_images), test_media_dir, failed_images)
                            if "metadata" not in test_object["attributes"]["call"]:
                                test_object["attributes"]["call"]["metadata"] = {}
                            test_object["attributes"]["call"]["metadata"]["failed_images"] = failed_images
                        else:
                            utils.logger.warn("No failed images found for test_media_dir: '{}' (but test failed). Path checked: /data/idp_testing_reports/{}/{}/{}", 
                                       test_media_dir, environment, timestamp, test_media_dir)
                    else:
                        utils.logger.debug("Test passed, skipping image search for test_media_dir: '{}'", test_media_dir)
                else:
                    utils.logger.debug("Test object does not have test_media_dir in metadata (test: {}, outcome: {})", 
                               test_attributes.get("name", "unknown"), test_outcome)
    except Exception as e:
        error_message = e

    return render_template(
        'tests_detail.html',
        utils=utils,
        json_report=json_report,
        error_message=error_message,
        environment=environment,
        timestamp=timestamp
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

    test_reports = utils.getTestReports(utils.logger, environment)
    for timestamp, exec_option, passed, failed, num_tests, duration in test_reports:
        run_id = timestamp
        output.append(f'playwright_tests_info{{run_id="{run_id}",exec_option="{exec_option}"}} 1')
        output.append(f'playwright_tests_passed{{run_id="{run_id}"}} {passed}')
        output.append(f'playwright_tests_failed{{run_id="{run_id}"}} {failed}')
        output.append(f'playwright_tests_total{{run_id="{run_id}"}} {num_tests}')
        output.append(f'playwright_tests_duration{{run_id="{run_id}"}} {duration}')
        output.append('')
    return Response("\n".join(output), mimetype='text/plain')

