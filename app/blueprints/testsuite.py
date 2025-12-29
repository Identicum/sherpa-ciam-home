from flask import Blueprint, render_template, send_from_directory
import json
from pathlib import Path
import utils

testsuite_bp = Blueprint('testsuite', __name__)


@testsuite_bp.route('/testsuite/<environment>', methods=["GET"])
@utils.require_oidc_login
def testsuite(environment: str):
    """Renders Test Suite for Environment

    Args:
        environment (str): Environment Name

    Returns:
        Template: Environment Test Suite HTML
    """
    LOGGER = utils.logger
    CUSTOM_EXEC_ENVS = utils.getCustomTestExecEnvNames(logger=LOGGER, environment=environment,config=utils.getConfig(LOGGER))
    return render_template(
        f'testsuite.html',
        utils=utils,
        environment=environment,
        exec_environments=CUSTOM_EXEC_ENVS
    )

@testsuite_bp.route('/testsuite/<environment>/report/<timestamp>', methods=["GET"])
@utils.require_oidc_login
def testreport_detail(environment: str, timestamp: str):
    """Renders Tests Report Page

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
            LOGGER = utils.logger
            for test_object in json_report["included"]:
                test_attributes = test_object.get("attributes", {})
                test_call = test_attributes.get("call", {})
                test_metadata = test_call.get("metadata", {})
                
                test_outcome = test_attributes.get("outcome", "")
                call_outcome = test_call.get("outcome", "")
                
                if test_metadata.get("test_media_dir"):
                    test_media_dir = test_metadata["test_media_dir"]
                    LOGGER.debug("Processing test with test_media_dir: '{}' (outcome: {})", test_media_dir, test_outcome)
                    
                    if "metadata" not in test_object["attributes"]["call"]:
                        test_object["attributes"]["call"]["metadata"] = {}
                    test_object["attributes"]["call"]["metadata"]["test_media_dir_path"] = test_media_dir
                    LOGGER.debug("Set test_media_dir_path to: '{}'", test_media_dir)
                    
                    if test_outcome == "failed" or call_outcome == "failed":
                        failed_images = utils.getTestFailedImages(
                            logger=LOGGER,
                            environment=environment,
                            timestamp=timestamp,
                            test_media_dir=test_media_dir
                        )
                        if failed_images:
                            LOGGER.info("Adding {} failed images to test object (test_media_dir: '{}', images: {})", 
                                       len(failed_images), test_media_dir, failed_images)
                            test_object["attributes"]["call"]["metadata"]["failed_images"] = failed_images
                        else:
                            LOGGER.warn("No failed images found for test_media_dir: '{}' (but test failed). Path checked: /data/idp_testing_reports/{}/{}/{}", 
                                       test_media_dir, environment, timestamp, test_media_dir)
                    else:
                        LOGGER.debug("Test passed, skipping image search for test_media_dir: '{}'", test_media_dir)
                else:
                    LOGGER.debug("Test object does not have test_media_dir in metadata (test: {}, outcome: {})", 
                               test_attributes.get("name", "unknown"), test_outcome)
    except Exception as e:
        error_message = e

    return render_template(
        'testreport.html',
        utils=utils,
        json_report=json_report,
        error_message=error_message,
        environment=environment,
        timestamp=timestamp
    )


@testsuite_bp.route('/testsuite/<environment>/report/<timestamp>/images/<test_media_dir>/<filename>', methods=["GET"])
@utils.require_oidc_login
def serve_test_image(environment: str, timestamp: str, test_media_dir: str, filename: str):
    """Sirve las imágenes de los reportes de pruebas
    
    Args:
        environment (str): Environment Name
        timestamp (str): Test Execution Timestamp
        test_media_dir (str): Test media directory name (nombre de la carpeta de la prueba)
        filename (str): Image filename
        
    Returns:
        File: Image file
    """
    LOGGER = utils.logger
    image_dir = f"/data/idp_testing_reports/{environment}/{timestamp}/{test_media_dir}"
    
    LOGGER.debug("Serving image request - environment: {}, timestamp: {}, test_media_dir: {}, filename: {}", 
                 environment, timestamp, test_media_dir, filename)
    LOGGER.debug("Image directory path: '{}'", image_dir)
    
    if not filename.endswith('.png') or not filename.startswith('test-failed-'):
        LOGGER.warn("Invalid file requested: '{}'", filename)
        return "Invalid file", 403
    
    image_path = Path(image_dir)
    if not image_path.exists():
        LOGGER.error("Image directory does not exist: '{}'", image_dir)
        return f"Directory not found: {image_dir}", 404
    
    file_path = image_path / filename
    if not file_path.is_file():
        LOGGER.error("Image file does not exist: '{}'", file_path)
        return f"File not found: {file_path}", 404
    
    LOGGER.debug("Serving image file: '{}'", file_path)
    return send_from_directory(str(image_path), filename, mimetype='image/png')

