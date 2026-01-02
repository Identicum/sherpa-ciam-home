from flask import Blueprint, redirect, render_template, request, url_for
import utils

testrunner_bp = Blueprint('testrunner', __name__, template_folder='../templates')


@testrunner_bp.route('/testrunner/<environment>', methods=["GET"])
@utils.require_oidc_login
def testrunner_interface(environment: str):
    """Renders 'Test Runner' Test Execution Request Interface por the provided Environment

    Args:
        environment (str): Environment name

    Returns:
        Template: 'Test Runner' Test Execution Request Interface
    """
    LOGGER = utils.logger
    CUSTOM_EXEC_ENVS = utils.getCustomTestExecEnvNames(logger=LOGGER, environment=environment, config=utils.getConfig(LOGGER))
    ENV_AVAILABLE = utils.getEnvironmentTestAvailability(logger=LOGGER, environment=environment)
    return render_template(
        'testrunner.html',
        environment=environment,
        custom_exec_envs=CUSTOM_EXEC_ENVS,
        env_available=ENV_AVAILABLE,
        utils=utils
    )

@testrunner_bp.route('/testrunner/<environment>', methods=["POST"])
@utils.require_oidc_login
def testrunner_request_test(environment: str):
    """
    Requests test execution for the provided environment
    More specifically, places an `{environment}.execution` file in a directory mounted to the host.
    This schema requires the host machine to have a scheduled script execution which will run tests for each environment it finds a pid file for, then delete the file.

    Args:
        environment (str): Environment name
    """

    LOGGER = utils.logger

    exec_env = request.args.get("custom-exec", None)
    utils.requestTestExecution(logger=LOGGER, exec_env=exec_env, environment=environment)
    
    return redirect(url_for('testsuite.testsuite', environment=environment))