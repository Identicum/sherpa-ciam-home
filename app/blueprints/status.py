from flask import abort, Blueprint, current_app, render_template
import status_report
import utils

status_bp = Blueprint('status', __name__)


@status_bp.route('/status/<environment>', methods=["GET"])
def status_page(environment: str):
    """Renders the public IDP Status Page (Grafana alerts + latest tests execution)

    Args:
        environment (str): Environment Name

    Returns:
        Template: Status Page Rendered HTML Page
    """
    if environment not in utils.getEnvironments(logger=current_app.logger, config=current_app.json_config):
        abort(404)
    environment_status = None
    error_message = None
    try:
        environment_status = status_report.run(logger=current_app.logger, environment=environment, config=current_app.json_config)
    except Exception as e:
        current_app.logger.error("Error building status for environment {}: {}", environment, e)
        error_message = current_app.messages.get('status.error')
    return render_template(
        'status.html',
        logger=current_app.logger,
        config=current_app.json_config,
        utils=utils,
        environment=environment,
        status=environment_status,
        error_message=error_message
    )
