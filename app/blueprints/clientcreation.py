from flask import Blueprint, render_template, request
import json
import utils

clientcreation_bp = Blueprint('clientcreation', __name__)


@clientcreation_bp.route('/clientcreation', methods=["GET"])
def clientcreation_form():
    """Renders Request Client form

    Returns:
        Template: Rendered HTML page with Request Client form
    """
    logger = utils.getLogger()
    config = utils.getConfig(logger=logger)


    return render_template(
        'clientcreation_form.html',
        utils=utils,
        config=config
    )

@clientcreation_bp.route('/clientcreation', methods=["POST"])
def clientcreation():
    """Process Request Client form

    Returns:
        Template: Rendered HTML page with Request Client form
    """
    logger = utils.getLogger()
    config = utils.getConfig(logger=logger)
    data = request.form.to_dict()
    logger.debug(f"Received data: {data}")

    return render_template(
        'clientcreation_feedback.html',
        utils=utils,
        config=config
    )
