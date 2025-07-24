
from flask import Blueprint, jsonify, render_template, request
import utils
from forms import ClientCreationForm

clientcreation_bp = Blueprint('clientcreation', __name__)



@clientcreation_bp.route('/clientcreation', methods=["GET", "POST"])
def clientcreation_form():
    """Renders and processes Request Client form"""
    logger = utils.getLogger()
    config = utils.getConfig(logger=logger)
    form = ClientCreationForm()
    # Set choices dynamically
    form.integrationType.choices = [(t, t) for t in utils.getIntegrationTypes(logger=logger, config=config)]
    form.realmType.choices = [(r, r) for r in utils.getRealmTypes(logger=logger, config=config)]

    # Determine selected realmType (from form or default)
    selectedRealmType = form.realmType.data or (form.realmType.choices[0][0] if form.realmType.choices else None)
    workspaces = utils.getRealmTypeWorkspaces(logger=logger, realmType=selectedRealmType, config=config) if selectedRealmType else []
    form.workspace.choices = [(w, w) for w in workspaces]

    if form.validate_on_submit():
        # Process form data here
        logger.debug(f"Received data: {form.data}")
        # Redirect or render feedback
        return render_template(
            'clientcreation_feedback.html',
            utils=utils,
            config=config
        )

    return render_template(
        'clientcreation_form.html',
        form=form,
        utils=utils,
        config=config
    )


@clientcreation_bp.route('/clientcreation/workspaces', methods=['GET'])
def get_workspaces():
    logger = utils.getLogger()
    config = utils.getConfig(logger=logger)
    realm_type = request.args.get('realmType')
    logger.debug(f"Fetching workspaces for realmType: {realm_type}")
    workspaces = utils.getRealmTypeWorkspaces(logger=logger, realmType=realm_type, config=config) if realm_type else []
    return jsonify(workspaces)