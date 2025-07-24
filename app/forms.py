from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, FieldList, SelectMultipleField
from wtforms.validators import DataRequired, Email

class ClientCreationForm(FlaskForm):
    integrationType = SelectField(
        'Integration Type',
        choices=[],
        validators=[DataRequired()]
    )
    realmType = SelectField(
        'Realm Type',
        choices=[],
        validators=[DataRequired()]
    )
    workspace = SelectMultipleField(
        'Workspace',
        choices=[],
        validators=[DataRequired()]
    )
    clientName = StringField(
        'Client Name',
        validators=[DataRequired()]
    )
    ownerEmail = StringField(
        'Owner Email',
        validators=[DataRequired(), Email()]
    )
    redirectUris = FieldList(
        StringField('Redirect URI', validators=[DataRequired()]),
        min_entries=1,
        max_entries=2
    )
