from flask import current_app as app
from flask_login import current_user
from flask_user.forms import unique_email_validator
from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    PasswordField,
    RadioField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
    validators,
)

from opencve.constants import CVSS_SCORES, FREQUENCIES_TYPES
from flask_user.translation_utils import lazy_gettext as _ 


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField(
        "Password", validators=[validators.DataRequired("Password is required")]
    )
    new_password = PasswordField(
        "Password", validators=[validators.DataRequired("Password is required")]
    )
    submit = SubmitField("Change password")

    def validate(self):
        user_manager = app.user_manager

        if not super(ChangeEmailForm, self).validate():
            return False

        if not current_user or not user_manager.verify_password(
            self.password.data, current_user
        ):
            self.password.errors.append("Password is incorrect")
            return False

        return True

class WebhookUrlForm(FlaskForm):

    webhook_url = TextAreaField(_('Webhook Url (Warning : Replace Mail)'),render_kw={"rows": 10, "cols": 50}, validators=[validators.DataRequired()])
    submit = SubmitField("Save Change")

class ChangeEmailForm(FlaskForm):
    email = StringField(
        "New email",
        validators=[
            validators.DataRequired("Email is required"),
            validators.Email("Invalid email"),
            unique_email_validator,
        ],
    )
    password = PasswordField(
        "Password", validators=[validators.DataRequired("Password is required")]
    )
    submit = SubmitField("Change email")

    def validate(self):
        user_manager = app.user_manager

        if not super(ChangeEmailForm, self).validate():
            return False

        if not current_user or not user_manager.verify_password(
            self.password.data, current_user
        ):
            self.password.errors.append("Password is incorrect")
            return False

        return True
class WebhookAddCveForm(FlaskForm):
    jsonmod = TextAreaField(_('Enter the test CVE ID'))
    submit  = SubmitField("Add Test CVE")
    
class WebhookTestNotificationsForm(FlaskForm):
    
    submit = SubmitField("Send test webhook")
    
class MailTestNotificationsForm(FlaskForm):
    submit = SubmitField("Send test notification")



class MailNotificationsForm(FlaskForm):
    enable_mail = RadioField(
        "Enable email notifications", choices=[("yes", "Yes"), ("no", "No")]
    )
  
    enable_webhook = RadioField(
        "Enable webhook notifications", choices=[("yes", "Yes"), ("no", "No")]
    )
    frequency = SelectField("Email frequency", choices=FREQUENCIES_TYPES)
    submit = SubmitField("Save changes")




class FiltersNotificationForm(FlaskForm):
    new_cve = BooleanField("New CVE")
    first_time = BooleanField("Subscription appeared for the first time")
    references = BooleanField("Reference changed")
    cvss = BooleanField("CVSS changed")
    cpes = BooleanField("CPE changed")
    summary = BooleanField("Summary changed")
    cwes = BooleanField("CWE changed")
    cvss_score = SelectField("CVSS score", coerce=int, choices=CVSS_SCORES)
    submit = SubmitField("Save changes")


class TagForm(FlaskForm):
    name = StringField(
        "Name",
        validators=[
            validators.DataRequired("Name is required"),
            validators.Regexp(
                "^[a-zA-Z0-9\-_]+$",
                message="Only alphanumeric, dash and underscore characters are accepted",
            ),
        ],
    )
    description = StringField("Description")
    color = StringField(
        "Color",
        validators=[
            validators.DataRequired("Color is required"),
            validators.Regexp(
                "^#[0-9a-fA-F]{6}$", message="Color must be in hexadecimal format"
            ),
        ],
        default="#000000",
    )
    submit = SubmitField("Save")


class ActivitiesViewForm(FlaskForm):
    view = RadioField(
        "Activities View",
        choices=[
            ("all", "Display all activities"),
            ("subscriptions", "Display subscriptions activities"),
        ],
    )
