from celery import Celery
from flask_admin import Admin
from flask_debugtoolbar import DebugToolbarExtension
from flask_login import current_user
from flask_gravatar import Gravatar
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_user import UserManager, EmailManager
from flask_user.forms import EditUserProfileForm, RegisterForm, unique_email_validator
from flask_wtf import RecaptchaField
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from wtforms import validators, StringField
from opencve import opencve_webhook
from flask import render_template


class CustomUserManager(UserManager):
    """
    Add custom properties in default Flask-User objects.
    """

    def customize(self, app):
        def _unique_email_validator(form, field):
            """
            Check if the new email is unique. Skip this step if the
            email is the same as the current one.
            """
            if field.data.lower() == current_user.email.lower():
                return
            unique_email_validator(form, field)

        # Add the email field and make first and last names as not required
        class CustomUserProfileForm(EditUserProfileForm):
            first_name = StringField("First name")
            last_name = StringField("Last name")
            email = StringField(
                "Email",
                validators=[
                    validators.DataRequired(),
                    validators.Email(),
                    _unique_email_validator,
                ],
            )

        self.EditUserProfileFormClass = CustomUserProfileForm

        # Add the reCaptcha
        if app.config.get("DISPLAY_RECAPTCHA"):

            class CustomRegisterForm(RegisterForm):
                recaptcha = RecaptchaField()

            self.RegisterFormClass = CustomRegisterForm

        # Allow emails to be send using sendmail
        if app.config.get("EMAIL_ADAPTER") == "sendmail":
            from flask_user.email_adapters import SendmailEmailAdapter

            self.email_adapter = SendmailEmailAdapter(app)


class CustomEmailManager(EmailManager):

    def _render_and_send_webhook(self,email,user,template_filename,**kwargs):
        
        kwargs['app_name'] = self.user_manager.USER_APP_NAME
        kwargs['email'] = email
        kwargs['user'] = user
        kwargs['user_manager'] = self.user_manager

        subject = render_template(template_filename+'_subject.txt', **kwargs)
        subject = subject.replace('\n', ' ')
        subject = subject.replace('\r', ' ')

        html_message = render_template(template_filename+'_message.html', **kwargs)

        text_message = render_template(template_filename+'_message.txt', **kwargs)
    
        if user.is_webhook :
            opencve_webhook.send_opencve_alert(html_message,user)
        else :
            raise ValueError('Webhook profile only')
    
    def send_user_report(self, user, **kwargs):
        """Send the 'user report' email."""
        self._render_and_send_email(
            user.email,
            user,
            "emails/report",
            **kwargs,
        )
    def send_user_testmail(self, user, **kwargs):
        """Send the 'user test' email."""
        self._render_and_send_email(
            user.email,
            user,
            "emails/testmail",
            **kwargs,
        )
        #opencve_webhook.send_opencve_alert(f"{user.email}","testAPP")
    def send_user_test_webhook(self,user,**kwargs):
        "send the user test webhook"
        self._render_and_send_webhook(
            user.email,
            user,
            "emails/testmail",
            **kwargs,
        )
    def send_user_test_webhook_report(self,user,**kwargs):
        "send the user test webhook report"
        self._render_and_send_webhook(
            user.email,
            user,
            "emails/webhook",
            **kwargs,
        )
    


class FlaskCelery(Celery):
    """
    Provide the init_app function.
    """

    def __init__(self, *args, **kwargs):
        super(FlaskCelery, self).__init__(*args, **kwargs)

        if "app" in kwargs:
            self.init_app(kwargs["app"])

    def init_app(self, app):
        self.app = app
        self.conf.update(app.config.get("CELERY_CONF", {}))


# Debug toolbar
debug_toolbar = DebugToolbarExtension()

# CSRF protection
csrf = CSRFProtect()

# SQLAlchemy
db = SQLAlchemy(session_options={"autoflush": False})

# Flask gravatar
gravatar = Gravatar(
    size=100,
    rating="g",
    default="retro",
    force_default=False,
    use_ssl=True,
    base_url=None,
)

# Flask migrate
migrate = Migrate()

# Flask-User
user_manager = CustomUserManager(None, None, None)

# Celery
cel = FlaskCelery("opencve", include=["opencve.tasks"])

# Flask Limiter
limiter = Limiter(key_func=lambda: "Remove the default warning")
