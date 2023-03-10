from flask import current_app as app
from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from opencve.controllers.main import main
from opencve.controllers.tags import UserTagController
from opencve.models.cve import Cve
from opencve.models.tags import CveTag, UserTag
from opencve.extensions import db
from opencve.forms import (
    ChangeEmailForm,
    ChangePasswordForm,
    FiltersNotificationForm,
    MailNotificationsForm,
    MailTestNotificationsForm,
    WebhookTestNotificationsForm,
    TagForm,
    WebhookUrlForm,
)
import json

# test email notification
from celery.utils.log import get_task_logger
from flask_user import EmailError
from opencve.extensions import user_manager
from opencve.tasks import *
from opencve.commands import utils

logger = get_task_logger(__name__)


@main.route("/account/subscriptions", methods=["GET"])
@login_required
def subscriptions():
    return render_template("profiles/subscriptions.html")


@main.route("/account/notifications", methods=["GET", "POST"])
@login_required
def notifications():
    """
    webhook_test_notifications_form = WebhookTestNotificationsForm (

        obj=current_user,
       
        
    )
    mail_test_notifications_form = MailTestNotificationsForm(
        obj=current_user,
    )
    """

    mail_notifications_form = MailNotificationsForm(
        obj=current_user,
        enable_mail="yes" if current_user.enable_notifications else "no",
        enable_webhook="yes" if current_user.webhook else "no",
        frequency=current_user.frequency_notifications.code,
    )
    webhook_url_form = WebhookUrlForm(
        obj=current_user,
        webhook_url = current_user.webhook_url,
    )
    

    filters = current_user.filters_notifications or {"event_types": [], "cvss": 0}
    filters_notifications_form = FiltersNotificationForm(
        obj=current_user,
        new_cve=True if "new_cve" in filters["event_types"] else False,
        first_time=True if "first_time" in filters["event_types"] else False,
        references=True if "references" in filters["event_types"] else False,
        cvss=True if "cvss" in filters["event_types"] else False,
        cpes=True if "cpes" in filters["event_types"] else False,
        summary=True if "summary" in filters["event_types"] else False,
        cwes=True if "cwes" in filters["event_types"] else False,
        cvss_score=filters["cvss"],
    )

    if request.method == "POST":
        form_name = request.form["form-name"]

        if (
            form_name == "mail_notifications_form"
            and mail_notifications_form.validate()
        ):

     
            current_user.enable_notifications = (
                True if mail_notifications_form.enable_mail.data == "yes" else False
            )
            current_user.webhook = (
                True if mail_notifications_form.enable_webhook.data == "yes" else False
            )
            current_user.frequency_notifications = (
                mail_notifications_form.frequency.data
            )
            db.session.commit()

            flash(
                "Your notifications setting has been changed successfully.", "success"
            )
            return redirect(url_for("main.notifications"))

        if (
            form_name == "filters_notifications_form"
            and filters_notifications_form.validate()
        ):
            filters = {
                "event_types": [],
                "cvss": filters_notifications_form.cvss_score.data,
            }

            for typ in [
                "new_cve",
                "first_time",
                "references",
                "cvss",
                "cpes",
                "cwes",
                "summary",
            ]:
                if getattr(filters_notifications_form, typ).data:
                    filters["event_types"].append(typ)

            current_user.filters_notifications = filters
            db.session.commit()

            flash(
                "Your notifications setting has been changed successfully.", "success"
            )
        if form_name == "webhook_url_form":
            current_user.webhook_url = (

                webhook_url_form.webhook_url.data
            )
            db.session.commit()
            flash(
                "Webhook URL updated",
                "success",
            )
            return redirect(url_for("main.notifications"))

        """
        if form_name == "mail_test_notifications_form":
            # send test email notification
            try:
                user_manager.email_manager.send_user_testmail(
                    current_user,
                    **{
                        "subject": "Test notification from OpenCVE",
                        "body": "This message was sent for testing purposes to validate your user profile email settings.",
                    },
                )
                logger.info("Test notification sent to: {}".format(current_user.email))
            except EmailError as e:
                logger.error(f"EmailError : {e}")

            flash(
                "Test notification was sent to:  {} .".format(current_user.email),
                "success",
            )
            return redirect(url_for("main.notifications"))
            
        if form_name == "webhook_test_notifications_form":
            # send test webhook notification
           
            try:
                user_manager.email_manager.send_user_test_webhook(
                    current_user,
                    **{
                        "subject": "Test Webhook from OpenCVE",
                        "body": "This message was sent for testing purposes to validate your user profile Webhook settings.",
                    },
                )
                logger.info("Test webhook sent to: {}".format(current_user.email))
            except EmailError as e:
                logger.error(f"EmailError : {e}")

            flash(
                "Test webhook notification was sent to:  {} .".format(current_user.email),
                "success",
            )
            return redirect(url_for("main.notifications"))
            
            
            #send test webhook report (can be implemented to mail)
            
            # To test your webhook report without the celery tasks
            # Create one or multiple new test cves and do the handle task in a test context to send a test webhook 
            #Create test cve files
            
            test_cve_file = open("/app/venv/lib/python3.8/site-packages/opencve/views/test_new_cve.json","r")
            test_cve = json.load(test_cve_file)
            #utils.CveUtil.create_cve(test_cve) is done in handle_event_test

            #Test handle task
            try :
                handle_events_test(test_cve)
                handle_alerts_test()
                handle_reports_test_webhook() # can be created to test mail too
            except ValueError as e:
                logger.error(f"{e}")
                
            flash(
                "Test webhook report was sent to:  {} .".format(current_user.email),
                "success",
            )
            return redirect(url_for("main.notifications"))
        """



    return render_template(
        "profiles/notifications.html",
        mail_notifications_form=mail_notifications_form,
        filters_notifications_form=filters_notifications_form,
        #mail_test_notifications_form=mail_test_notifications_form,
        #webhook_test_notifications_form=webhook_test_notifications_form,
        webhook_url_form=webhook_url_form,
    )


@main.route("/account/tags", methods=["GET", "POST"])
@login_required
def tags():
    tags, _, pagination = UserTagController.list(
        {**request.args, "user_id": current_user.id}
    )
    tag_form = TagForm()

    # Form has been submitted
    if request.method == "POST" and tag_form.validate():

        # Check if the tag doesn't already exist
        if UserTag.query.filter_by(
            user_id=current_user.id, name=tag_form.name.data
        ).first():
            flash("This tag already exists.", "error")

        # Create the new tag
        else:
            tag = UserTag(
                user=current_user,
                name=tag_form.name.data,
                description=tag_form.description.data,
                color=tag_form.color.data,
            )
            db.session.add(tag)
            db.session.commit()

            flash(f"The tag {tag.name} has been successfully added.", "success")
            return redirect(
                url_for("main.edit_tag", tag=tag.name, page=request.args.get("page"))
            )

    return render_template(
        "profiles/tags.html",
        tags=tags,
        form=tag_form,
        pagination=pagination,
        mode="create",
    )


@main.route("/account/tags/<string:tag>", methods=["GET", "POST"])
@login_required
def edit_tag(tag):
    tag = UserTagController.get({"user_id": current_user.id, "name": tag})
    if not tag:
        return redirect(url_for("main.tags"))

    tag_form = TagForm(obj=tag, color=tag.color)

    if request.method == "POST" and tag_form.validate():

        # Prohibit name change
        if tag_form.name.data != tag.name:
            return redirect(url_for("main.tags"))

        # Update the tag
        tag_form.populate_obj(tag)
        tag.color = tag_form.color.data
        db.session.commit()

        flash(f"The tag {tag.name} has been successfully updated.", "success")
        return redirect(
            url_for("main.edit_tag", tag=tag.name, page=request.args.get("page"))
        )

    tags, _, pagination = UserTagController.list(
        {**request.args, "user_id": current_user.id}
    )

    return render_template(
        "profiles/tags.html",
        tags=tags,
        form=tag_form,
        pagination=pagination,
        mode="update",
    )


@main.route("/account/tags/<string:tag>/delete", methods=["GET", "POST"])
@login_required
def delete_tag(tag):
    tag = UserTagController.get({"user_id": current_user.id, "name": tag})
    if not tag:
        return redirect(url_for("main.tags"))

    count = (
        db.session.query(Cve.id)
        .join(CveTag)
        .filter(CveTag.user_id == current_user.id)
        .filter(CveTag.tags.contains([tag.name]))
        .count()
    )

    if count > 0:
        flash(
            f"The tag {tag.name} is still associated to {count} CVE(s), detach them before removing the tag.",
            "error",
        )
        return redirect(url_for("main.tags"))

    # Confirmation page
    if request.method == "GET":
        return render_template("profiles/delete_tag.html", tag=tag, count=count)

    # Delete the tag
    else:
        db.session.delete(tag)
        db.session.commit()
        flash(f"The tag {tag.name} has been deleted.", "success")
        return redirect(url_for("main.tags"))
