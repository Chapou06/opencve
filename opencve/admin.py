import datetime

import arrow
from flask import abort
from flask_admin import AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_user import current_user

from sqlalchemy import desc, func
from sqlalchemy.orm import joinedload
from wtforms import PasswordField,BooleanField, validators
from flask import current_app as app
from flask import flash, redirect, request, url_for
from flask_login import current_user

from opencve.controllers.main import main
from opencve.controllers.tags import UserTagController
from opencve.models.cve import Cve
from opencve.models.tags import CveTag, UserTag
from opencve.extensions import db
from opencve.forms import (
   
    MailTestNotificationsForm,
    WebhookTestNotificationsForm,
    WebhookAddCveForm,
 
)
import json
from flask_user import EmailError
from opencve.extensions import user_manager
from opencve.tasks import *
from opencve import utils




class AuthModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.admin

    def inaccessible_callback(self, name, **kwargs):
        abort(404)


class HomeView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.admin

    def inaccessible_callback(self, name, **kwargs):
        abort(404)

    @expose("/")
    def index(self):
        if (not current_user.is_authenticated) or (not current_user.admin):
            abort(404)

        # Import here to avoid circular dependencies
        from opencve.extensions import db
        from opencve.models import users_products, users_vendors
        from opencve.models.cve import Cve
        from opencve.models.products import Product
        from opencve.models.reports import Report
        from opencve.models.tasks import Task
        from opencve.models.users import User
        from opencve.models.vendors import Vendor

        # Numbers of users
        users = User.query.count()

        # Numbers of confirmed users
        confirmed_users = User.query.filter(User.email_confirmed_at.isnot(None)).count()

        # Numbers of CVEs
        cves = Cve.query.count()

        # Numbers of generated reports
        reports = Report.query.count()

        # Numbers of vendors
        vendors = Vendor.query.count()

        # Numbers of products
        products = Product.query.count()

        # Last task date
        task_date = "--"
        task = Task.query.order_by(Task.created_at.desc()).first()
        if task:
            task_date = task.created_at.strftime("%a, %d %b %Y %H:%M:%S")

        # Number of vendors per user
        user_vendors = (
            db.session.query(
                User.id,
                User.username,
                func.count(users_vendors.c.user_id).label("total"),
            )
            .join(users_vendors)
            .group_by(User.id, User.username)
            .order_by(desc("total"))
            .limit(10)
            .all()
        )

        # Number of products per user
        user_products = (
            db.session.query(
                User.id,
                User.username,
                func.count(users_products.c.user_id).label("total"),
            )
            .join(users_products)
            .group_by(User.id, User.username)
            .order_by(desc("total"))
            .limit(10)
            .all()
        )

        # Number of reports per user
        user_reports = (
            db.session.query(
                User.id, User.username, func.count(Report.user_id).label("total")
            )
            .join(Report)
            .group_by(User.id, User.username)
            .order_by(desc("total"))
            .limit(10)
            .all()
        )

        # Number of users per day
        users_by_day = (
            db.session.query(
                func.date_trunc("day", User.created_at), func.count(User.id)
            )
            .group_by(func.date_trunc("day", User.created_at))
            .order_by(func.date_trunc("day", User.created_at))
            .all()
        )
        days = {
            "day": [arrow.get(user[0]).strftime("%d/%m/%y") for user in users_by_day],
            "count": [user[1] for user in users_by_day],
        }

        # Keep the last week
        week = {"day": days["day"][-7::], "count": days["count"][-7::]}

        # Number of users per month
        users_by_month = (
            db.session.query(
                func.date_trunc("month", User.created_at), func.count(User.id)
            )
            .group_by(func.date_trunc("month", User.created_at))
            .order_by(func.date_trunc("month", User.created_at))
            .all()
        )
        months = {
            "month": [
                arrow.get(month[0]).strftime("%B %Y") for month in users_by_month
            ],
            "count": [month[1] for month in users_by_month],
        }

        return self.render(
            "admin/index.html",
            statistics={
                "Total users": users,
                "Confirmed users": confirmed_users,
                "Total CVEs": cves,
                "Total reports": reports,
                "Total vendors": vendors,
                "Total products": products,
                "Last task": task_date,
            },
            users={
                "vendors": user_vendors,
                "products": user_products,
                "reports": user_reports,
            },
            week=week,
            days=days,
            months=months,
        )

    @expose("/tasks")
    def tasks(self):
        from .extensions import db
        from .models.tasks import Task

        tasks = (
            db.session.query(Task.created_at, Task.id, func.count(Task.id))
            .join(Task.changes)
            .group_by(Task)
            .order_by(Task.created_at.desc())
            .all()
        )

        return self.render("admin/tasks.html", tasks=tasks)

    @expose("/tasks/<id>")
    def task(self, id):
        from .models.tasks import Task
        from .models.changes import Change

        task = Task.query.get(id)
        changes = (
            Change.query.options(joinedload("cve"))
            .options(joinedload("events"))
            .filter_by(task_id=id)
            .order_by(Change.created_at.desc())
            .all()
        )
    @expose("/test",methods=["GET", "POST"])
    def test(self):
        
        webhook_test_notifications_form = WebhookTestNotificationsForm (
        obj=current_user,
        )
        webhook_add_cve_form = WebhookAddCveForm (
            obj = current_user
        )

        mail_test_notifications_form = MailTestNotificationsForm(
        obj=current_user,
        )
        if request.method == "POST":
            form_name = request.form["form-name"]


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
            
            if form_name == "webhook_add_cve_form":
                
                # To test your webhook report without the celery tasks
                # Create one or multiple new test cves and do the handle task in a test context to send a test webhook 
                #Create test cve files
                test_cve_file = open("/app/venv/lib/python3.8/site-packages/opencve/views/test_new_cve.json","r")
                test_cve = json.load(test_cve_file)
                #utils.CveUtil.create_cve(test_cve) is done in handle_event_test

                #Test handle task
                new_id = webhook_add_cve_form.jsonmod.data
                test_cve_mod = utils.add_test_json(test_cve , new_id)
                
                try :
                    handle_events_test(test_cve_mod)
                    
                except ValueError as e:
                    logger.error(f"{e}")
                    
                flash(
                    "Successfully added cve to database",
                    "success",
                )
                
            
                
            if form_name == "webhook_test_notifications_form":
                # send test webhook notification
                """
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
                """
                
                #send test webhook report (can be implemented to mail)
                
               
                
                
                try :
                    
                    handle_alerts_test()
                    handle_reports_test_() 
                   #handle_reports_test_mail()
                    
                except ValueError as e:
                    logger.error(f"{e}")
                    
                flash(
                    "Test webhook report was sent to:  {} .".format(current_user.email),
                    "success",
                )
                
            



        return self.render("admin/test.html",mail_test_notifications_form=mail_test_notifications_form,webhook_add_cve_form=webhook_add_cve_form,
        webhook_test_notifications_form=webhook_test_notifications_form)


class UserModelView(AuthModelView):
    page_size = 20
    create_modal = False
    edit_modal = False
    can_view_details = True
    column_filters = column_searchable_list = ["username", "email"]
    column_list = ("username", "email", "created_at", "is_confirmed")
    column_details_list = (
        "username",
        "email",
        "webhook_url",
        "created_at",
        "updated_at",
        "email_confirmed_at",
        "enable_notifications",
        "filters_notifications",
        "frequency_notifications",
        "first_name",
        "last_name",
        "active",
        "admin",
        "webhook",
        "vendors",
        "products",
    )
    column_formatters_detail = dict(
        vendors=lambda v, c, m, p: ", ".join([v.name for v in m.vendors]),
        products=lambda v, c, m, p: ", ".join([p.name for p in m.products]),
    )

    # The real `password` attribute is not displayed. Instead we use 2
    # password inputs : one for the create user form (required) and the
    # other for the edit form (optional).
    form_args = dict(email=dict(validators=[validators.Email()]))
    form_excluded_columns = "password"
    form_extra_fields = {
        "create_password": PasswordField("Password", [validators.DataRequired()]),
        "edit_password": PasswordField("Password"),
        "webhook": BooleanField(),
    }
    form_widget_args = {
        "edit_password": {
            "placeholder": "Don't fill this input to keep the password unchanged",
        }
    }
    form_create_rules = (
        "username",
        "email",
        "create_password",
        "first_name",
        "last_name",
        "active",
        "admin",
        "webhook",
    )
    form_edit_rules = (
        "username",
        "email",
        "edit_password",
        "first_name",
        "last_name",
        "active",
        "admin",
        "webhook",
    )

    def on_model_change(self, form, User, is_created):
        if is_created:
            User.set_password(form.create_password.data)
            User.email_confirmed_at = datetime.datetime.utcnow()
        else:
            if form.edit_password.data.strip():
                User.set_password(form.edit_password.data)


class CveModelView(AuthModelView):
    page_size = 20
    can_create = False
    can_edit = False
    can_delete = False
    can_view_details = True
    column_filters = ["cve_id", "summary", "cvss2", "cvss3", "updated_at"]
    column_searchable_list = ["cve_id", "summary", "cvss2", "cvss3"]
    column_list = ("cve_id", "updated_at", "cvss2", "cvss3")


class EventModelView(AuthModelView):
    page_size = 20
    can_create = False
    can_edit = False
    can_delete = False
    can_view_details = True
    column_filters = column_searchable_list = ["type", "created_at"]
    column_list = ("cve", "type", "created_at")


class VendorModelView(AuthModelView):
    page_size = 20
    create_modal = False
    edit_modal = False
    can_view_details = True
    column_filters = column_searchable_list = ["name"]
    column_list = ["name", "created_at"]
    column_details_list = ["name", "users", "created_at", "updated_at"]
    column_formatters_detail = dict(users=lambda v, c, m, p: m.users)


class ProductModelView(AuthModelView):
    page_size = 20
    create_modal = False
    edit_modal = False
    can_view_details = True
    column_filters = column_searchable_list = ["name"]
    column_list = ["name", "vendor", "created_at"]
    column_details_list = ["vendor", "name", "users", "created_at", "updated_at"]
    column_formatters_detail = dict(users=lambda v, c, m, p: m.users)
