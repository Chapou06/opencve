from flask import request, render_template

from opencve.controllers.main import main

# from opencve.controllers.cwes import get_cwes
from opencve.controllers.cwes import CweController
from flask_user import current_user, login_required

@main.route("/cwe")
@login_required
def cwes():
    objects, _, pagination = CweController.list(request.args)
    return render_template("cwes.html", cwes=objects, pagination=pagination)
