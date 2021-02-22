import os

import jinja2

from restapi.config import ABS_RESTAPI_PATH, BACKEND_PACKAGE, CUSTOM_PACKAGE, MODELS_DIR
from restapi.connectors import CONNECTORS_FOLDER
from restapi.utilities.logs import log


def get_html_template(template_file, replaces):

    # Custom templates from project backend/models/email/
    template_path = os.path.join(
        os.curdir, CUSTOM_PACKAGE, MODELS_DIR, "emails", template_file
    )

    if not os.path.exists(template_path):
        # Core templates from restapi/connectors/smtp/templates/
        template_path = os.path.join(
            ABS_RESTAPI_PATH,
            BACKEND_PACKAGE,
            CONNECTORS_FOLDER,
            "smtp",
            "templates",
            template_file,
        )

    if not os.path.exists(template_path):
        log.info("Template not found: {}", template_file)
        return None

    try:
        templateLoader = jinja2.FileSystemLoader(
            searchpath=os.path.dirname(template_path)
        )
        templateEnv = jinja2.Environment(loader=templateLoader, autoescape=True)
        template = templateEnv.get_template(template_file)

        return template.render(**replaces)
    except BaseException as e:
        log.error("Error loading template {}: {}", template_file, e)
        return None
