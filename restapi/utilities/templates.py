import os

import jinja2

from restapi.config import CUSTOM_PACKAGE, MODELS_DIR
from restapi.utilities.logs import log


def get_html_template(template_file, replaces):

    template_path = os.path.join(os.curdir, CUSTOM_PACKAGE, MODELS_DIR, "emails")

    if not os.path.exists(template_path):
        log.info("Template not found: {}", template_file)
        return None

    try:
        templateLoader = jinja2.FileSystemLoader(searchpath=template_path)
        templateEnv = jinja2.Environment(loader=templateLoader, autoescape=True)
        template = templateEnv.get_template(template_file)

        return template.render(**replaces)
    # except jinja2.exceptions.TemplateNotFound as e:
    #     log.error("Template not found: {} ({})", template_file, e)
    #     return None
    except BaseException as e:
        log.error("Error loading template {}: {}", template_file, e)
        return None
