# -*- coding: utf-8 -*-

import os
import jinja2
from restapi.confs import MODELS_DIR, CUSTOM_PACKAGE
from restapi.utilities.logs import log


def get_html_template(template_file, replaces):

    try:
        template_path = os.path.join(os.curdir, CUSTOM_PACKAGE, MODELS_DIR, "emails")

        templateLoader = jinja2.FileSystemLoader(searchpath=template_path)
        templateEnv = jinja2.Environment(loader=templateLoader, autoescape=True)
        template = templateEnv.get_template(template_file)

        return template.render(**replaces)
    except jinja2.exceptions.TemplateNotFound as e:
        log.error("Template not found: {} ({})", template_file, e)
        return None
    except BaseException as e:
        log.error("Error loading template {}: {}", template_file, e)
        return None
