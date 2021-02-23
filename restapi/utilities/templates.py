import os
from typing import Any, Dict, Optional, Tuple

import html2text
import jinja2

from restapi.config import ABS_RESTAPI_PATH, CUSTOM_PACKAGE, MODELS_DIR
from restapi.connectors import CONNECTORS_FOLDER
from restapi.utilities.logs import log


def get_html_template(
    template_file: str, replaces: Dict[str, Any]
) -> Tuple[Optional[str], Optional[str]]:

    # Custom templates from project backend/models/email/
    template_path = os.path.join(
        os.curdir, CUSTOM_PACKAGE, MODELS_DIR, "emails", template_file
    )

    if not os.path.exists(template_path):
        # Core templates from restapi/connectors/smtp/templates/
        template_path = os.path.join(
            ABS_RESTAPI_PATH,
            CONNECTORS_FOLDER,
            "smtp",
            "templates",
            template_file,
        )

    if not os.path.exists(template_path):
        log.info("Template not found: {}", template_file)
        return None, None

    try:

        templateLoader = jinja2.FileSystemLoader(
            searchpath=os.path.dirname(template_path)
        )
        templateEnv = jinja2.Environment(loader=templateLoader, autoescape=True)
        template = templateEnv.get_template(template_file)

        html_body = template.render(**replaces)

        h2t = html2text.HTML2Text()
        h2t.unicode_snob = 1
        h2t.ignore_emphasis = True
        h2t.single_line_break = True
        plain_body = h2t.handle(html_body)

        return html_body, plain_body
    except BaseException as e:
        log.error("Error loading template {}: {}", template_file, e)
        return None, None
