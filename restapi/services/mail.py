# -*- coding: utf-8 -*-
import os

from utilities.email import send_mail as send
from utilities import helpers
from utilities import MODELS_DIR, CUSTOM_PACKAGE
from utilities.logs import get_logger

log = get_logger(__name__)


def send_mail_is_active():
    host = os.environ.get("SMTP_HOST")
    port = os.environ.get("SMTP_PORT")

    return host is not None and port is not None


def send_mail(
        body, subject,
        to_address=None, from_address=None,
        cc=None, bcc=None,
        plain_body=None):

    try:
        host = os.environ.get("SMTP_HOST")
        port = os.environ.get("SMTP_PORT")
        username = os.environ.get("SMTP_USERNAME")
        password = os.environ.get("SMTP_PASSWORD")

        if from_address is None:
            from_address = os.environ.get("SMTP_NOREPLY")
        if from_address is None:
            from_address = os.environ.get("SMTP_ADMIN")

        if to_address is None:
            to_address = os.environ.get("SMTP_ADMIN")

        if plain_body is None:
            return send(
                body, subject, to_address, from_address,
                smtp_host=host,
                smtp_port=port,
                username=username,
                cc=cc, bcc=bcc,
                password=password
            )
        else:
            return send(
                body, subject, to_address, from_address,
                smtp_host=host,
                smtp_port=port,
                username=username,
                password=password,
                html=True,
                plain_body=plain_body
            )

    except BaseException as e:
        log.error(str(e))
        return False


def get_html_template(template_file, replaces):
    path = helpers.current_dir(CUSTOM_PACKAGE, MODELS_DIR)
    template = os.path.join(path, "emails", template_file)

    html = None
    if os.path.isfile(template):
        with open(template, 'r') as f:
            html = f.read()

    if html is None:
        return html

    for r in replaces:
        val = replaces.get(r)
        key = "%%" + r + "%%"
        html = html.replace(key, val)

    return html
