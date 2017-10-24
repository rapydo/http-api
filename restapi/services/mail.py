# -*- coding: utf-8 -*-
import os

from utilities.email import send_mail as send
from utilities.logs import get_logger

log = get_logger(__name__)


def send_mail(body, subject, to_address=None, from_address=None):

    try:
        host = os.environ.get("SMTP_HOST")
        port = os.environ.get("SMTP_PORT")
        username = os.environ.get("SMTP_USERNAME")
        password = os.environ.get("SMTP_PASSWORD")

        if from_address is None:
            from_address = os.environ.get("SMTP_ADMIN")

        if to_address is None:
            to_address = os.environ.get("SMTP_ADMIN")

        return send(
            body, subject, to_address, from_address,
            smtp_host=host,
            smtp_port=port,
            username=username,
            password=password
        )

    except BaseException as e:
        log.error(str(e))
        return False
