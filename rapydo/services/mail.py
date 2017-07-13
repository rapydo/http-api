# -*- coding: utf-8 -*-
import smtplib
from email.mime.text import MIMEText
import os

from rapydo.utils.logs import get_logger

log = get_logger(__name__)


def send_mail(body, subject, from_address, to_address):

    host = os.environ.get("SMTP_HOST")

    if host is None:
        log.info("Skipping send email: smtp host not configured")
        return False

    msg = MIMEText(body)

    # me == the sender's email address
    # you == the recipient's email address
    msg['Subject'] = subject
    msg['From'] = from_address
    msg['To'] = to_address

    # FIXME: read env var... it is available on detect?
    s = smtplib.SMTP('smtp.dockerize.io')
    s.send_message(msg)
    s.quit()

    log.debug("Mail sent to %s" % to_address)

    return True
