# -*- coding: utf-8 -*-
import smtplib
from email.mime.text import MIMEText
import os

from utilities.logs import get_logger

log = get_logger(__name__)


def send_mail(body, subject, to_address=None, from_address=None):

    try:
        host = os.environ.get("SMTP_HOST")

        if host is None:
            log.info("Skipping send email: smtp host not configured")
            return False

        if from_address is None:
            from_address = os.environ.get("SMTP_ADMIN")

        if from_address is None:
            log.warning(
                "Unable to send email: " +
                "both from address and default admin are missing")
            return False

        if to_address is None:
            to_address = os.environ.get("SMTP_ADMIN")

        if to_address is None:
            log.warning(
                "Unable to send email: " +
                "both destination address and default admin are missing")
            return False

        msg = MIMEText(body)

        # me == the sender's email address
        # you == the recipient's email address
        msg['Subject'] = subject
        msg['From'] = from_address
        msg['To'] = to_address

        s = smtplib.SMTP(host)
        s.send_message(msg)
        s.quit()

        log.debug("Mail sent to %s" % to_address)

        return True
    except BaseException as e:
        log.error(str(e))
        return False
