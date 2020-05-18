# -*- coding: utf-8 -*-
import os
import socket
import datetime
import pytz

from restapi.confs import TESTING

if TESTING:
    from restapi.services.mailmock import SMTP, SMTP_SSL
else:
    from smtplib import SMTP, SMTP_SSL  # pragma: no cover

from smtplib import SMTPException, SMTPAuthenticationError

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from restapi.utilities.logs import log

# TODO: configure HOST with gmail, search example online
# Sending e-mails in python, more info: https://pymotw.com/3/smtplib


def get_smtp_client(smtp_host, smtp_port, username=None, password=None):
    ###################
    # https://stackabuse.com/how-to-send-emails-with-gmail-using-python/

    if smtp_port is not None:
        if isinstance(smtp_port, str) and smtp_port.isnumeric():
            smtp_port = int(smtp_port)
        if not isinstance(smtp_port, int):
            log.error("Invalid SMTP port: {}", smtp_port)
            return None

    if not smtp_port:
        smtp = SMTP(smtp_host)
    elif smtp_port == 465:
        smtp = SMTP_SSL(smtp_host)
    else:
        smtp = SMTP(smtp_host)

    smtp.set_debuglevel(0)
    if not smtp_port:
        log.verbose("Connecting to {}", smtp_host)
    else:
        log.verbose("Connecting to {}:{}", smtp_host, smtp_port)
        try:
            smtp.connect(smtp_host, smtp_port)
            smtp.ehlo()
        except socket.gaierror as e:
            log.error(str(e))
            return None

    if username and password:
        log.verbose("Authenticating SMTP")
        try:
            smtp.login(username, password)
        except SMTPAuthenticationError as e:
            log.error(str(e))
            return None
    return smtp


def send_mail_is_active():

    host = os.environ.get("SMTP_HOST")

    return host and host.strip()


def test_smtp_client():
    host = os.environ.get("SMTP_HOST")
    port = os.environ.get("SMTP_PORT")
    username = os.environ.get("SMTP_USERNAME")
    password = os.environ.get("SMTP_PASSWORD")

    smtp = get_smtp_client(host, port, username, password)
    if smtp is None:
        return False

    smtp.quit()
    return True


def send(
    body,
    subject,
    to_address,
    from_address,
    smtp_host='localhost',
    smtp_port=587,
    cc=None,
    bcc=None,
    username=None,
    password=None,
    html=False,
    plain_body=None,
):

    if not smtp_host:
        log.error("Skipping send email: smtp host not configured")
        return False

    if not from_address:
        log.error("Skipping send email: from address not configured")
        return False

    if not to_address:
        log.error("Skipping send email: destination address not configured")
        return False

    smtp_client = get_smtp_client(smtp_host, smtp_port, username, password)
    if smtp_client is None:
        log.error(
            "Unable to send email: client initialization failed ({}:{})",
            smtp_host,
            smtp_port
        )
        return False

    with smtp_client as smtp:

        try:

            dest_addresses = [to_address]

            date_fmt = "%a, %b %d, %Y at %I:%M %p %z"
            if html:
                msg = MIMEMultipart('alternative')
            else:
                msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = from_address
            msg['To'] = to_address
            if cc is None:
                pass
            elif isinstance(cc, str):
                msg['Cc'] = cc
                dest_addresses.append(cc.split(","))
            elif isinstance(cc, list):
                msg['Cc'] = ",".join(cc)
                dest_addresses.append(cc)
            else:
                log.warning("Invalid CC value: {}", cc)
                cc = None

            if bcc is None:
                pass
            elif isinstance(bcc, str):
                msg['Bcc'] = bcc
                dest_addresses.append(bcc.split(","))
            elif isinstance(bcc, list):
                msg['Bcc'] = ",".join(bcc)
                dest_addresses.append(bcc)
            else:
                log.warning("Invalid BCC value: {}", bcc)
                bcc = None

            msg['Date'] = datetime.datetime.now(pytz.utc).strftime(date_fmt)

            if html:
                if plain_body is None:
                    log.warning("Plain body is none")
                    plain_body = body
                part1 = MIMEText(plain_body, 'plain')
                part2 = MIMEText(body, 'html')
                msg.attach(part1)
                msg.attach(part2)

            try:
                log.verbose("Sending email to {}", to_address)

                smtp.sendmail(from_address, dest_addresses, msg.as_string())

                log.info(
                    "Successfully sent email to {} [cc={}], [bcc={}]",
                    to_address, cc, bcc
                )
                smtp.quit()
                return True
            except SMTPException:
                log.error("Unable to send email to {}", to_address)
                smtp.quit()
                return False

        except BaseException as e:
            log.error(str(e))
            return False

    return False


def send_mail(
    body,
    subject,
    to_address=None,
    from_address=None,
    cc=None,
    bcc=None,
    plain_body=None,
):

    try:
        host = os.environ.get("SMTP_HOST")
        port = os.environ.get("SMTP_PORT")
        username = os.environ.get("SMTP_USERNAME")
        password = os.environ.get("SMTP_PASSWORD")

        if not from_address:
            from_address = os.environ.get("SMTP_NOREPLY")
        if not from_address:
            from_address = os.environ.get("SMTP_ADMIN")

        if not to_address:
            to_address = os.environ.get("SMTP_ADMIN")

        if plain_body is None:
            return send(
                body,
                subject,
                to_address,
                from_address,
                smtp_host=host,
                smtp_port=port,
                username=username,
                cc=cc,
                bcc=bcc,
                password=password,
            )
        else:
            return send(
                body,
                subject,
                to_address,
                from_address,
                smtp_host=host,
                smtp_port=port,
                username=username,
                password=password,
                html=True,
                plain_body=plain_body,
            )

    except BaseException as e:
        log.error(str(e))
        return False
