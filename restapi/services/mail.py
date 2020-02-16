# -*- coding: utf-8 -*-
import os
import socket
import datetime
import pytz

from smtplib import SMTP, SMTP_SSL
from smtplib import SMTPException, SMTPAuthenticationError

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from restapi.confs import MODELS_DIR, CUSTOM_PACKAGE

from restapi.utilities.logs import log

# TODO: configure HOST with gmail, search example online

"""
Sending e-mails in python, more info:
https://pymotw.com/3/smtplib/
"""


def get_smtp_client(smtp_host, smtp_port, username=None, password=None):
    ###################
    # https://stackabuse.com/how-to-send-emails-with-gmail-using-python/
    if smtp_port == '465':
        smtp = SMTP_SSL(smtp_host)
    else:
        smtp = SMTP(smtp_host)
        # if this is 587 we might need also
        # smtp.starttls()

    ###################
    smtp.set_debuglevel(0)
    log.verbose("Connecting to {}:{}", smtp_host, smtp_port)
    try:
        smtp.connect(smtp_host, smtp_port)
        smtp.ehlo()
    except socket.gaierror as e:
        log.error(str(e))
        return None

    if username is not None and password is not None:
        log.verbose("Authenticating SMTP")
        try:
            smtp.login(username, password)
        except SMTPAuthenticationError as e:
            log.error(str(e))
            return None
    return smtp


def send_mail_is_active():
    host = os.environ.get("SMTP_HOST")
    port = os.environ.get("SMTP_PORT")

    if host is None or port is None:
        return False

    if host.strip() == '':
        return False

    if port.strip() == '':
        return False

    return True


def test_smtp_client():
    host = os.environ.get("SMTP_HOST")
    port = os.environ.get("SMTP_PORT")
    username = os.environ.get("SMTP_USERNAME")
    password = os.environ.get("SMTP_PASSWORD")

    with get_smtp_client(host, port, username, password) as smtp:
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

    if smtp_host is None:
        log.error("Skipping send email: smtp host not configured")
        return False

    if from_address is None:
        log.error("Skipping send email: from address not configured")
        return False

    if to_address is None:
        log.error("Skipping send email: destination address not configured")
        return False

    with get_smtp_client(smtp_host, smtp_port, username, password) as smtp:

        if smtp is None:
            log.error("Unable to send email: client initialization failed")
            return False

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

        if from_address is None:
            from_address = os.environ.get("SMTP_NOREPLY")
        if from_address is None:
            from_address = os.environ.get("SMTP_ADMIN")

        if to_address is None:
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


def get_html_template(template_file, replaces):
    """
    # FIXME: use jinja2 instead :)
    """
    # Deprecated since 0.7.1
    log.warning(
        "Deprecated template, convert it with jinja and import get_html_template " +
        "from restapi.utilities.templates instead"
    )
    path = os.path.join(os.curdir, CUSTOM_PACKAGE, MODELS_DIR)
    template = os.path.join(path, "emails", template_file)

    html = None
    if os.path.isfile(template):
        with open(template, 'r') as f:
            html = f.read()
    else:
        log.warning("Unable to find email template: {}", template)

    if html is None:
        return html

    for r in replaces:
        val = replaces.get(r)
        key = "%%" + r + "%%"
        html = html.replace(key, val)

    return html
