# default values:
# 'admin': '', 'noreply': '', 'host': '', 'port': '', 'username': '', 'password': ''}


import datetime
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from smtplib import SMTPAuthenticationError, SMTPException

import pytz

from restapi.confs import TESTING
from restapi.connectors import Connector
from restapi.env import Env

if TESTING:
    from restapi.connectors.smtp.mailmock import SMTP, SMTP_SSL
else:
    from smtplib import SMTP, SMTP_SSL  # pragma: no cover

from restapi.utilities.logs import log


class Mail(Connector):
    def get_connection_exception(self):
        return (socket.gaierror, SMTPAuthenticationError)

    def connect(self, **kwargs):
        self.extended_variables = self.variables.copy()
        self.extended_variables.update(kwargs)

        if port := self.extended_variables.get("port"):
            port = Env.to_int(port)

        host = self.extended_variables.get("host")

        if not port:
            smtp = SMTP(host)
            log.verbose("Connecting to {}", host)
        elif port == 465:
            smtp = SMTP_SSL(host)
        else:
            smtp = SMTP(host)

        smtp.set_debuglevel(0)
        if port:
            log.verbose("Connecting to {}:{}", host, port)
            smtp.connect(host, port)
            smtp.ehlo()

        username = self.extended_variables.get("username")
        password = self.extended_variables.get("password")
        if username and password:
            log.verbose("Authenticating SMTP")
            smtp.login(username, password)

        self.smtp = smtp
        return self

    def disconnect(self):
        self.smtp.quit()
        self.smtp = None

    def send(
        self,
        body,
        subject,
        to_address=None,
        from_address=None,
        cc=None,
        bcc=None,
        plain_body=None,
    ):

        if not from_address:
            from_address = self.extended_variables.get("noreply")
        if not from_address:
            from_address = self.extended_variables.get("admin")
        if not from_address:
            log.error("Skipping send email: from address not configured")
            return False

        if not to_address:
            to_address = self.extended_variables.get("admin")
        if not to_address:
            log.error("Skipping send email: destination address not configured")
            return False

        try:

            if plain_body is not None:
                msg = MIMEMultipart("alternative")
            else:
                msg = MIMEText(body)

            msg["Subject"] = subject
            msg["From"] = from_address
            msg["To"] = to_address

            dest_addresses = [to_address]

            if cc is None:
                pass
            elif isinstance(cc, str):
                msg["Cc"] = cc
                dest_addresses.append(cc.split(","))
            elif isinstance(cc, list):
                msg["Cc"] = ",".join(cc)
                dest_addresses.append(cc)
            else:
                log.warning("Invalid CC value: {}", cc)
                cc = None

            if bcc is None:
                pass
            elif isinstance(bcc, str):
                msg["Bcc"] = bcc
                dest_addresses.append(bcc.split(","))
            elif isinstance(bcc, list):
                msg["Bcc"] = ",".join(bcc)
                dest_addresses.append(bcc)
            else:
                log.warning("Invalid BCC value: {}", bcc)
                bcc = None

            date_fmt = "%a, %b %d, %Y at %I:%M %p %z"
            msg["Date"] = datetime.datetime.now(pytz.utc).strftime(date_fmt)

            if plain_body is not None:
                part1 = MIMEText(plain_body, "plain")
                part2 = MIMEText(body, "html")
                msg.attach(part1)
                msg.attach(part2)

            try:
                log.verbose("Sending email to {}", to_address)

                self.smtp.sendmail(from_address, dest_addresses, msg.as_string())

                log.info(
                    "Successfully sent email to {} [cc={}], [bcc={}]",
                    to_address,
                    cc,
                    bcc,
                )
                return True
            # Cannot be tested because smtplib is mocked!
            except SMTPException:  # pragma: no cover
                log.error("Unable to send email to {}", to_address)
                return False

        # Cannot be tested because smtplib is mocked
        except BaseException as e:  # pragma: no cover
            log.error(str(e))
            return False
