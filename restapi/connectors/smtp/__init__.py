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
        self.variables = self.variables.copy()
        self.variables.update(kwargs)

        if port := self.variables.get("port"):
            port = Env.to_int(port)

        host = self.variables.get("host")

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

        if self.variables.get("username") and self.variables.get("password"):
            log.verbose("Authenticating SMTP")
            smtp.login(self.variables.get("username"), self.variables.get("password"))

        self.smtp = smtp
        return self

    def disconnect(self):
        self.disconnected = True
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

        if not to_address:
            to_address = self.variables.get("admin")
        if not to_address:
            log.error("Skipping send email: destination address not configured")
            return False

        if not from_address:
            from_address = self.variables.get("noreply")
        if not from_address:
            from_address = self.variables.get("admin")
        if not from_address:
            log.error("Skipping send email: from address not configured")
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
        except SMTPException as e:
            log.error("Unable to send email to {} ({})", to_address, e)
            return False
        except BaseException as e:
            log.error(str(e))
            return False
