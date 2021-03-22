import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate
from smtplib import SMTPAuthenticationError, SMTPException, SMTPServerDisconnected
from threading import Thread
from typing import List, Optional, Union

from restapi.config import TESTING
from restapi.connectors import Connector, ExceptionsList
from restapi.env import Env

# mypy: ignore-errors
if TESTING:
    from restapi.connectors.smtp.mailmock import SMTP, SMTP_SSL
else:
    from smtplib import SMTP, SMTP_SSL  # pragma: no cover

from restapi.utilities.logs import log


class Mail(Connector):
    def __init__(self) -> None:
        self.smtp: Optional[SMTP] = None
        super().__init__()
        # instance_variables is updated with custom variabiles in connect
        # and the used in the send method.
        # This way the send method will be able to use variabiles overridden in connect
        self.instance_variables = self.variables.copy()

    def get_connection_exception(self) -> ExceptionsList:
        return (socket.gaierror, SMTPAuthenticationError)

    def connect(self, **kwargs):
        self.instance_variables.update(kwargs)

        if port := self.instance_variables.get("port"):
            port = Env.to_int(port)

        host = self.instance_variables.get("host")

        if not port:
            smtp = SMTP(host)
            log.debug("Connecting to {}", host)
        elif port == 465:
            smtp = SMTP_SSL(host)
        else:
            smtp = SMTP(host)

        smtp.set_debuglevel(0)
        if port:
            log.debug("Connecting to {}:{}", host, port)
            smtp.connect(host, port)
            smtp.ehlo()

        if self.instance_variables.get("username") and self.instance_variables.get(
            "password"
        ):
            smtp.login(
                self.instance_variables.get("username"),
                self.instance_variables.get("password"),
            )

        self.smtp = smtp
        return self

    def disconnect(self) -> None:
        self.disconnected = True

        if not self.smtp:
            return None

        try:
            self.smtp.quit()
            self.smtp = None
        except SMTPServerDisconnected:  # pragma: no cover
            log.debug("SMTP is already disconnected")

        return None

    def is_connected(self) -> bool:

        if not self.smtp:
            return False

        try:
            status = self.smtp.noop()[0]
            return status == 250
        except SMTPServerDisconnected:  # pragma: no cover
            return False

    def send_async(
        self,
        body: str,
        subject: str,
        to_address: Optional[str] = None,
        from_address: Optional[str] = None,
        cc: Optional[Union[str, List[str]]] = None,
        bcc: Optional[Union[str, List[str]]] = None,
        plain_body: Optional[str] = None,
    ) -> None:
        thr = Thread(
            target=self.send,
            args=[body, subject, to_address, from_address, cc, bcc, plain_body],
        )
        thr.start()

        # in TESTING mode async mails are kept sync to simplify checks
        if TESTING:
            thr.join()

        # In async mode there is no return value
        # Because being sent asynchronously it is not possible to
        # synchronously know if the email is sent or not
        return None

    def send(
        self,
        body: str,
        subject: str,
        to_address: Optional[str] = None,
        from_address: Optional[str] = None,
        cc: Optional[Union[str, List[str]]] = None,
        bcc: Optional[Union[str, List[str]]] = None,
        plain_body: Optional[str] = None,
    ) -> bool:

        if not to_address:
            to_address = self.instance_variables.get("admin")
        if not to_address:
            log.error("Skipping send email: destination address not configured")
            return False

        if not from_address:
            from_address = self.instance_variables.get("noreply")
        if not from_address:
            from_address = self.instance_variables.get("admin")
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

            msg["Date"] = formatdate()

            if plain_body is not None:
                part1 = MIMEText(plain_body, "plain")
                part2 = MIMEText(body, "html")
                msg.attach(part1)
                msg.attach(part2)

            log.debug("Sending email to {}", to_address)

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
            # Why this disconnect? Because when trying to send an email to a non
            # existing email address the server could drop the connection. Then all the
            # following use of this connection will fail. Furthmore this expception is
            # pretty generic and may be raised due to errors in connection. In both
            # cases invalidate the connection and open a new one is a good choice
            self.disconnect()
            return False
        except BaseException as e:
            log.error(str(e))
            return False


instance = Mail()


def get_instance(
    verification: Optional[int] = None,
    expiration: Optional[int] = None,
    **kwargs: Union[Optional[str], int],
) -> "Mail":

    return instance.get_instance(
        verification=verification, expiration=expiration, **kwargs
    )
