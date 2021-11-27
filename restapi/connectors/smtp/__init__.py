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

MAX_NUM_RETRIES = 3


class Mail(Connector):
    def __init__(self) -> None:
        self.smtp: Optional[SMTP] = None
        super().__init__()
        # instance_variables is updated with custom variabiles in connect
        # and the used in the send method.
        # This way the send method will be able to use variabiles overridden in connect
        self.instance_variables = self.variables.copy()

    @staticmethod
    def get_connection_exception() -> ExceptionsList:
        return (socket.gaierror, SMTPAuthenticationError)

    def connect(self, **kwargs: str) -> "Mail":
        self.instance_variables.update(kwargs)

        port = Env.to_int(self.instance_variables.get("port")) or 25

        host = self.instance_variables.get("host")

        if port == 465:
            smtp = SMTP_SSL(host)
        else:
            smtp = SMTP(host)

        smtp.set_debuglevel(0)
        log.debug("Connecting to {}:{}", host, port)
        smtp.connect(host, port)
        smtp.ehlo()

        username = self.instance_variables.get("username")
        password = self.instance_variables.get("password")
        if username and password:
            smtp.login(username, password)

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

    @classmethod
    def send_async(
        cls,
        body: str,
        subject: str,
        to_address: Optional[str] = None,
        from_address: Optional[str] = None,
        cc: Union[None, str, List[str]] = None,
        bcc: Union[None, str, List[str]] = None,
        plain_body: Optional[str] = None,
    ) -> None:

        thr = Thread(
            target=cls.send_async_thread,
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

    @classmethod
    def send_async_thread(
        cls,
        body: str,
        subject: str,
        to_address: Optional[str] = None,
        from_address: Optional[str] = None,
        cc: Union[None, str, List[str]] = None,
        bcc: Union[None, str, List[str]] = None,
        plain_body: Optional[str] = None,
        retry: int = 1,
    ) -> bool:

        with get_instance() as client:
            sent = client.send(
                body, subject, to_address, from_address, cc, bcc, plain_body
            )

        if sent or retry > MAX_NUM_RETRIES:
            return sent

        log.warning("Sending email again")  # pragma: no cover
        return cls.send_async_thread(  # pragma: no cover
            body=body,
            subject=subject,
            to_address=to_address,
            from_address=from_address,
            cc=cc,
            bcc=bcc,
            plain_body=plain_body,
            retry=retry + 1,
        )

    def send(
        self,
        body: str,
        subject: str,
        to_address: Optional[str] = None,
        from_address: Optional[str] = None,
        cc: Union[None, str, List[str]] = None,
        bcc: Union[None, str, List[str]] = None,
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
        except SMTPException as e:
            log.error("Unable to send email to {} ({})", to_address, e)
            return False
        except Exception as e:
            log.error(str(e))
            return False


instance = Mail()


def get_instance(
    verification: Optional[int] = None,
    expiration: Optional[int] = None,
    **kwargs: str,
) -> "Mail":

    return instance.get_instance(
        verification=verification, expiration=expiration, **kwargs
    )
