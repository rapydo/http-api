import email
import json
from smtplib import SMTPException, SMTPServerDisconnected
from typing import Tuple

from restapi.utilities.logs import LOGS_FOLDER, log


class SMTP:
    """
    This is a very rough replacement of smtplib.SMTP class
    """

    def __init__(self, host):
        log.info("Mail mock initialized with host = {}", host)
        self.disconnected = False

    def __enter__(self) -> "SMTP":  # pragma: no cover
        return self

    def __exit__(self, _type, value, tb):  # pragma: no cover
        pass

    @staticmethod
    def set_debuglevel(intval):
        log.info("Mail mock set debug level = {}", intval)

    @staticmethod
    def connect(host, port):
        log.info("Mail mock connected to {}:{}", host, port)

    @staticmethod
    def login(user, pwd):
        log.info("Mail mock login ok")

    def quit(self) -> None:
        self.disconnected = True
        log.info("Mail mock sent quit message")

    @staticmethod
    def ehlo() -> None:
        log.info("Mail mock sent ehlo message")

    @staticmethod
    def sendmail(from_address, dest_addresses, msg):

        if from_address == "invalid1":
            raise SMTPException("SMTP Error")

        if from_address == "invalid2":
            raise BaseException("Generic Error")

        json_fpath = LOGS_FOLDER.joinpath("mock.mail.lastsent.json")
        body_fpath = LOGS_FOLDER.joinpath("mock.mail.lastsent.body")

        if json_fpath.exists():
            json_fpath.rename("mock.mail.prevsent.json")

        if body_fpath.exists():
            body_fpath.rename("mock.mail.prevsent.body")

        data = {"from": from_address, "cc": dest_addresses, "msg": msg}
        log.info("Mail mock sending email from {} to {}", from_address, dest_addresses)
        with open(json_fpath, "w+") as file:
            file.write(json.dumps(data))
        log.info("Mail mock sent email from {} to {}", from_address, dest_addresses)
        log.info("Mail mock mail written in {}", json_fpath)

        log.info("Extracting body")
        b = email.message_from_string(msg)
        if b.is_multipart():
            # get the first payload (the non html version)
            first_payload = b.get_payload()[0]
            # This is enough when the message is not based64-encoded
            payload = first_payload.get_payload()
            # Otherwise this is needed:
            payload = first_payload.get_payload(decode=True).decode("utf-8")
        else:
            # This is enough when the message is not based64-encoded
            # payload = b.get_payload()
            # Otherwise this is needed:
            payload = b.get_payload(decode=True).decode("utf-8")

        with open(body_fpath, "w+") as file:
            file.write(payload)

        log.info("Mail body written in {}", body_fpath)

    def noop(self) -> Tuple[int]:
        if self.disconnected:
            raise SMTPServerDisconnected  # pragma: no cover

        return (250,)


class SMTP_SSL(SMTP):
    pass
