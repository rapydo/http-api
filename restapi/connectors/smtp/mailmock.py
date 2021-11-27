import email
from smtplib import SMTPException, SMTPServerDisconnected
from types import TracebackType
from typing import Optional, Tuple, Type, TypeVar

import orjson

from restapi.utilities.logs import LOGS_FOLDER, log

T = TypeVar("T", bound="SMTP")


class SMTP:
    """
    This is a very rough replacement of smtplib.SMTP class
    """

    def __init__(self, host: str) -> None:
        log.info("Mail mock initialized with host = {}", host)
        self.disconnected = False

    def __enter__(self: T) -> T:  # pragma: no cover
        return self

    def __exit__(
        self,
        _type: Optional[Type[Exception]],
        value: Optional[Exception],
        tb: Optional[TracebackType],
    ) -> bool:  # pragma: no cover
        # return False if the exception is not handled:
        # -> return True if the exception is None (nothing to be handled)
        # -> return False if the exception is not None (because it is not handled here)
        # always return False is not accepted by mypy...
        return _type is None

    @staticmethod
    def set_debuglevel(intval: int) -> None:
        log.info("Mail mock set debug level = {}", intval)

    @staticmethod
    def connect(host: str, port: int) -> None:
        log.info("Mail mock connected to {}:{}", host, port)

    @staticmethod
    def login(user: str, pwd: str) -> None:
        log.info("Mail mock login ok")

    def quit(self) -> None:
        self.disconnected = True
        log.info("Mail mock sent quit message")

    @staticmethod
    def ehlo() -> None:
        log.info("Mail mock sent ehlo message")

    @staticmethod
    def sendmail(from_address: str, dest_addresses: str, msg: str) -> None:

        if from_address == "invalid1":
            raise SMTPException("SMTP Error")

        if from_address == "invalid2":
            raise Exception("Generic Error")

        json_fpath = LOGS_FOLDER.joinpath("mock.mail.lastsent.json")
        body_fpath = LOGS_FOLDER.joinpath("mock.mail.lastsent.body")
        json_fpath_prev = LOGS_FOLDER.joinpath("mock.mail.prevsent.json")
        body_fpath_perv = LOGS_FOLDER.joinpath("mock.mail.prevsent.body")

        if json_fpath.exists():
            json_fpath.rename(json_fpath_prev)

        if body_fpath.exists():
            body_fpath.rename(body_fpath_perv)

        data = {"from": from_address, "cc": dest_addresses, "msg": msg}
        log.info("Mail mock sending email from {} to {}", from_address, dest_addresses)
        with open(json_fpath, "w+") as file:
            file.write(orjson.dumps(data).decode("UTF-8"))
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
