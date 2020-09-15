import email
import json
from smtplib import SMTPException

from restapi.utilities.logs import log


class SMTP:
    """
    This is a very rough replacement of smtplib.SMTP class
    """

    def __init__(self, host):
        log.info("Mail mock initialized with host = {}", host)

    def __enter__(self):
        return self

    def __exit__(self, _type, value, tb):
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

    @staticmethod
    def quit():
        log.info("Mail mock sent quit message")

    @staticmethod
    def ehlo():
        log.info("Mail mock sent ehlo message")

    @staticmethod
    def sendmail(from_address, dest_addresses, msg):

        if from_address == "invalid1":
            raise SMTPException("SMTP Error")

        if from_address == "invalid2":
            raise BaseException("Generic Error")

        fpath = "/logs/mock.mail.lastsent.json"
        data = {"from": from_address, "cc": dest_addresses, "msg": msg}
        log.info("Mail mock sending email from {} to {}", from_address, dest_addresses)
        with open(fpath, "w+") as file:
            file.write(json.dumps(data))
        log.info("Mail mock sent email from {} to {}", from_address, dest_addresses)
        log.info("Mail mock mail written in {}", fpath)

        log.info("Extracting body")
        fpath = "/logs/mock.mail.lastsent.body"
        b = email.message_from_string(msg)
        payload = ""
        if b.is_multipart():
            for payload in b.get_payload():
                # get the first payload (the non html version)
                payload = payload.get_payload()
                break
        else:
            payload = b.get_payload()

        with open(fpath, "w+") as file:
            file.write(payload)

        log.info("Mail body written in {}", fpath)


class SMTP_SSL(SMTP):
    pass
