# -*- coding: utf-8 -*-
from restapi.utilities.logs import log


class SMTP:
    """
    This is a very rough replacement of smtplib.SMTP class
    """

    def __init__(self, host):
        log.info("Mail mock initialized with host = {}", host)

    def __enter__(self):
        log.info("Mail mock entering the with context")
        return self

    def __exit__(self, _type, value, tb):
        log.info("Mail mock exiting the with context")

    def set_debuglevel(self, intval):
        log.info("Mail mock set debug level = {}", intval)

    def connect(self, host, port):
        log.info("Mail mock connected to {}:{}", host, port)

    def login(self, user, pwd):
        log.info("Mail mock login ok")

    def quit(self):
        log.info("Mail mock sent quit message")

    def ehlo(self):
        log.info("Mail mock sent ehlo message")

    def sendmail(self, from_address, dest_addresses, msg):
        log.info("Mail mock sent email from {} to {}", from_address, dest_addresses)


class SMTP_SSL(SMTP):
    pass
