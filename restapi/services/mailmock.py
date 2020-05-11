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
        log.info("Mail mock sent email from {} to {}", from_address, dest_addresses)


class SMTP_SSL(SMTP):
    pass
