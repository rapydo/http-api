"""
FTP connector with automatic integration in rapydo framework, based on ftplib
"""

import socket
import ssl
from ftplib import FTP, FTP_TLS, error_reply
from typing import Optional, Union

import certifi

from restapi.config import SSL_CERTIFICATE
from restapi.connectors import Connector, ExceptionsList
from restapi.env import Env
from restapi.exceptions import ServiceUnavailable
from restapi.utilities.logs import log


class FTP_TLS_SharedSession(FTP_TLS):
    # Can't find a type hint in the parent function
    def ntransfercmd(self, cmd, rest=None):  # type: ignore
        """Explicit FTPS, with shared TLS session"""
        conn, size = FTP.ntransfercmd(self, cmd, rest)
        if self._prot_p and self.sock:  # type: ignore
            conn = self.context.wrap_socket(
                conn,
                server_hostname=self.host,
                session=self.sock.session,  # type: ignore
            )
        return conn, size


class FTPExt(Connector):
    def __init__(self) -> None:
        self.connection: Union[FTP, FTP_TLS] = FTP()
        self.initialized = False
        super().__init__()

    # exception ftplib.error_reply
    # Exception raised when an unexpected reply is received from the server.

    # exception ftplib.error_temp
    # Exception raised when an error code signifying a temporary error
    # (response codes in the range 400–499) is received.

    # exception ftplib.error_perm
    # Exception raised when an error code signifying a permanent error
    # (response codes in the range 500–599) is received.

    # exception ftplib.error_proto
    # Exception raised when a reply is received from the server that does not fit the
    # response specifications of the File Transfer Protocol,
    # i.e. begin with a digit in the range 1–5.

    @staticmethod
    def get_connection_exception() -> ExceptionsList:
        return (socket.gaierror,)

    def connect(self, **kwargs: str) -> "FTPExt":

        variables = self.variables.copy()

        variables.update(kwargs)

        if (host := variables.get("host")) is None:  # pragma: no cover
            raise ServiceUnavailable("Missing hostname")

        if (user := variables.get("user")) is None:  # pragma: no cover
            raise ServiceUnavailable("Missing credentials")

        if (password := variables.get("password")) is None:  # pragma: no cover
            raise ServiceUnavailable("Missing credentials")

        port = Env.get_int(variables.get("port"), 21)

        ssl_enabled = Env.to_bool(variables.get("ssl_enabled"))

        if ssl_enabled:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

            context.load_default_certs()

            # Disable certificate verification:
            # context.verify_mode = ssl.CERT_NONE
            # Enable certificate verification:
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = False
            # Path to pem file to verify self signed certificates
            context.load_verify_locations(cafile=SSL_CERTIFICATE)
            # System CA to verify true cerificates
            context.load_verify_locations(cafile=certifi.where())
            ftp_tls_conn = FTP_TLS_SharedSession(context=context, timeout=10)
            # ftp_tls_conn.debugging = 1

            ftp_tls_conn.connect(host, port)
            # ftp_tls_conn.auth()
            ftp_tls_conn.login(user, password)
            ftp_tls_conn.set_pasv(True)
            # Set up secure data connection
            ftp_tls_conn.prot_p()

            self.connection = ftp_tls_conn
        else:
            ftp_conn = FTP(timeout=10)
            # ftp_conn.debugging = 1

            ftp_conn.connect(host, port)
            ftp_conn.login(user, password)
            ftp_conn.set_pasv(True)

            self.connection = ftp_conn

        self.initialized = True
        log.debug("Current directory: {}", self.connection.pwd())
        return self

    def disconnect(self) -> None:
        self.disconnected = True
        if self.connection and self.initialized and self.connection.sock:
            self.connection.quit()
            self.initialized = False

    def is_connected(self) -> bool:
        # Can't happen because connection is not Optional[]
        if not self.connection:  # pragma: no cover
            return False

        if self.disconnected:
            return False
        try:
            self.connection.voidcmd("NOOP")
            return True
        except error_reply:  # pragma: no cover
            return False


instance = FTPExt()


def get_instance(
    verification: Optional[int] = None,
    expiration: Optional[int] = None,
    **kwargs: str,
) -> "FTPExt":

    return instance.get_instance(
        verification=verification, expiration=expiration, **kwargs
    )
