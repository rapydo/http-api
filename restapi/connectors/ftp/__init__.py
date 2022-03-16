"""
FTP connector with automatic integration in rapydo framework, based on ftplib
"""

import socket
import ssl
from ftplib import FTP, FTP_TLS, error_reply
from typing import Optional

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
        self.connection: Optional[FTP_TLS] = None
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
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
            self.connection = FTP_TLS_SharedSession(context=ctx, timeout=10)
            self.connection.debugging = 1

            self.connection.connect(host, port)
            # self.connection.auth()
            self.connection.login(user, password)
            self.connection.set_pasv(True)
            # Set up secure data connection
            self.connection.prot_p()
        else:
            self.connection = FTP(context=ctx, timeout=10)
            self.connection.debugging = 1

            self.connection.connect(host, port)
            self.connection.login(user, password)
            self.connection.set_pasv(True)

        log.debug("Current directory: {}", self.connection.pwd())
        return self

    def disconnect(self) -> None:
        self.disconnected = True
        if self.connection:
            self.connection.quit()
            # expect ???:
            # -> log.debug("Connection already closed")

    def is_connected(self) -> bool:
        if not self.connection:
            return False

        try:
            self.connection.voidcmd("NOOP")
            return True
        except error_reply:
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
