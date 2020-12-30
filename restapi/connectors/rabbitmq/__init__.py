import json
import socket
import ssl
import urllib.parse
from typing import Dict, List, Optional, Union

import pika
import requests
from pika.exceptions import (
    AMQPChannelError,
    AMQPConnectionError,
    ChannelClosedByBroker,
    ConnectionClosed,
    ConnectionWrongStateError,
    StreamLostError,
    UnroutableError,
)
from requests.auth import HTTPBasicAuth

from restapi.connectors import Connector
from restapi.env import Env
from restapi.exceptions import RestApiException, ServiceUnavailable
from restapi.utilities.logs import log


class RabbitExt(Connector):
    def __init__(self) -> None:
        self.connection: Optional[pika.BlockingConnection] = None
        super().__init__()

    def get_connection_exception(self):
        # Includes:
        #   AuthenticationError,
        #   ProbableAuthenticationError,
        #   ProbableAccessDeniedError,
        #   ConnectionClosed...
        return (
            AMQPConnectionError,
            # Includes failures in name resolution
            socket.gaierror,
        )

    def connect(self, **kwargs):

        variables = self.variables.copy()
        # Beware, if you specify a user different by the default,
        # then the send method will fail to to PRECONDITION_FAILED because
        # the user_id will not pass the verification
        # Locally save self.variables + kwargs to be used in send()
        variables.update(kwargs)

        ssl_enabled = Env.to_bool(variables.get("ssl_enabled"))

        log.info("Connecting to the Rabbit (SSL = {})", ssl_enabled)

        if (host := variables.get("host")) is None:
            raise ServiceUnavailable("Missing hostname")

        if (user := variables.get("user")) is None:
            raise ServiceUnavailable("Missing credentials")

        if (password := variables.get("password")) is None:
            raise ServiceUnavailable("Missing credentials")

        port = int(variables.get("port", "0"))
        vhost = variables.get("vhost", "/")

        if ssl_enabled:
            # context = ssl.SSLContext(verify_mode=ssl.CERT_NONE)
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            # context.verify_mode = ssl.CERT_REQUIRED
            context.verify_mode = ssl.CERT_NONE
            context.load_default_certs()
            # Enable client certification verification
            # context.load_cert_chain(certfile=server_cert, keyfile=server_key)
            # context.load_verify_locations(cafile=client_certs)
            self.connection = pika.BlockingConnection(
                pika.ConnectionParameters(
                    host=host,
                    port=port,
                    virtual_host=vhost,
                    credentials=pika.PlainCredentials(user, password),
                    ssl_options=pika.SSLOptions(
                        context=context, server_hostname=variables.get("host")
                    ),
                )
            )

        else:

            self.connection = pika.BlockingConnection(
                pika.ConnectionParameters(
                    host=host,
                    port=port,
                    virtual_host=vhost,
                    credentials=pika.PlainCredentials(user, password),
                )
            )

        self.channel = None
        return self

    def disconnect(self) -> None:
        self.disconnected = True
        try:
            if self.connection:
                if self.connection.is_closed:
                    log.debug("Connection already closed")
                else:
                    self.connection.close()
        # No need to close the connection in this case... right?
        # Stream connection lost: ConnectionResetError(104, 'Connection reset by peer')
        except StreamLostError:  # pragma: no cover
            pass

    def is_connected(self) -> bool:
        if not self.connection or not self.connection.is_open:
            return False

        try:
            # this will verify if channel is still open and will try to recreate it
            # In some conditions the connection is open but in a wrong state and the
            # channel creation raises a ConnectionWrongStateError exception
            # This way the connection will be considered as closed and invalidated
            self.get_channel()
            return True
        # raised when `Channel allocation requires an open connection`
        except ConnectionWrongStateError:  # pragma: no cover
            return False

    def exchange_exists(self, exchange: str) -> bool:
        channel = self.get_channel()
        try:
            out = channel.exchange_declare(exchange=exchange, passive=True)
            log.debug(out)
            return True
        except ChannelClosedByBroker as e:
            log.error(e)
            return False

    def create_exchange(self, exchange: str) -> None:

        channel = self.get_channel()
        out = channel.exchange_declare(
            exchange=exchange, exchange_type="direct", durable=True, auto_delete=False
        )
        log.debug(out)

    def delete_exchange(self, exchange: str) -> None:

        channel = self.get_channel()
        out = channel.exchange_delete(exchange, if_unused=False)
        log.debug(out)

    def queue_exists(self, queue: str) -> bool:
        channel = self.get_channel()
        try:
            out = channel.queue_declare(queue=queue, passive=True)
            log.debug(out)
            return True
        except ChannelClosedByBroker as e:
            log.error(e)
            return False

    def create_queue(self, queue: str) -> None:

        channel = self.get_channel()
        out = channel.queue_declare(
            queue=queue, durable=True, exclusive=False, auto_delete=False
        )
        log.debug(out)

    def delete_queue(self, queue: str) -> None:

        channel = self.get_channel()
        out = channel.queue_delete(
            queue,
            if_unused=False,
            if_empty=False,
        )
        log.debug(out)

    def get_bindings(self, exchange: str) -> Optional[List[Dict[str, str]]]:
        if not self.exchange_exists(exchange):
            log.critical("Does not exist")
            return None

        host = self.variables.get("host", "")
        schema = ""
        if not host.startswith("http"):
            if Env.to_bool(self.variables.get("ssl_enabled")):
                schema = "https://"
            else:
                schema = "http://"

        port = self.variables.get("management_port")
        # url-encode unsafe characters by also including / (thanks to safe parameter)
        # / -> %2F
        vhost = urllib.parse.quote(self.variables.get("vhost", "/"), safe="")
        user = self.variables.get("user")
        password = self.variables.get("password")
        # API Reference:
        # A list of all bindings in which a given exchange is the source.
        r = requests.get(
            f"{schema}{host}:{port}/api/exchanges/{vhost}/{exchange}/bindings/source",
            auth=HTTPBasicAuth(user, password),
            verify=False,
        )
        response = r.json()
        if r.status_code != 200:  # pragma: no cover
            raise RestApiException(
                {"RabbitMQ": response.get("error", "Unknown error")},
                status_code=r.status_code,
            )

        bindings = []
        for row in response:
            # row == {
            #   'source': exchange-name,
            #   'vhost': probably '/',
            #   'destination': queue-or-dest-exchange-name,
            #   'destination_type': 'queue' or 'exchange',
            #   'routing_key': routing_key,
            #   'arguments': Dict,
            #   'properties_key': ?? as routing_key?
            # }

            bindings.append(
                {
                    "exchange": row["source"],
                    "routing_key": row["routing_key"],
                    "queue": row["destination"],
                }
            )

        return bindings

    def queue_bind(self, queue: str, exchange: str, routing_key: str) -> None:

        channel = self.get_channel()
        out = channel.queue_bind(
            queue=queue, exchange=exchange, routing_key=routing_key
        )
        log.debug(out)

    def queue_unbind(self, queue: str, exchange: str, routing_key: str) -> None:

        channel = self.get_channel()
        out = channel.queue_unbind(
            queue=queue, exchange=exchange, routing_key=routing_key
        )
        log.debug(out)

    def send_json(self, message, routing_key="", exchange="", headers=None):
        return self.send(
            body=json.dumps(message),
            routing_key=routing_key,
            exchange=exchange,
            headers=headers,
        )

    def send(self, body, routing_key="", exchange="", headers=None):
        """
        Send a message to the RabbitMQ queue

        :param body: the data to be send.
                        If this message should be json-encoded please use .send_json()
        :param exchange: RabbitMQ exchange where the message should be sent.
                         Empty for default exchange.
        :param queue: RabbitMQ routing key.
        """

        # Settings for the message:
        permanent_delivery = 2  # make message persistent

        if headers is None:
            headers = {}

        props = pika.BasicProperties(
            delivery_mode=permanent_delivery,
            headers=headers,
            # This should be the same used by the connect method, i.e.:
            # self.variables + kwargs
            # Otherwise it will fail with error:
            # Failed to write message, channel is dead (
            #     (406, "PRECONDITION_FAILED - user_id property
            #            set to 'CUSTOM' but authenticated user was 'BASE'
            #           "
            #     )
            # )
            user_id=self.variables.get("user"),
        )

        try:

            channel = self.get_channel()
            channel.basic_publish(
                exchange=exchange,
                routing_key=routing_key,
                body=body,
                properties=props,
                mandatory=True,
            )
            log.debug("Message sent to RabbitMQ")
            return True
        except UnroutableError as e:
            log.error(e)

        except ConnectionClosed as e:
            # TODO: This happens often. Check if heartbeat solves problem.
            log.error("Failed to write message, connection is dead ({})", e)

        except AMQPConnectionError as e:
            log.error("Failed to write message, connection failed ({})", e)

        except AMQPChannelError as e:
            log.error("Failed to write message, channel is dead ({})", e)
            self.channel = None

        except AttributeError as e:  # pragma: no cover
            log.error("Failed to write message:, {}", e)

        return False

    def get_channel(self):
        """
        Return existing channel (if healthy) or create and
        return new one.

        :return: An healthy channel.
        :raises: AttributeError if the connection is None.
        """

        if not self.connection:
            raise ServiceUnavailable(f"Service {self.name} is not available")

        if self.channel is None:
            log.debug("Creating new channel.")
            self.channel = self.connection.channel()
            self.channel.confirm_delivery()

        elif self.channel.is_closed:
            log.debug("Recreating channel.")
            self.channel = self.connection.channel()
            self.channel.confirm_delivery()

        return self.channel


instance = RabbitExt()


def get_instance(
    verification: Optional[int] = None,
    expiration: Optional[int] = None,
    **kwargs: Union[Optional[str], int],
) -> "RabbitExt":

    return instance.get_instance(
        verification=verification, expiration=expiration, **kwargs
    )
