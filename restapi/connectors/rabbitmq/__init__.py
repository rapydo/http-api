import json
import socket
import ssl
from typing import Optional, Union

import pika

from restapi.connectors import Connector
from restapi.env import Env
from restapi.utilities.logs import log


class RabbitExt(Connector):
    def get_connection_exception(self):
        # Includes:
        #   AuthenticationError,
        #   ProbableAuthenticationError,
        #   ProbableAccessDeniedError,
        #   ConnectionClosed...
        return (
            pika.exceptions.AMQPConnectionError,
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

        credentials = pika.PlainCredentials(
            variables.get("user"),
            variables.get("password"),
        )

        if ssl_enabled:
            # context = ssl.SSLContext(verify_mode=ssl.CERT_NONE)
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            # context.verify_mode = ssl.CERT_REQUIRED
            context.verify_mode = ssl.CERT_NONE
            context.load_default_certs()
            # Enable client certification verification
            # context.load_cert_chain(certfile=server_cert, keyfile=server_key)
            # context.load_verify_locations(cafile=client_certs)
            ssl_options = pika.SSLOptions(
                context=context, server_hostname=variables.get("host")
            )
        else:
            ssl_options = None

        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=variables.get("host"),
                port=int(variables.get("port", "0")),
                virtual_host=variables.get("vhost"),
                credentials=credentials,
                ssl_options=ssl_options,
            )
        )

        self.channel = None
        return self

    def disconnect(self):
        if self.connection.is_closed:
            log.debug("Connection already closed")
        else:
            self.connection.close()
        self.disconnected = True

    def is_connected(self):
        return self.connection.is_open

    def exchange_exists(self, exchange):
        channel = self.get_channel()
        try:
            out = channel.exchange_declare(exchange=exchange, passive=True)
            log.debug(out)
            return True
        except pika.exceptions.ChannelClosedByBroker as e:
            log.error(e)
            return False

    def create_exchange(self, exchange):

        channel = self.get_channel()
        out = channel.exchange_declare(
            exchange=exchange, exchange_type="direct", durable=True, auto_delete=False
        )
        log.debug(out)

    def delete_exchange(self, exchange):

        channel = self.get_channel()
        out = channel.exchange_delete(exchange, if_unused=False)
        log.debug(out)

    def queue_exists(self, queue):
        channel = self.get_channel()
        try:
            out = channel.queue_declare(queue=queue, passive=True)
            log.debug(out)
            return True
        except pika.exceptions.ChannelClosedByBroker as e:
            log.error(e)
            return False

    def create_queue(self, queue):

        channel = self.get_channel()
        out = channel.queue_declare(
            queue=queue, durable=True, exclusive=False, auto_delete=False
        )
        log.debug(out)

    def delete_queue(self, queue):

        channel = self.get_channel()
        out = channel.queue_delete(
            queue,
            if_unused=False,
            if_empty=False,
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
        except pika.exceptions.UnroutableError as e:
            log.error(e)

        except pika.exceptions.ConnectionClosed as e:
            # TODO: This happens often. Check if heartbeat solves problem.
            log.error("Failed to write message, connection is dead ({})", e)

        except pika.exceptions.AMQPConnectionError as e:
            log.error("Failed to write message, connection failed ({})", e)

        except pika.exceptions.AMQPChannelError as e:
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
