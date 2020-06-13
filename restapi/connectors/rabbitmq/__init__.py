import json
import socket
import ssl

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

    # initialize is only invoked for backend databases
    def initialize(self):  # pragma: no cover
        pass

    # destroy is only invoked for backend databases
    def destroy(self):  # pragma: no cover
        pass

    def connect(self, **kwargs):

        variables = self.variables.copy()
        variables.update(kwargs)

        ssl_enabled = Env.to_bool(variables.get("ssl_enabled"))

        log.info("Connecting to the Rabbit (SSL = {})", ssl_enabled)

        credentials = pika.PlainCredentials(
            variables.get("user"), variables.get("password"),
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
                port=int(variables.get("port")),
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

    def __enter__(self):
        return self

    def __exit__(self, _type, value, tb):
        self.disconnect()

    def write_to_queue(self, jmsg, queue, exchange="", headers=None):
        """
        Send a log message to the RabbitMQ queue, unless
        the dont-connect parameter is set. In that case,
        the messages get logged into the normal log files.
        If the connection is dead, reconnection is attempted,
        but not eternally.

        :param jmsg: JSON log message
        :param app_name: App name (will be used for the ElasticSearch index name)
        :param exchange: RabbitMQ exchange where the jmsg should be sent.
                         Empty for default exchange.
        :param queue: RabbitMQ routing key.
        """

        log.verbose(
            "Asked to log ({}, {}): {}", exchange, queue, jmsg,
        )
        body = json.dumps(jmsg)

        # Settings for the message:
        permanent_delivery = 2  # make message persistent
        if headers is None:
            headers = {}

        props = pika.BasicProperties(delivery_mode=permanent_delivery, headers=headers)

        log.verbose("Sending message to RabbitMQ")

        try:

            channel = self.get_channel()
            failed_message = channel.basic_publish(
                exchange=exchange,
                routing_key=queue,
                body=body,
                properties=props,
                mandatory=True,
            )

            if failed_message:
                log.error("RabbitMQ write failed {}", failed_message)
                return False

            log.verbose("Message sent to RabbitMQ")
            return True

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

        log.warning("Could not write to RabbitMQ ({}, {}): {}", exchange, queue, body)

        return False

    def get_channel(self):
        """
        Return existing channel (if healthy) or create and
        return new one.

        :return: An healthy channel.
        :raises: AttributeError if the connection is None.
        """
        if self.channel is None:
            log.verbose("Creating new channel.")
            self.channel = self.connection.channel()

        elif self.channel.is_closed:
            log.verbose("Recreating channel.")
            self.channel = self.connection.channel()

        return self.channel
