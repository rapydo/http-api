import pika
import json
import ssl
from restapi.utilities.logs import log
from restapi.connectors import Connector

# TODO To be tested: Reconnection mechanism (e.g. wrong password),
#      does it try to reconnect several times, then give up?
# TODO To be added: Heartbeat mechanism
# TODO To be added: Close connection - sigint, sigkill


class RabbitExt(Connector):
    '''
    This class provides a (wrapper for a) RabbitMQ connection
    in order to write log messages into a queue.

    This is used in SeaDataCloud, where the log
    queues are then consumed by Logstash / ElasticSearch.
    '''

    def get_connection_exception(self):
        return None

    def preconnect(self, **kwargs):
        return True

    def postconnect(self, obj, **kwargs):
        return True

    def initialize(self):
        pass

    def destroy(self):
        pass

    def connect(self, **kwargs):

        conn_wrapper = RabbitWrapper(self.variables)
        return conn_wrapper


class RabbitWrapper:
    def __init__(self, variables):
        self.__variables = variables
        self.__connection = None
        self.__channel = None
        self._connection_retries = 0
        # TODO: Declare queue and exchange, just in case?

        try:
            self.__connect()
            log.debug(
                'RabbitMQ connection wrapper created')

        except pika.exceptions.AMQPConnectionError:  # pragma: no cover
            ''' Includes AuthenticationError, ProbableAuthenticationError,
            ProbableAccessDeniedError, ConnectionClosed...
            '''
            log.warning(
                'Could not connect to RabbitMQ now, connection will be retried later'
            )
            log.debug(
                'RabbitMQ connection wrapper created but without connection).'
            )

    def __connect(self):
        # Do not import before loading the ext!
        from restapi.services.detect import Detector
        ssl_enabled = Detector.get_bool_envvar(
            self.__variables.get('ssl_enabled', False)
        )

        log.info('Connecting to the Rabbit (SSL = {})', ssl_enabled)

        credentials = pika.PlainCredentials(
            self.__variables.get('user'), self.__variables.get('password')
        )

        try:
            if ssl_enabled:
                # log.warning("SSL not implemented for Rabbit")
                # context = ssl.SSLContext(verify_mode=ssl.CERT_NONE)
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                # context.verify_mode = ssl.CERT_REQUIRED
                context.verify_mode = ssl.CERT_NONE
                context.load_default_certs()
                # Enable client certification verification
                # context.load_cert_chain(certfile=server_cert, keyfile=server_key)
                # context.load_verify_locations(cafile=client_certs)
                ssl_options = pika.SSLOptions(
                    context=context,
                    server_hostname=self.__variables.get('host')
                )
            else:
                ssl_options = None

            self.__connection = pika.BlockingConnection(
                pika.ConnectionParameters(
                    host=self.__variables.get('host'),
                    port=int(self.__variables.get('port')),
                    virtual_host=self.__variables.get('vhost'),
                    credentials=credentials,
                    ssl_options=ssl_options,
                )
            )
            self._connection_retries = 0

            # with pika.BlockingConnection(conn_params) as conn:
            #     ch = conn.channel()
            #     ch.queue_declare("foobar")
            #     ch.basic_publish("", "foobar", "Hello, world!")
            #     print(ch.basic_get("foobar"))

        except BaseException as e:  # pragma: no cover
            ''' Includes AuthenticationError, ProbableAuthenticationError,
            ProbableAccessDeniedError, ConnectionClosed...
            '''
            log.warning('Connecting to the Rabbit failed ({})', e)
            self.__connection = None
            self._connection_retries += 1
            raise e

    def write_to_queue(self, jmsg, queue, exchange="", headers=None):
        '''
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
        '''

        log.verbose(
            'Asked to log ({}, {}): {}',
            exchange,
            queue,
            jmsg,
        )
        body = json.dumps(jmsg)

        # If no RabbitMQ connection, write into normal log:
        MAX_RETRY = 3
        if self._connection_retries > MAX_RETRY:
            log.info(
                'RABBIT LOG MESSAGE ({}, {}): {}', exchange, queue, body
            )
            return False

        # Settings for the message:
        permanent_delivery = 2  # make message persistent
        if headers is None:
            headers = {}

        props = pika.BasicProperties(delivery_mode=permanent_delivery, headers=headers)

        # Try sending n times:
        for i in range(1, MAX_RETRY + 1):
            log.verbose(
                'Sending message to RabbitMQ (try {}/{})',
                i, MAX_RETRY,
            )

            try:

                if self.__connection is None and self._connection_retries <= MAX_RETRY:
                    self.__connect()
                elif not self.__connection.is_open:
                    self.__connect()

                channel = self.__get_channel()
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

                log.verbose('Message sent to RabbitMQ')
                return True

            except pika.exceptions.ConnectionClosed as e:  # pragma: no cover
                # TODO: This happens often. Check if heartbeat solves problem.
                log.error(
                    'Failed to write message (try {}/{}), connection is dead ({})',
                    i, MAX_RETRY, e
                )
                self.__connection = None

            except pika.exceptions.AMQPConnectionError as e:  # pragma: no cover
                log.error(
                    'Failed to write message (try {}/{}), connection failed ({})',
                    i, MAX_RETRY, e
                )
                self.__connection = None

            except pika.exceptions.AMQPChannelError as e:  # pragma: no cover
                log.error(
                    'Failed to write message (try {}/{}), channel is dead ({})',
                    i, MAX_RETRY, e
                )
                self.__channel = None

            except AttributeError as e:  # pragma: no cover
                log.error(
                    'Failed to write message (try {}/{}), {}',
                    i, MAX_RETRY, e
                )
                self.__connection = None

        log.warning(  # pragma: no cover
            'Could not write to RabbitMQ ({}, {}): {}',
            exchange, queue, body
        )

        return False  # pragma: no cover

    def __get_channel(self):
        '''
        Return existing channel (if healthy) or create and
        return new one.

        :return: An healthy channel.
        :raises: AttributeError if the connection is None.
        '''
        if self.__channel is None:
            log.verbose('Creating new channel.')
            self.__channel = self.__connection.channel()

        elif self.__channel.is_closed:
            log.verbose('Recreating channel.')
            self.__channel = self.__connection.channel()

        return self.__channel

    def close_connection(self):
        # TODO: This must be called!
        if self.__connection.is_closed or self.__connection.is_closing:
            log.debug('Connection already closed or closing.')
        else:
            self.__connection.close()
