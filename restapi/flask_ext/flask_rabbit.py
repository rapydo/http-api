# -*- coding: utf-8 -*-

import pika
import json
from restapi.flask_ext import BaseExtension, get_logger
# from utilities.logs import re_obscure_pattern

log = get_logger(__name__)

# TODO To be tested: With working RabbitMQ: Does everything
#       work as intended?
# TODO To be tested: Reconnection mechanism (e.g. wrong password),
#      does it try to reconnect several times, then give up?
# TODO To be tested: dont_connect setting, does it log to file
#      directly?
# TODO To be added: Heartbeat mechanism
# TODO To be added: Close connection - sigint, sigkill


class RabbitExt(BaseExtension):
    '''
    This class provides a (wrapper for a) RabbitMQ connection
    in order to write log messages into a queue.

    This is used in SeaDataCloud, where the log
    queues are then consumed by Logstash / ElasticSearch.
    '''

    def custom_connection(self, **kwargs):

        # NOTE: for SeaDataCloud

        # Only used in production
        dont_connect = False
        from restapi.confs import PRODUCTION
        if not PRODUCTION:
            dont_connect = True
            log.warning("Skipping Rabbit, logging to normal log instead.")
            # TODO: Have a TEST setting for testbeds, with different queue?
            # TODO: Log into some file if Rabbit not available?

        log.debug('Creating connection wrapper...')
        conn_wrapper = RabbitWrapper(self.variables, dont_connect)
        log.debug('Creating connection wrapper... done.')
        return conn_wrapper

class RabbitWrapper(object):

    def __init__(self, variables, dont_connect=False):
        log.debug('Creating RabbitMQ connection wrapper with variables %s' % variables)
        self.__variables = variables
        self.__connection = None
        self.__channel = None
        self.__dont_connect = dont_connect
        self.__couldnt_connect = 0
        # TODO: Declare queue and exchange, just in case?

        # Initial connection:
        if self.__dont_connect:
            log.warn('Will not connect to RabbitMQ (dont_connect = True).')
            log.debug('Creating RabbitMQ connection wrapper... done. (without connection).')
            return None

        try:
            self.__connect()
            log.debug('Creating RabbitMQ connection wrapper... done. (successful).')

        except pika.exceptions.AMQPConnectionError as e:
            ''' Includes AuthenticationError, ProbableAuthenticationError,
            ProbableAccessDeniedError, ConnectionClosed...
            '''
            log.warn('Could not connect to RabbitMQ now. Connection will be attempted a few times when messages are sent.')
            log.debug('Creating RabbitMQ connection wrapper... done. (without connection).')


    def __connect(self):
        log.info('Connecting to the Rabbit...')

        credentials = pika.PlainCredentials(
            self.__variables.get('user'),
            self.__variables.get('password')
        )
        ssl_enabled = self.__variables.get('ssl_enabled')
        if ssl_enabled is None:
            ssl_enabled = False
        else:
            ssl_enabled = (ssl_enabled.lower() == 'true' or int(ssl_enabled)==1)
        log.info('SSL enabled for RabbitMQ? %s' % ssl_enabled)

        try:
            self.__connection = pika.BlockingConnection(
                pika.ConnectionParameters(
                    host = self.__variables.get('host'),
                    port = int(self.__variables.get('port')),
                    virtual_host = self.__variables.get('vhost'),
                    credentials = credentials,
                    ssl = ssl_enabled
                )
            )
            self.__couldnt_connect = 0
            log.info('Connecting to the Rabbit... done.')

        except pika.exceptions.AMQPConnectionError as e:
            ''' Includes AuthenticationError, ProbableAuthenticationError,
            ProbableAccessDeniedError, ConnectionClosed...
            '''
            log.warn('Connecting to the Rabbit... failed (%s)' % e)
            self.__connection = None
            self.__couldnt_connect = self.__couldnt_connect+1
            raise e



    '''
    Send a log message to the RabbitMQ queue, unless
    the dont-connect parameter is set. In that case,
    the messages get logged into the normal log files.
    If the connection is dead, reconnection is attempted,
    but not eternally.

    :param dictionary_message: JSON log message
    :param app_name: App name (will be used for the ElasticSearch index name)
    :param exchange: RabbitMQ exchange where the message should be sent
    :param queue: RabbitMQ routing key.
    '''
    def log_json_to_queue(self, dictionary_message, app_name, exchange, queue):
        log.verbose('Asked to log (%s, %s, %s): %s' % (exchange, queue, app_name, dictionary_message))
        body = json.dumps(dictionary_message)

        # If no RabbitMQ connection, write into normal log:
        max_reconnect = 3
        if self.__dont_connect or self.__couldnt_connect > max_reconnect:
            log.info('RABBIT LOG MESSAGE (%s, %s, %s): %s' % (app_name, exchange, queue, body))
            return

        # Settings for the message:
        filter_code = 'de.dkrz.seadata.filter_code.json' # TODO Add to variables!
        permanent_delivery=2
        props = pika.BasicProperties(
            delivery_mode=permanent_delivery,
            headers={'app_name': app_name, 'filter_code': filter_code},
        )

        # Try sending n times:
        success = False
        max_publish = 3
        e = None
        for i in range(max_publish):
            log.verbose('Trying to send message to RabbitMQ in try (%s/%s)' % ((i+1), max_publish))

            try:

                if self.__connection is None and self.__couldnt_connect <= max_reconnect:
                    self.__connect()
                elif not self.__connection.is_open:
                    self.__connect()

                channel = self.__get_channel()
                success = channel.basic_publish(
                    exchange=exchange,
                    routing_key=queue,
                    properties=props,
                    body=body,
                    mandatory=True
                )
                if success:
                    log.verbose('Succeeded to send message to RabbitMQ in try (%s/%s)' % ((i+1), max_publish))
                    break
                else:
                    log.warn('Log fail without clear reason.')

            except pika.exceptions.ConnectionClosed as e:
                # TODO: This happens often. Check if heartbeat solves problem.
                log.info('Failed to send log message in try (%s/%s), because connection is dead (%s).'
                    % ((i+1), max_publish, e))
                self.__connection = None
                continue

            except pika.exceptions.AMQPConnectionError as e:
                log.info('Failed to send log message in try (%s/%s) because connection failed (%s).'
                    % ((i+1), max_publish, e))
                self.__connection = None
                continue

            except pika.exceptions.AMQPChannelError as e:
                log.info('Failed to send log message in try (%s/%s), because channel is dead (%s).'
                    % ((i+1), max_publish, e))
                self.__channel = None
                continue

            except AttributeError as e:
                log.info('Failed to send log message in try (%s/%s) (%s).' % ((i+1), max_publish, e))
                self.__connection = None
                continue

            # If failed each time:
            if i+1 >= max_publish:
                log.warning('Could not log to RabbitMQ (%s), logging here instead...' % e)
                log.info('RABBIT LOG MESSAGE (%s, %s, %s): %s' % (app_name, exchange, queue, body))



    '''
    Return existing channel (if healthy) or create and
    return new one.

    :return: The channel, or None if connection is switched off.
    :raises: AttributeError if the connection is None.
    '''
    def __get_channel(self):

        if self.__dont_connect:
            self.__channel = None

        elif self.__channel is None:
            log.verbose('Creating new channel.')
            self.__channel = self.__connection.channel()

        elif self.__channel.is_closed or self.__channel.is_closing:
            log.verbose('Recreating channel.')
            self.__channel = self.__connection.channel()

        return self.__channel


    '''
    Cleanly close the connection.
    '''
    def close_connection(self):
        # TODO: This must be called!
        if self.__dont_connect:
            return
        if self.__connection.is_closed or self.__connection.is_closing:
            log.debug('Connection already closed or closing.')
        else:
            self.__connection.close()
