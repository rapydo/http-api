# -*- coding: utf-8 -*-

import pika
from restapi.flask_ext import BaseExtension, get_logger
# from utilities.logs import re_obscure_pattern

log = get_logger(__name__)


class RabbitExt(BaseExtension):

    def custom_connection(self, **kwargs):

        variables = self.variables

        # PAOLO's old way
        # uri = 'amqp://%s:%s@%s:%s/' % (
        #     variables.get('user'),
        #     variables.get('password'),
        #     variables.get('host'),
        #     variables.get('port'),
        # ) + '%' + '2F'
        # log.very_verbose("URI IS %s" % re_obscure_pattern(uri))
        # parameter = pika.connection.URLParameters(uri)
        # return pika.BlockingConnection(parameter)

        # MERRET's new way
        credentials = pika.PlainCredentials(
            variables.get('user'),
            variables.get('password')
        )
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=variables.get('host'),
                virtual_host=variables.get('vhost'),
                credentials=credentials
            )
        )

        # channel = connection.channel()
        # # Declare exchange, queue, and binding
        # channel.queue_declare(queue=QUEUE)
        # channel.exchange_declare(exchange=EXCHANGE, exchange_type='topic')
        # channel.queue_bind(
        #     exchange=EXCHANGE, queue=QUEUE, routing_key=ROUTING_KEY)
        return connection

    # def custom_init(self, pinit=False, pdestroy=False, **kwargs):
    #     """ Note: we ignore args here """

    #     # recover instance with the parent method
    #     queue = super().custom_init()
    #     print(queue)
    #     return queue
