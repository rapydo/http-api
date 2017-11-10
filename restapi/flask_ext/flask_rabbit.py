# -*- coding: utf-8 -*-

import pika
from restapi.flask_ext import BaseExtension, get_logger
from utilities.logs import re_obscure_pattern

log = get_logger(__name__)


class RabbitExt(BaseExtension):

    def custom_connection(self, **kwargs):

        variables = self.variables
        uri = 'amqp://%s:%s@%s:%s/' % (
            variables.get('user'),
            variables.get('password'),
            variables.get('host'),
            variables.get('port'),
        ) + '%' + '2F'
        log.very_verbose("URI IS %s" % re_obscure_pattern(uri))

        parameter = pika.connection.URLParameters(uri)
        return pika.BlockingConnection(parameter)

    # def custom_init(self, pinit=False, pdestroy=False, **kwargs):
    #     """ Note: we ignore args here """

    #     # recover instance with the parent method
    #     queue = super().custom_init()
    #     print(queue)
    #     return queue
