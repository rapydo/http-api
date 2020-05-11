# -*- coding: utf-8 -*-

from gripcontrol import GripPubControl
from gripcontrol import WebSocketMessageFormat
from pubcontrol import Item

from restapi.utilities.logs import log
from restapi.connectors import Connector


class ServiceUnavailable(BaseException):
    pass


class PushpinExt(Connector):

    def get_connection_exception(self):
        return ServiceUnavailable

    def preconnect(self, **kwargs):
        return True

    def postconnect(self, obj, **kwargs):
        return True

    def initialize(self, pinit, pdestroy, abackend=None):
        return self.get_instance()

    def connect(self, **kwargs):

        variables = kwargs or self.variables

        host = variables.get('host')
        port = variables.get('port')

        control_uri = 'http://{}:{}'.format(host, port)
        pubctrl = GripPubControl({
            'control_uri': control_uri
        })

        client = PushpinClient(pubctrl)

        is_active = client.publish_on_stream('admin', 'Connection test', sync=True)

        if is_active:
            return client

        raise ServiceUnavailable("Pushpin unavailable on {}".format(control_uri))


class PushpinClient:

    def __init__(self, pub):
        self.pub = pub

    @staticmethod
    def callback(result, message):
        if result:
            log.debug('Message successfully published on pushpin')
        else:
            log.error('Publish failed on pushpin: {}', message)

    def publish_on_stream(self, channel, message, sync=False):
        if not sync:
            self.pub.publish_http_stream(
                channel, message, callback=PushpinClient.callback)
            return True

        try:
            self.pub.publish_http_stream(channel, message, blocking=True)
            log.debug('Message successfully published on pushpin')
            return True
        except BaseException as e:
            log.error('Publish failed on pushpin: {}', message)
            log.error(e)
            return False

    def publish_on_socket(self, channel, message, sync=False):
        item = Item(WebSocketMessageFormat(message, binary=False))
        if not sync:
            self.pub.publish(channel, item, callback=self.callback)
            return True

        try:
            self.pub.publish(channel, item, blocking=True)
            log.debug('Message successfully published on pushpin')
            return True
        except BaseException as e:
            log.error('Publish failed on pushpin: {}', message)
            log.error(e)
            return False
