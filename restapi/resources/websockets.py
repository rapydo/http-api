# -*- coding: utf-8 -*-

from flask import Response, request
try:
    from gripcontrol import WebSocketEvent
    from gripcontrol import decode_websocket_events, encode_websocket_events
    from gripcontrol import websocket_control_message, create_grip_channel_header
except ImportError as e:
    print(str(e))

from restapi.protocols.bearer import authentication
from restapi.rest.definition import EndpointResource
from restapi.exceptions import RestApiException
from restapi import decorators as decorate

from restapi.utilities.logs import log


class PushpinWebSocket(EndpointResource):

    depends_on = ["PUSHPIN_ENABLE"]

    POST = {
        "/socket/<channel>": {
            "description": "Open a websocket",
            "responses": {"200": {"description": "Websocket connection accepted"}},
        }
    }
    PUT = {
        "/socket/<channel>": {
            "description": "Push to socket",
            "responses": {"200": {"description": "Message sent"}},
        }
    }

    @decorate.catch_error()
    def put(self, channel):

        pushpin = self.get_service_instance('pushpin')

        message = 'Hello, your job is completed!'
        published = pushpin.publish_on_socket(channel, message, sync=True)

        return "Message received: {}".format(published)

    @decorate.catch_error()
    @authentication.required(allow_access_token_parameter=True)
    def post(self, channel):

        in_events = decode_websocket_events(request.data)
        if in_events is None or len(in_events) <= 0:
            log.error("Websocket request: {}", request.data)
            raise RestApiException("Cannot decode websocket request")
        in_events = in_events[0]

        event_type = None

        try:
            event_type = in_events.type
        except BaseException as e:
            log.error(e)
            raise RestApiException("Cannot decode websocket request")

        if event_type is None:
            log.error("Event type is None")
            raise RestApiException("Cannot decode websocket request")

        out_events = []
        if event_type == 'OPEN':
            out_events.append(WebSocketEvent('OPEN'))
            out_events.append(
                WebSocketEvent(
                    'TEXT',
                    'c:' + websocket_control_message(
                        'subscribe', {'channel': channel}
                    ),
                )
            )
            headers = {
                'Sec-WebSocket-Extensions': 'grip'
            }
            resp = Response(
                encode_websocket_events(out_events),
                mimetype='application/websocket-events',
                headers=headers,
            )
            return resp

        log.error("Unknkown event type: {}", event_type)
        raise RestApiException("Cannot understand websocket request")


class PushpinHTTPStream(EndpointResource):

    depends_on = ["PUSHPIN_ENABLE"]

    POST = {
        "/stream/<channel>": {
            "description": "Open a HTTP Stream for Long polling",
            "responses": {"200": {"description": "HTTP Stream connection accepted"}},
        }
    }
    PUT = {
        "/stream/<channel>": {
            "description": "Push to stream",
            "responses": {"200": {"description": "Message sent"}},
        }
    }

    @decorate.catch_error()
    def put(self, channel):

        pushpin = self.get_service_instance('pushpin')

        message = 'Hello, your job is completed!\n'
        published = pushpin.publish_on_stream(channel, message, sync=True)

        return "Message received: {}".format(published)

    @decorate.catch_error()
    @authentication.required(allow_access_token_parameter=True)
    def post(self, channel):

        headers = {}
        headers['Grip-Hold'] = 'stream'
        headers['Grip-Channel'] = create_grip_channel_header(channel)

        resp = Response(
            'Stream opened, prepare yourself!\n',
            mimetype='text/plain',
            headers=headers,
        )
        # resp['Sec-WebSocket-Extensions'] = 'grip'
        return resp
