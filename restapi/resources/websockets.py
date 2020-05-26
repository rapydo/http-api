# -*- coding: utf-8 -*-

from flask import Response, request
from gripcontrol import WebSocketEvent
from gripcontrol import decode_websocket_events, encode_websocket_events
from gripcontrol import websocket_control_message, create_grip_channel_header
from flask_apispec import MethodResource

from restapi.rest.definition import EndpointResource
from restapi.exceptions import RestApiException
from restapi import decorators

from restapi.utilities.logs import log


class PushpinWebSocket(MethodResource, EndpointResource):

    depends_on = ["PUSHPIN_ENABLE"]

    _POST = {
        "/socket/<channel>": {
            "description": "Open a websocket",
            "responses": {"200": {"description": "Websocket connection accepted"}},
        }
    }
    _PUT = {
        "/socket/<channel>": {
            "description": "Push to socket",
            "responses": {"200": {"description": "Message sent"}},
        }
    }

    @decorators.catch_errors()
    @decorators.auth.required(allow_access_token_parameter=True)
    def put(self, channel):

        pushpin = self.get_service_instance('pushpin')

        message = 'Hello, your job is completed!'
        published = pushpin.publish_on_socket(channel, message, sync=True)

        return self.response("Message received: {}".format(published))

    @decorators.catch_errors()
    @decorators.auth.required(allow_access_token_parameter=True)
    def post(self, channel):

        try:
            # in_events = decode_websocket_events(request.get_data())
            in_events = decode_websocket_events(request.get_data())
        except ValueError as e:
            log.error(e)
            raise RestApiException(
                "Cannot decode websocket request: invalid format", status_code=400)

        if in_events is None or len(in_events) <= 0:
            log.error("Websocket request: {}", request.data)
            raise RestApiException(
                "Cannot decode websocket request: invalid in_event", status_code=400)
        in_events = in_events[0]

        event_type = None

        try:
            event_type = in_events.type
        except BaseException as e:
            log.error(e)
            raise RestApiException(
                "Cannot decode websocket request: invalid type", status_code=400)

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
        raise RestApiException("Cannot understand websocket request", status_code=400)


class PushpinHTTPStream(MethodResource, EndpointResource):

    depends_on = ["PUSHPIN_ENABLE"]

    _POST = {
        "/stream/<channel>": {
            "description": "Open a HTTP Stream for Long polling",
            "produces": ['application/json', 'text/plain'],
            "responses": {"200": {"description": "HTTP Stream connection accepted"}},
        }
    }
    _PUT = {
        "/stream/<channel>": {
            "description": "Push to stream",
            "responses": {"200": {"description": "Message sent"}},
        }
    }

    @decorators.catch_errors()
    def put(self, channel):

        pushpin = self.get_service_instance('pushpin')

        message = 'Hello, your job is completed!\n'
        published = pushpin.publish_on_stream(channel, message, sync=True)

        return "Message received: {}".format(published)

    @decorators.catch_errors()
    @decorators.auth.required(allow_access_token_parameter=True)
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
