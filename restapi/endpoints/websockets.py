from flask import Response, request
from gripcontrol import (
    WebSocketEvent,
    create_grip_channel_header,
    decode_websocket_events,
    encode_websocket_events,
    websocket_control_message,
)

from restapi import decorators
from restapi.exceptions import RestApiException
from restapi.rest.definition import EndpointResource
from restapi.utilities.logs import log


class PushpinWebSocket(EndpointResource):

    depends_on = ["PUSHPIN_ENABLE"]

    @decorators.auth.require(allow_access_token_parameter=True)
    @decorators.endpoint(
        path="/socket/<channel>/<sync>",
        description="Push to socket",
        responses={200: "Message sent"},
    )
    def put(self, channel, sync):

        # Unable to use a kwargs due to conflicts with allow_access_token_parameter
        sync = sync == "1"

        pushpin = self.get_service_instance("pushpin")

        message = "Hello, your job is completed!"
        published = pushpin.publish_on_socket(channel, message, sync=sync)

        return self.response(f"Message received: {published} (sync={sync})")

    @decorators.auth.require(allow_access_token_parameter=True)
    @decorators.endpoint(
        path="/socket/<channel>",
        description="Open a websocket",
        responses={200: "Websocket connection accepted"},
    )
    def post(self, channel):

        try:
            # in_events = decode_websocket_events(request.get_data())
            in_events = decode_websocket_events(request.get_data())
        except ValueError as e:
            log.error(e)
            raise RestApiException(
                "Cannot decode websocket request: invalid format", status_code=400
            )

        if in_events is None or len(in_events) <= 0:
            log.error("Websocket request: {}", request.data)
            raise RestApiException(
                "Cannot decode websocket request: invalid in_event", status_code=400
            )
        in_events = in_events[0]

        event_type = None

        try:
            event_type = in_events.type
        except BaseException as e:  # pragma: no cover
            log.error(e)
            raise RestApiException(
                "Cannot decode websocket request: invalid type", status_code=400
            )

        if event_type is None:  # pragma: no cover
            raise RestApiException("Cannot decode websocket request, no event type")

        out_events = []
        if event_type == "OPEN":
            ctrl_msg = websocket_control_message("subscribe", {"channel": channel})
            out_events.append(WebSocketEvent("OPEN"))
            out_events.append(WebSocketEvent("TEXT", f"c:{ctrl_msg}",))
            headers = {"Sec-WebSocket-Extensions": "grip"}
            resp = Response(
                encode_websocket_events(out_events),
                mimetype="application/websocket-events",
                headers=headers,
            )
            return resp

        log.error("Unknkown event type: {}", event_type)
        raise RestApiException("Cannot understand websocket request", status_code=400)


class PushpinHTTPStream(EndpointResource):

    depends_on = ["PUSHPIN_ENABLE"]

    @decorators.endpoint(
        path="/stream/<channel>/<sync>",
        description="Push to stream",
        responses={200: "Message sent"},
    )
    def put(self, channel, sync):

        # Unable to use a kwargs due to conflicts with allow_access_token_parameter
        sync = sync == "1"

        pushpin = self.get_service_instance("pushpin")

        message = "Hello, your job is completed!\n"
        published = pushpin.publish_on_stream(channel, message, sync=sync)

        return self.response(f"Message received: {published} (sync={sync})")

    @decorators.auth.require(allow_access_token_parameter=True)
    @decorators.endpoint(
        path="/stream/<channel>",
        description="Open a HTTP Stream for Long polling",
        responses={200: "HTTP Stream connection accepted"},
    )
    def post(self, channel):

        headers = {}
        headers["Grip-Hold"] = "stream"
        headers["Grip-Channel"] = create_grip_channel_header(channel)

        resp = Response(
            "Stream opened, prepare yourself!\n",
            mimetype="text/plain",
            headers=headers,
        )
        # resp['Sec-WebSocket-Extensions'] = 'grip'
        return resp
