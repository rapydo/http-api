from typing import Optional

from gripcontrol import GripPubControl, WebSocketMessageFormat
from pubcontrol import Item

from restapi.connectors import Connector, ExceptionsList
from restapi.utilities.logs import log


class ServiceUnavailable(Exception):
    pass


class PushpinExt(Connector):
    @staticmethod
    def get_connection_exception() -> ExceptionsList:
        return (ServiceUnavailable,)

    def connect(self, **kwargs: str) -> "PushpinExt":

        variables = self.variables.copy()
        variables.update(kwargs)

        host = variables.get("host")
        port = variables.get("port")

        control_uri = f"http://{host}:{port}"
        self.pubctrl = GripPubControl({"control_uri": control_uri})

        is_active = self.publish_on_stream("admin", "Connection test", sync=True)

        if not is_active:
            raise ServiceUnavailable(f"Pushpin unavailable on {control_uri}")
        return self

    def disconnect(self) -> None:
        self.disconnected = True

    def is_connected(self) -> bool:
        log.warning("pushpin.is_connected method is not implemented")
        return not self.disconnected

    @staticmethod
    def callback(result: str, message: str) -> None:
        if result:
            log.debug("Message successfully published on pushpin")
        else:  # pragma: no cover
            log.error("Publish failed on pushpin: {}", message)

    def publish_on_stream(self, channel: str, message: str, sync: bool = False) -> bool:
        if not sync:
            self.pubctrl.publish_http_stream(
                channel, message, callback=PushpinExt.callback
            )
            return True

        try:
            self.pubctrl.publish_http_stream(channel, message, blocking=True)
            log.debug("Message successfully published on pushpin")
            return True
        except Exception as e:
            log.error("Publish failed on pushpin: {}", message)
            log.error(e)
            return False

    def publish_on_socket(self, channel: str, message: str, sync: bool = False) -> bool:
        item = Item(WebSocketMessageFormat(message, binary=False))
        if not sync:
            self.pubctrl.publish(channel, item, callback=self.callback)
            return True

        try:
            self.pubctrl.publish(channel, item, blocking=True)
            log.debug("Message successfully published on pushpin")
            return True
        except Exception as e:  # pragma: no cover
            log.error("Publish failed on pushpin: {}", message)
            log.error(e)
            return False


instance = PushpinExt()


def get_instance(
    verification: Optional[int] = None,
    expiration: Optional[int] = None,
    **kwargs: str,
) -> "PushpinExt":

    return instance.get_instance(
        verification=verification, expiration=expiration, **kwargs
    )
