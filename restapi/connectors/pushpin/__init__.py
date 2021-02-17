from typing import Optional, Union

from gripcontrol import GripPubControl, WebSocketMessageFormat
from pubcontrol import Item

from restapi.connectors import Connector
from restapi.utilities.logs import log


class ServiceUnavailable(BaseException):
    pass


class PushpinExt(Connector):
    def get_connection_exception(self):
        return ServiceUnavailable

    def connect(self, **kwargs):

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
    def callback(result, message):
        if result:
            log.debug("Message successfully published on pushpin")
        else:  # pragma: no cover
            log.error("Publish failed on pushpin: {}", message)

    def publish_on_stream(self, channel, message, sync=False):
        if not sync:
            self.pubctrl.publish_http_stream(
                channel, message, callback=PushpinExt.callback
            )
            return True

        try:
            self.pubctrl.publish_http_stream(channel, message, blocking=True)
            log.debug("Message successfully published on pushpin")
            return True
        except BaseException as e:
            log.error("Publish failed on pushpin: {}", message)
            log.error(e)
            return False

    def publish_on_socket(self, channel, message, sync=False):
        item = Item(WebSocketMessageFormat(message, binary=False))
        if not sync:
            self.pubctrl.publish(channel, item, callback=self.callback)
            return True

        try:
            self.pubctrl.publish(channel, item, blocking=True)
            log.debug("Message successfully published on pushpin")
            return True
        except BaseException as e:  # pragma: no cover
            log.error("Publish failed on pushpin: {}", message)
            log.error(e)
            return False


instance = PushpinExt()


def get_instance(
    verification: Optional[int] = None,
    expiration: Optional[int] = None,
    **kwargs: Union[Optional[str], int],
) -> "PushpinExt":

    return instance.get_instance(
        verification=verification, expiration=expiration, **kwargs
    )
