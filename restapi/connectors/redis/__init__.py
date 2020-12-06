from typing import Optional, Union

from redis import StrictRedis
from redis.exceptions import ConnectionError as RedisConnectionError

from restapi.connectors import Connector
from restapi.env import Env

# from restapi.utilities.logs import log


class RedisExt(Connector):
    def __init__(self, app=None):
        super().__init__(app)

    def get_connection_exception(self):
        return None

    def connect(self, **kwargs):

        variables = self.variables.copy()
        variables.update(kwargs)

        # ssl=True, ssl_ca_certs=certifi.where()
        # turning off hostname verification (not recommended):
        # ssl_cert_reqs=None
        self.r = StrictRedis(
            host=variables.get("host", "redis.dockerized.io"),
            port=Env.to_int(variables.get("port"), 6379),
            db=0,
        )
        return self

    def disconnect(self) -> None:
        self.disconnected = True

    def is_connected(self) -> bool:
        try:
            self.r.get("")
            return True
        except RedisConnectionError:
            return False


instance = RedisExt()


def get_instance(
    verification: Optional[int] = None,
    expiration: Optional[int] = None,
    **kwargs: Union[Optional[str], int],
) -> "RedisExt":

    return instance.get_instance(
        verification=verification, expiration=expiration, **kwargs
    )
