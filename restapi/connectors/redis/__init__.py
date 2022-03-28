"""
Redis connector with automatic integration in rapydo framework
"""

from typing import Optional

from redis import StrictRedis
from redis.exceptions import ConnectionError as RedisConnectionError

from restapi.connectors import Connector, ExceptionsList
from restapi.env import Env

# from restapi.utilities.logs import log


class RedisExt(Connector):

    DB = 0
    CELERY_BACKEND_DB = 1
    CACHE_DB = 2
    CELERY_BEAT_DB = 3
    CELERY_BROKER_DB = 4

    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    def get_connection_exception() -> ExceptionsList:
        return None

    def connect(self, **kwargs: str) -> "RedisExt":

        variables = self.variables.copy()
        variables.update(kwargs)

        # ssl=True, ssl_ca_certs=certifi.where()
        # turning off hostname verification (not recommended):
        # ssl_cert_reqs=None
        # Please note about the huge drop of performances with TLS:
        # https://github.com/redis/redis/issues/7595
        self.r = StrictRedis(
            host=variables.get("host", "redis.dockerized.io"),
            port=Env.to_int(variables.get("port"), 6379),
            password=variables.get("password"),
            db=RedisExt.DB,
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
    **kwargs: str,
) -> "RedisExt":

    return instance.get_instance(
        verification=verification, expiration=expiration, **kwargs
    )
