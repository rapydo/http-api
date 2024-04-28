from typing import Any, Callable

from flask import Flask
from flask_caching import Cache as FlaskCache

from restapi.connectors import Connector
from restapi.env import Env
from restapi.exceptions import ServiceUnavailable
from restapi.utilities.globals import mem


class Cache:
    @staticmethod
    def get_instance(app: Flask) -> FlaskCache:
        if not Connector.check_availability("redis"):
            raise ServiceUnavailable("Can't enable the cache without Redis")

        # This check prevents KeyError raised during tests
        # Exactly as reported here:
        # https://github.com/sh4nks/flask-caching/issues/191
        if not hasattr(mem, "cache"):
            redis = Env.load_variables_group(prefix="redis")
            mem.cache = FlaskCache(
                config={
                    "CACHE_TYPE": "RedisCache",
                    "CACHE_REDIS_HOST": redis.get("host"),
                    "CACHE_REDIS_PORT": redis.get("port"),
                    "CACHE_REDIS_PASSWORD": redis.get("password"),
                    # Usually 1=celery, 3=celery-beat
                    "CACHE_REDIS_DB": "2",
                }
            )

        mem.cache.init_app(app)

        return mem.cache

    @staticmethod
    def clear() -> None:
        mem.cache.clear()

    # This can be used to invalidate any endpoint, for example:
    # # 1 - From an endpoint
    # Cache.invalidate(self.get)
    # # 2 - import endpoint
    # from myproject.endpoints.mymodule import MyEndpoint
    # Cache.invalidate(MyEndpoint.get)
    # # 3 - With meta
    # c = Meta.get_class("endpoints.mymodule", "MyEndpoint")
    # Cache.invalidate(c.get)
    @staticmethod
    def invalidate(func: Callable[[Any], Any], *args: Any, **kwargs: Any) -> None:
        mem.cache.delete_memoized(func, *args, **kwargs)
