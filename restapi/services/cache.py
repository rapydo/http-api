from typing import Any, Callable, Dict, Optional, Union

from flask import Flask
from flask_caching import Cache as FlaskCache

from restapi.connectors import Connector
from restapi.env import Env
from restapi.exceptions import ServiceUnavailable
from restapi.utilities.globals import mem


class Cache:
    @staticmethod
    def get_config() -> Dict[str, Union[Optional[str], int]]:

        redis = Env.load_variables_group(prefix="redis")
        return {
            "CACHE_TYPE": "flask_caching.backends.redis",
            "CACHE_REDIS_HOST": redis.get("host"),
            "CACHE_REDIS_PORT": redis.get("port"),
            "CACHE_REDIS_PASSWORD": redis.get("password"),
            # Usually 1=celery, 3=celery-beat
            "CACHE_REDIS_DB": "2",
            # "CACHE_REDIS_URL": redis.get(""),
        }

    @staticmethod
    def get_instance(app: Flask) -> FlaskCache:

        if not Connector.check_availability("redis"):
            raise ServiceUnavailable("Can't enable the cache without Redis")

        # This check prevents KeyError raised during tests
        # Exactly as reported here:
        # https://github.com/sh4nks/flask-caching/issues/191
        if not hasattr(mem, "cache"):
            cache_config = Cache.get_config()
            mem.cache = FlaskCache(config=cache_config)

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
