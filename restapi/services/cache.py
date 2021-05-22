import os
import tempfile
from typing import Dict, Optional, Union

from flask_caching import Cache as FlaskCache

from restapi.connectors import Connector
from restapi.env import Env
from restapi.utilities.globals import mem


class Cache:
    @staticmethod
    def get_config(use_redis: bool) -> Dict[str, Union[Optional[str], int]]:

        if use_redis:
            redis = Env.load_variables_group(prefix="redis")
            return {
                "CACHE_TYPE": "flask_caching.backends.redis",
                "CACHE_REDIS_HOST": redis.get("host"),
                "CACHE_REDIS_PORT": redis.get("port"),
                "CACHE_REDIS_PASSWORD": redis.get("password"),
                # Usually 0=celery, 1=celery-beat
                "CACHE_REDIS_DB": "2",
                # "CACHE_REDIS_URL": redis.get(""),
            }

        return {
            "CACHE_TYPE": "flask_caching.backends.filesystem",
            "CACHE_DIR": os.path.join(tempfile.gettempdir(), "cache"),
            "CACHE_THRESHOLD": 4096,
            # 'CACHE_IGNORE_ERRORS': True,
        }

    @staticmethod
    def get_instance(app):

        # This check prevent KeyError raised during tests
        # Exactly as reported here:
        # https://github.com/sh4nks/flask-caching/issues/191
        if not hasattr(mem, "cache"):

            cache_config = Cache.get_config(
                use_redis=Connector.check_availability("redis")
            )
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
    def invalidate(func, *args, **kwargs):
        mem.cache.delete_memoized(func, *args, **kwargs)
