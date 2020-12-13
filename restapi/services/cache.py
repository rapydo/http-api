from typing import Dict, Optional, Union

from flask_caching import Cache as FlaskCache

from restapi.env import Env
from restapi.utilities.globals import mem


class Cache:
    @staticmethod
    def get_config(use_redis: bool) -> Dict[str, Union[Optional[str], int]]:

        if use_redis:
            redis = Env.load_variables_group(prefix="redis")
            return {
                "CACHE_TYPE": "redis",
                "CACHE_REDIS_HOST": redis.get("host"),
                "CACHE_REDIS_PORT": redis.get("port"),
                "CACHE_REDIS_PASSWORD": redis.get("password"),
                "CACHE_REDIS_DB": redis.get("1"),
                # "CACHE_REDIS_URL": redis.get(""),
            }

        return {
            "CACHE_TYPE": "filesystem",
            "CACHE_DIR": "/tmp/cache",
            "CACHE_THRESHOLD": 4096,
            # 'CACHE_IGNORE_ERRORS': True,
        }

    @staticmethod
    def get_instance(app, detector):

        # This check prevent KeyError raised during tests
        # Exactly as reported here:
        # https://github.com/sh4nks/flask-caching/issues/191
        if not hasattr(mem, "cache"):

            cache_config = Cache.get_config(
                use_redis=detector.check_availability("redis")
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