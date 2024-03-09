"""
If you need things globally, come here and take.

Source:
https://pythonconquerstheuniverse.wordpress.com/
    2010/10/20/a-globals-class-pattern-for-python/

"""

from typing import Any, Optional

from flask_caching import Cache
from sqlalchemy.engine.base import Engine
from sqlalchemy.engine.url import URL


class mem:
    cache: Cache
    customizer: Any
    initializer: Any
    configuration: dict[str, Any]
    private_endpoints: Any
    authenticated_endpoints: Any
    docs: Any
    # default to True to save connectors by default
    # is set False during server boot
    boot_completed: bool = True

    # None URL is used as default URL
    sqlalchemy_engines: dict[Optional[URL], Engine] = {}
