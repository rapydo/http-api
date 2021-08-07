"""
If you need things globally, come here and take.

Source:
https://pythonconquerstheuniverse.wordpress.com/
    2010/10/20/a-globals-class-pattern-for-python/

"""
from typing import Any, Dict

from flask_caching import Cache


class mem:

    # Type of variable becomes "Any" due to an unfollowed import
    cache: Cache  # type: ignore
    customizer: Any
    initializer: Any
    configuration: Dict[str, Any]
    private_endpoints: Any
    authenticated_endpoints: Any
    docs: Any
    geo_reader: Any
