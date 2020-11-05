"""
If you need things globally, come here and take.

Source:
https://pythonconquerstheuniverse.wordpress.com/
    2010/10/20/a-globals-class-pattern-for-python/

"""
from typing import Any


class mem:

    customizer: Any
    initializer: Any
    configuration: Any
    private_endpoints: Any
    authenticated_endpoints: Any
    docs: Any
    geo_reader: Any
