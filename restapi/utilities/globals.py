"""
If you need things globally, come here and take.

"""
from restapi.customizer import BaseCustomizer


class mem:

    customizer: BaseCustomizer
    """
    Source:
    https://pythonconquerstheuniverse.wordpress.com/
        2010/10/20/a-globals-class-pattern-for-python/
    """

    pass
