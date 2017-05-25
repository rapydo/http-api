# -*- coding: utf-8 -*-

"""

Generalization of Exceptions
to handle services known errors

"""

from rapydo.utils import htmlcodes as hcodes


class RestApiException(Exception):

    def __init__(self, exception, status_code=None):

        if status_code is None:
            status_code = hcodes.HTTP_BAD_NOTFOUND
        super(RestApiException).__init__()
        self.status_code = status_code
