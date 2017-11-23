# -*- coding: utf-8 -*-

"""

Generalization of Exceptions
to handle services known errors

"""

from utilities import htmlcodes as hcodes


class RestApiException(Exception):

    def __init__(self, exception, status_code=None):

        if status_code is None:
            status_code = hcodes.HTTP_BAD_NOTFOUND
        super(RestApiException, self).__init__(exception)
        self.status_code = status_code
