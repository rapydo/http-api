# -*- coding: utf-8 -*-

"""

Generalization of Exceptions
to handle services known errors

"""


class RestApiException(Exception):
    # code is now an alias for status_code
    def __init__(self, exception, status_code=None, code=None):

        if status_code is None:
            status_code = code

        if status_code is None:
            status_code = 404

        super(RestApiException, self).__init__(exception)
        self.status_code = status_code


class DatabaseDuplicatedEntry(Exception):
    pass
