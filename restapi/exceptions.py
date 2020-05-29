"""

Generalization of Exceptions
to handle services known errors

"""


class RestApiException(Exception):
    # code is now an alias for status_code
    def __init__(self, exception, status_code=None, code=None, is_warning=False):

        if status_code is None:
            status_code = code

        if status_code is None:
            status_code = 404

        super().__init__(exception)
        self.status_code = status_code
        self.is_warning = is_warning


class Forbidden(RestApiException):
    def __init__(self, exception, is_warning=False):
        super().__init__(exception, status_code=403, is_warning=is_warning)


class DatabaseDuplicatedEntry(Exception):
    pass
