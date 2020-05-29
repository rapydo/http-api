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


class BadRequest(RestApiException):
    def __init__(self, exception, is_warning=False):
        super().__init__(exception, status_code=400, is_warning=is_warning)


class Unauthorized(RestApiException):
    def __init__(self, exception, is_warning=False):
        super().__init__(exception, status_code=401, is_warning=is_warning)


class Forbidden(RestApiException):
    def __init__(self, exception, is_warning=False):
        super().__init__(exception, status_code=403, is_warning=is_warning)


class NotFound(RestApiException):
    def __init__(self, exception, is_warning=False):
        super().__init__(exception, status_code=404, is_warning=is_warning)


class Conflict(RestApiException):
    def __init__(self, exception, is_warning=False):
        super().__init__(exception, status_code=409, is_warning=is_warning)


class ServiceUnavailable(RestApiException):
    def __init__(self, exception, is_warning=False):
        super().__init__(exception, status_code=503, is_warning=is_warning)


class DatabaseDuplicatedEntry(Exception):
    pass
