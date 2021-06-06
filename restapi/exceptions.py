"""

Generalization of Exceptions
to handle services known errors

"""
from typing import Union

ExceptionType = Union[str, Exception]


class RestApiException(Exception):
    def __init__(
        self,
        exception: ExceptionType,
        status_code: int = 404,
        is_warning: bool = False,
    ):

        super().__init__(exception)
        self.status_code = status_code or 404
        self.is_warning = is_warning


class BadRequest(RestApiException):
    def __init__(self, exception: ExceptionType, is_warning: bool = False):
        super().__init__(exception, status_code=400, is_warning=is_warning)


class Unauthorized(RestApiException):
    def __init__(self, exception: ExceptionType, is_warning: bool = False):
        super().__init__(exception, status_code=401, is_warning=is_warning)


class Forbidden(RestApiException):
    def __init__(self, exception: ExceptionType, is_warning: bool = False):
        super().__init__(exception, status_code=403, is_warning=is_warning)


class NotFound(RestApiException):
    def __init__(self, exception: ExceptionType, is_warning: bool = False):
        super().__init__(exception, status_code=404, is_warning=is_warning)


class Conflict(RestApiException):
    def __init__(self, exception: ExceptionType, is_warning: bool = False):
        super().__init__(exception, status_code=409, is_warning=is_warning)


class ServerError(RestApiException):
    def __init__(self, exception: ExceptionType, is_warning: bool = False):
        super().__init__(exception, status_code=500, is_warning=is_warning)


class ServiceUnavailable(RestApiException):
    def __init__(self, exception: ExceptionType, is_warning: bool = False):
        super().__init__(exception, status_code=503, is_warning=is_warning)


class DatabaseDuplicatedEntry(Conflict):
    pass


class DatabaseMissingRequiredProperty(BadRequest):
    pass


# # RESPONSE TO BE VERIFIED
# HTTP_CONTINUE = 100 Continue
# HTTP_SWITCHING_PROTOCOLS = 101 Switching Protocols

# # RESPONSE RECEIVED
# HTTP_OK_BASIC = 200 OK
# HTTP_OK_CREATED = 201 HTTP_OK_CREATED
# HTTP_OK_ACCEPTED = 202 Accepted
# HTTP_OK_NORESPONSE = 204 No Content
# HTTP_PARTIAL_CONTENT = 206 Partial Content

# # WARNINGS
# HTTP_MULTIPLE_CHOICES = 300 Multiple Choices
# HTTP_FOUND = 302 Found (Previously "Moved temporarily")
# HTTP_NOT_MODIFIED = 304 Not Modified
# HTTP_TEMPORARY_REDIRECT = 307 Temporary Redirect (since HTTP/1.1)

# # SOFTWARE ERROR
# HTTP_BAD_REQUEST = 400 Bad Request
# HTTP_BAD_UNAUTHORIZED = 401 Unauthorized
# HTTP_BAD_FORBIDDEN = 403 Forbidden
# HTTP_BAD_NOTFOUND = 404 Not Found
# HTTP_BAD_METHOD_NOT_ALLOWED = 405 Method Not Allowed
# HTTP_BAD_CONFLICT = 409 Conflict
# HTTP_BAD_RESOURCE = 410 Gone
# HTTP_BAD_PAYLOAD_TOO_LARGE = 413 Payload Too Large
# HTTP_BAD_RANGE_NOT_SATISFIABLE = 416 Range Not Satisfiable

# # SERVER ERROR
# HTTP_SERVER_ERROR = 500 Internal Server Error
# HTTP_NOT_IMPLEMENTED = 501 Not Implemented
# HTTP_SERVICE_UNAVAILABLE = 503 Service Unavailable
# HTTP_INTERNAL_TIMEOUT = 504 Gateway Timeout
