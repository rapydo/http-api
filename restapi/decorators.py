# -*- coding: utf-8 -*-

from functools import wraps
import werkzeug.exceptions
from sentry_sdk import capture_exception
from restapi.confs import SENTRY_URL
from restapi.exceptions import RestApiException, DatabaseDuplicatedEntry
# imported here as utility for endpoints
from restapi.rest.bearer import authentication as auth
from restapi.utilities.logs import log

log.verbose("Auth loaded {}", auth)


def from_restapi_exception(self, e):
    if e.is_warning:
        log.warning(e)
    else:
        log.exception(e)
        log.error(e)
    return self.response(errors=e.args[0], code=e.status_code)


def catch_errors(exception=None, catch_generic=True, **kwargs):
    """
    A decorator to preprocess an API class method,
    and catch a specific error.
    """

    if exception is None:
        exception = RestApiException

    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            out = None

            try:
                out = func(self, *args, **kwargs)
            # Catch the exception requested by the user
            except exception as e:

                if isinstance(e, RestApiException):
                    return from_restapi_exception(self, e)

                log.exception(e)
                log.error(e)

                if hasattr(e, "status_code"):
                    error_code = getattr(e, "status_code")
                else:
                    error_code = 400

                return self.response(errors=str(e), code=error_code)

            # Catch the basic API exception
            except RestApiException as e:

                return from_restapi_exception(self, e)

            except werkzeug.exceptions.BadRequest:
                # do not stop werkzeug BadRequest
                raise

            except werkzeug.exceptions.UnprocessableEntity:
                # do not stop werkzeug UnprocessableEntity, it will be
                # catched by handle_marshmallow_errors
                raise

            # raised in case of malformed Range header
            except werkzeug.exceptions.RequestedRangeNotSatisfiable:
                raise
            # Catch any other exception
            except Exception as e:

                if SENTRY_URL is not None:
                    capture_exception(e)

                excname = e.__class__.__name__
                message = str(e)
                if not message:
                    message = "Unknown error"
                log.exception(message)
                log.error("Catched {} exception: {}", excname, message)
                if catch_generic:
                    if excname in ['AttributeError', 'ValueError', 'KeyError']:
                        error = 'Server failure; please contact admin.'
                    else:
                        error = {excname: message}
                    return self.response(errors=error, code=400)
                else:
                    raise e

            return out

        return wrapper

    return decorator


def catch_graph_exceptions(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):

        from neomodel.exceptions import RequiredProperty

        try:
            return func(self, *args, **kwargs)

        except DatabaseDuplicatedEntry as e:

            raise RestApiException(str(e), status_code=409)

        except RequiredProperty as e:

            raise RestApiException(str(e), status_code=400)

    return wrapper
