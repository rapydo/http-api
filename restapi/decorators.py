# -*- coding: utf-8 -*-

import re
from functools import wraps
import werkzeug.exceptions
from restapi.exceptions import RestApiException
from restapi.confs import SENTRY_URL
# imported here as utility for endpoints
from restapi.services.authentication.bearer import authentication as auth
from restapi.utilities.logs import log

log.verbose("Auth loaded {}", auth)


def from_restapi_exception(self, e):
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

            except werkzeug.exceptions.BadRequest as e:
                # do not stop werkzeug BadRequest
                raise e

            # Catch any other exception
            except Exception as e:

                if SENTRY_URL is not None:
                    from sentry_sdk import capture_exception

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
        from neomodel.exceptions import UniqueProperty

        try:
            return func(self, *args, **kwargs)

        except (UniqueProperty) as e:

            # Duplicated in admin_users
            # Please not that neomodel changed this error
            # the correct version is in admin_users
            prefix = "Node [0-9]+ already exists with label"
            m = re.search(r"{} (.+) and property (.+)".format(prefix), str(e))

            if m:
                node = m.group(1)
                prop = m.group(2)
                val = m.group(3)
                error = "A {} already exists with {} = {}".format(node, prop, val)
            else:
                error = str(e)

            raise RestApiException(error, status_code=409)
        except (RequiredProperty) as e:
            raise RestApiException(str(e))

        # FIXME: to be specified with new neomodel exceptions
        # except ConstraintViolation as e:
        # except UniqueProperty as e:

    return wrapper
