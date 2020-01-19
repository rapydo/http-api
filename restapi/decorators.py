# -*- coding: utf-8 -*-

"""

Decorating my REST API resources.

Decorate is a cool but sometimes dangerous place in Python, I guess.
Here we test different kind of decorations for different problems.

Restful resources are Flask Views classes.
Official docs talks about their decoration:
http://flask-restful.readthedocs.org/en/latest/extending.html#resource-method-decorators
So... you should also read better this section of Flask itself:
http://flask.pocoo.org/docs/0.10/views/#decorating-views

I didn't manage so far to have it working in the way the documentation require.

"""

import re
from functools import wraps
from restapi.exceptions import RestApiException
from restapi.confs import SENTRY_URL
from restapi.utilities.htmlcodes import hcodes
from restapi.utilities.globals import mem

from restapi.utilities.logs import log


#################################
# Identity is usefull to some (very) extreme decorators cases
def identity(*args, **kwargs):
    """ Expecting no keywords arguments """
    kwargs['content'] = args
    return kwargs


#################################
# Decide what is the response method for every endpoint


def set_response(original=False, custom_method=None, first_call=False):

    # Use identity if requested
    if original:
        mem.current_response = identity

    # Custom method is another option
    elif custom_method is not None:
        mem.current_response = custom_method

        # Debug when response is injected and if custom
        if not first_call:
            log.debug("Response method set to: {}", custom_method)


def custom_response(func=None, original=False):
    set_response(original=original, custom_method=func)


def get_response():
    return mem.current_response


#####################################################################
# # Error handling with custom methods
# def send_error(self, error, code=hcodes.HTTP_BAD_REQUEST):

#     # It is already print by send_errors, it is a duplicated msg
#     # log.error(error)
#     return self.send_errors(message=str(error), code=code)


def catch_error(exception=None, catch_generic=True, exception_label=None, **kwargs):
    """
    A decorator to preprocess an API class method,
    and catch a specific error.
    """

    if exception_label is None:
        exception_label = ''
    if len(exception_label) > 0:
        exception_label += ': '
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

                message = exception_label + str(e)
                if hasattr(e, "status_code"):
                    error_code = getattr(e, "status_code")
                else:
                    error_code = hcodes.HTTP_BAD_REQUEST
                # return send_error(self, message, error_code)
                return self.send_errors(message=message, code=error_code)

            # Catch the basic API exception
            except RestApiException as e:
                log.warning(e)
                if catch_generic:
                    # return send_error(self, e, e.status_code)
                    return self.send_errors(message=str(e), code=e.status_code)
                else:
                    raise e

            # Catch any other exception
            except Exception as e:

                if SENTRY_URL is not None:
                    from sentry_sdk import capture_exception

                    capture_exception(e)

                excname = e.__class__.__name__
                log.warning(
                    "Catched exception:\n\n[{}] {}\n", excname, e, exc_info=True
                )
                if catch_generic:
                    if excname in ['AttributeError', 'ValueError', 'KeyError']:
                        error = 'Server failure; please contact admin.'
                    else:
                        error = str(e)
                    # return send_error(self, error, hcodes.HTTP_BAD_REQUEST)
                    return self.send_errors(message=error, code=hcodes.HTTP_BAD_REQUEST)
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
            m = re.search("{} (.+) and property (.+)".format(prefix), str(e))

            if m:
                node = m.group(1)
                prop = m.group(2)
                val = m.group(3)
                error = "A {} already exists with {} = {}".format(node, prop, val)
            else:
                error = str(e)

            raise RestApiException(error, status_code=hcodes.HTTP_BAD_CONFLICT)
        except (RequiredProperty) as e:
            raise RestApiException(str(e))

        # FIXME: to be specified with new neomodel exceptions
        # except ConstraintViolation as e:
        # except UniqueProperty as e:

    return wrapper
