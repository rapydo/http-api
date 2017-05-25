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

# import traceback
from functools import wraps
from rapydo.exceptions import RestApiException
from rapydo.utils import htmlcodes as hcodes
from rapydo.utils.globals import mem
from rapydo.utils.logs import get_logger

log = get_logger(__name__)


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
            log.debug("Response method set to: %s" % custom_method)


def custom_response(func=None, original=False):
    set_response(original=original, custom_method=func)


def get_response():
    return mem.current_response


# #################################
# # Adding an identifier to a REST class
# # https://andrefsp.wordpress.com/2012/08/23/writing-a-class-decorator-in-python

# def enable_endpoint_identifier(name='myid', idtype='string'):
#     """
#     Class decorator for ExtendedApiResource objects;
#     Enable identifier and let you choose name and type.
#     """
#     def class_rebuilder(cls):   # decorator

#         def init(self):
#             log.info("[%s] Applying ID to endopoint:%s of type '%s'"
#                      % (self.__class__.__name__, name, idtype))
#             self.set_method_id(name, idtype)
#             # log.debug("New init %s %s" % (name, idtype))
#             super(cls, self).__init__()

#         NewClass = Meta.metaclassing(
#             cls, cls.__name__ + '_withid', {'__init__': init})
#         return NewClass
#     return class_rebuilder


# #################################
# # TOFIX: remove it here, it has been moved to commons

# # NOTE: ...this decorator took me quite a lot of time...

# # In fact, it is a decorator which requires special points:
# # 1. chaining: more than one decorator of the same type stacked
# # 2. arguments: the decorator takes parameters
# # 3. works for a method of class: not a single function, but with 'self'

# # http://scottlobdell.me/2015/04/decorators-arguments-python/
# def add_endpoint_parameter(name, ptype=str, default=None, required=False):

#     def decorator(func):
#         log.warning("DEPRECATED add_endpoint_parameter for %s" % func)

#         @wraps(func)
#         def wrapper(self, *args, **kwargs):

#             class_name = self.__class__.__name__
#             method_name = func.__name__.upper()
#             log.debug("[Class: %s] %s decorated with parameter '%s'"
#                       % (class_name, method_name, name))
#             params = {
#                 'name': name,
#                 'method': method_name,
#                 'mytype': ptype,
#                 'default': default,
#                 'required': required,
#             }
#             self.add_parameter(**params)
#             return func(self, *args, **kwargs)
#         return wrapper
#     return decorator


##############################
# Defining a generic decorator for restful methods

# It will assure to have all necessary things up:

# 1. standard json data returns
# MOVED INTO response.py/server.py

# 2. also to have my requested parameters configured and parsed
# right before the function call (necessary for flask_restful)
# http://flask-restful.readthedocs.org/en/latest/reqparse.html

# def apimethod(func):
#     """ 
#     Decorate methods to return the most standard json data
#     and also to parse available args before using them in the function
#     """

#     log.warning("Deprecated 'apimethod', to add parameters use SWAGGER")

#     @wraps(func)
#     def wrapper(self, *args, **kwargs):

#         # Debug
#         class_name = self.__class__.__name__
#         method_name = func.__name__.upper()
#         log.info("[Class: %s] %s request" % (class_name, method_name))

#         #######################
#         # PARAMETERS INPUT

#         # Load the right parameters that were decorated
#         if self.apply_parameters(method_name):
#             # Call the parse method
#             self.parse()

#         #######################
# # MAYBE THIS IS STILL USEFULL
#         # Call the wrapped function
#         out = None
#         try:
#             out = func(self, *args, **kwargs)
#         # Handle any error to avoid Flask using the HTML web page for errors
#         except BaseException as e:
#             # raise e
#             log.warning("nb: dig more changing the decorator 'except'")
#             # If we raise NotImpleted
#             if isinstance(e, NotImplementedError):
#                 message = "Missing functionality"
#             else:
#                 message = "Unexpected error"
#             return self.report_generic_error("%s\n[%s]" % (message, e))
#         finally:
#             log.debug("Called %s", func)

#         return out

#     return wrapper


# ##############################
# # A decorator for the whole class

# def all_rest_methods(Cls):
#     """
#     Decorate all the rest methods inside the custom restful class,
#     with the previously created 'apimethod'
#     """

#     api_methods = ['get', 'post', 'put', 'patch', 'delete']  # , 'search']

#     for attr in Cls.__dict__:

#         # Check if it's a method and if in it's in my list
#         if attr not in api_methods or not callable(getattr(Cls, attr)):
#             continue

#         # Get the method, and set the decorated version
#         original_method = getattr(Cls, attr)
#         setattr(Cls, attr, apimethod(original_method))

#         log.debug("Decorated %s.%s as api method" % (Cls.__name__, attr))

#     return Cls


#####################################################################
# Error handling with custom methods
def send_error(self, e, code=None):

    if code is None:
        code = hcodes.HTTP_BAD_REQUEST
    error = str(e)
    log.error(error)
    return self.send_errors(message=error, code=code)


def catch_error(
        exception=None, catch_generic=True,
        exception_label=None,
        # TOFIX: where have this gone??
        # error_code=None,
        **kwargs):
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

            # Catch the single exception that the user requested
            except exception as e:

                message = exception_label + str(e)
                if hasattr(e, "status_code"):
                    error_code = getattr(e, "status_code")
                    return send_error(self, message, error_code)
                else:
                    return send_error(self, message)

            # Catch the basic API exception
            except RestApiException as e:

                if catch_generic:
                    return send_error(self, e, e.status_code)
                else:
                    raise e

            # Catch any other exception
            except Exception as e:
                if catch_generic:
                    return send_error(self, e)
                else:
                    raise e

            return out
        return wrapper
    return decorator
