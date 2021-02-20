from functools import wraps
from typing import Any, Callable, Dict, Optional, TypeVar, Union, cast

import werkzeug.exceptions
from amqp.exceptions import AccessRefused
from flask import request
from flask_apispec import marshal_with  # also imported from endpoints
from flask_apispec import use_kwargs as original_use_kwargs
from marshmallow import post_load
from sentry_sdk import capture_exception

from restapi.config import SENTRY_URL
from restapi.exceptions import (
    BadRequest,
    Conflict,
    DatabaseDuplicatedEntry,
    RestApiException,
)
from restapi.models import PartialSchema, fields, validate
from restapi.rest.annotations import inject_apispec_docs
from restapi.rest.bearer import TOKEN_VALIDATED_KEY
from restapi.rest.bearer import HTTPTokenAuth as auth  # imported as alias for endpoints
from restapi.utilities.globals import mem
from restapi.utilities.logs import log

log.debug("Auth loaded {}", auth)
log.debug("Marshal loaded {}", marshal_with)

SYSTEM_EXCEPTIONS = ["AttributeError", "ValueError", "KeyError", "SystemError"]


F = TypeVar("F", bound=Callable[..., Any])


# same definition as in:
# https://github.com/jmcarp/flask-apispec/blob/master/flask_apispec/annotations.py
def use_kwargs(args, location=None, inherit=None, apply=None, **kwargs):
    # this use_kwargs is used override the default location (json)
    # with a more extensive default location (body)
    # This trick will prevent to add location='body' to mostly all models
    # Please note that body is also used as "in" parameter in swagger specs and well
    # accepted by schemathesis
    if location is None:
        location = "body"

    return original_use_kwargs(
        args=args, location=location, inherit=inherit, apply=apply, **kwargs
    )


def endpoint(
    path: str,
    summary: Optional[str] = None,
    description: Optional[str] = None,
    responses: Optional[Dict[Union[str, int], str]] = None,
    **kwargs: Any,
) -> Callable[[F], F]:
    def decorator(func: F) -> F:

        specs: Dict[str, Any] = {}

        specs["summary"] = summary
        specs["description"] = description

        specs_responses: Dict[str, Dict[str, str]] = {}
        if responses:
            for code, message in responses.items():
                specs_responses[str(code)] = {"description": message}
        specs["responses"] = specs_responses

        if not hasattr(func, "uris"):
            setattr(func, "uris", [])
        getattr(func, "uris").append(path)
        inject_apispec_docs(func, specs, None)

        @wraps(func)
        def wrapper(self: Any, *args: Any, **kwargs: Any) -> F:

            return cast(F, func(self, *args, **kwargs))

        return cast(F, wrapper)

    return decorator


# Prevent caching of 5xx errors responses
def cache_response_filter(response):
    if not isinstance(response, tuple):
        return True

    if len(response) < 3:  # pragma: no cover
        return True

    return response[1] < 500


# This is used to manipulate the function name to append a string depending
# by the Bearer token. This way all cache entries for authenticated endpoints
# will always user-dependent.
def make_cache_function_name(name: str) -> str:

    # Non authenticated endpoints do not valida the token.
    # Function name is not expanded by any token that could be provided (are ignored)
    if not request.environ.get(TOKEN_VALIDATED_KEY):
        return name

    # If the token is validated, the function name is expanded by a token-dependent key
    token = auth.get_authorization_token(allow_access_token_parameter=True)
    new_name = f"{name}-{hash(token)}"
    return new_name


# Used to cache endpoint with @decorators.cache(timeout=60)
def cache(*args, **kwargs):
    if "response_filter" not in kwargs:
        kwargs["response_filter"] = cache_response_filter
    if "make_name" not in kwargs:
        kwargs["make_name"] = make_cache_function_name
    return mem.cache.memoize(*args, **kwargs)


# Deprecated since 1.0
def catch_graph_exceptions(func):  # pragma: no cover

    log.warning(
        "Deprecated use of decorators.catch_graph_exceptions, you can safely remove it"
    )

    @wraps(func)
    def wrapper(self, *args, **kwargs):

        from neomodel.exceptions import RequiredProperty

        try:
            return func(self, *args, **kwargs)

        except DatabaseDuplicatedEntry as e:

            log.critical("boh")

            raise Conflict(str(e))

        except RequiredProperty as e:

            log.critical("Missing required")

            raise BadRequest(e)

    return wrapper


def graph_transactions(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):

        from neomodel import db

        try:

            db.begin()

            out = func(self, *args, **kwargs)

            db.commit()

            return out
        except Exception as e:
            log.debug("Neomodel transaction ROLLBACK")
            try:
                db.rollback()
            except Exception as sub_ex:
                log.warning("Exception raised during rollback: {}", sub_ex)
            raise e

    return wrapper


class Pagination(PartialSchema):
    get_total = fields.Boolean(
        required=False, description="Request the total number of elements"
    )
    page = fields.Int(
        required=False,
        description="Current page number",
        validate=validate.Range(min=1),
    )
    size = fields.Int(
        required=False,
        description="Number of elements to retrieve",
        validate=validate.Range(min=1, max=100),
    )
    sort_order = fields.Str(
        validate=validate.OneOf(["asc", "desc"]), required=False, missing="asc"
    )
    sort_by = fields.Str(required=False, missing=None)
    input_filter = fields.Str(required=False, missing=None)

    @post_load
    def verify_parameters(self, data, **kwargs):
        if "get_total" in data:
            data["page"] = None
            data["size"] = None
        else:
            data.setdefault("get_total", False)
            data.setdefault("page", 1)
            data.setdefault("size", 20)

        return data


def get_pagination(func):
    @wraps(func)
    # Should be converted in use_args, if/when available
    # https://github.com/jmcarp/flask-apispec/issues/189
    @use_kwargs(Pagination, location="query")
    def get_wrapper(self, *args, **kwargs):

        return func(self, *args, **kwargs)

    @wraps(func)
    # Should be converted in use_args, if/when available
    # https://github.com/jmcarp/flask-apispec/issues/189
    @use_kwargs(Pagination)
    def wrapper(self, *args, **kwargs):

        return func(self, *args, **kwargs)

    if func.__name__ == "get":
        return get_wrapper
    return wrapper


class ChunkUpload(PartialSchema):
    name = fields.Str(required=True)
    mimeType = fields.Str(required=True)
    size = fields.Int(required=True, validate=validate.Range(min=1))
    lastModified = fields.Int(required=True, validate=validate.Range(min=1))


def init_chunk_upload(func):
    @wraps(func)
    # Should be converted in use_args, if/when available
    # https://github.com/jmcarp/flask-apispec/issues/189
    @use_kwargs(ChunkUpload)
    def wrapper(self, *args, **kwargs):

        return func(self, *args, **kwargs)

    return wrapper


# This decorator is automatically added to every endpoints... do not use it explicitly!
def catch_exceptions(**kwargs):
    """
    A decorator to preprocess an API class method,
    and catch a specific error.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            out = None

            try:
                out = func(self, *args, **kwargs)
            # Catch the exception requested by the user
            except RestApiException as e:

                if e.is_warning:
                    log.warning(e)
                else:
                    log.exception(e)
                    log.error(e)

                return self.response(e.args[0], code=e.status_code)

            except werkzeug.exceptions.BadRequest:  # pragma: no cover
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

            # errors with RabbitMQ credentials raised when sending Celery tasks
            except AccessRefused as e:  # pragma: no cover
                log.critical(e)
                return self.response("Unexpected Server Error", code=500)
            except Exception as e:

                if SENTRY_URL is not None:  # pragma: no cover
                    capture_exception(e)

                excname = e.__class__.__name__
                message = str(e)
                if not message:  # pragma: no cover
                    message = "Unknown error"
                log.exception(message)
                log.error("Catched {} exception: {}", excname, message)

                if excname in SYSTEM_EXCEPTIONS:
                    return self.response(
                        "Server failure; please contact admin.", code=400
                    )
                return self.response({excname: message}, code=400)

            return out

        return wrapper

    return decorator
