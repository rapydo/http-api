from functools import wraps

import werkzeug.exceptions
from amqp.exceptions import AccessRefused
from flask_apispec import marshal_with, use_kwargs  # also imported from endpoints
from marshmallow import post_load
from sentry_sdk import capture_exception

from restapi.confs import SENTRY_URL
from restapi.exceptions import (
    BadRequest,
    Conflict,
    DatabaseDuplicatedEntry,
    RestApiException,
)
from restapi.models import InputSchema, fields, validate
from restapi.rest.bearer import HTTPTokenAuth as auth  # imported as alias for endpoints
from restapi.utilities.logs import log

log.verbose("Auth loaded {}", auth)
log.verbose("Marshal loaded {}", marshal_with)


def catch_errors(magic=False, **kwargs):
    """
    A decorator to preprocess an API class method,
    and catch a specific error.
    """

    # Deprecated since 0.7.5
    if not magic:  # pragma: no cover
        log.warning(
            "Deprecated use of catch_errors, just remove it... now it is automatic"
        )

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
                if excname in ["AttributeError", "ValueError", "KeyError"]:
                    error = "Server failure; please contact admin."
                else:
                    error = {excname: message}
                return self.response(error, code=400)

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

            raise Conflict(str(e))

        except RequiredProperty as e:

            raise BadRequest(e)

    return wrapper


class Pagination(InputSchema):
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
    @use_kwargs(Pagination, locations=["query"])
    def get_wrapper(self, *args, **kwargs):

        return func(self, *args, **kwargs)

    @wraps(func)
    # Should be converted in use_args, if/when available
    # https://github.com/jmcarp/flask-apispec/issues/189
    @use_kwargs(Pagination, locations=["form", "json"])
    def wrapper(self, *args, **kwargs):

        return func(self, *args, **kwargs)

    if func.__name__ == "get":
        return get_wrapper
    return wrapper


class ChunkUpload(InputSchema):
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
