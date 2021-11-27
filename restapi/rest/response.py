import decimal
import gzip
import sys
import time
from datetime import date, datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, cast
from urllib import parse as urllib_parse

from flask import Response as FlaskResponse
from flask import jsonify, render_template, request
from flask.json import JSONEncoder
from marshmallow import fields as marshmallow_fields
from marshmallow.utils import _Missing

from restapi import __version__ as version
from restapi.config import (
    GZIP_ENABLE,
    GZIP_LEVEL,
    GZIP_THRESHOLD,
    get_project_configuration,
)
from restapi.models import GET_SCHEMA_KEY, Schema, fields, validate
from restapi.services.authentication import BaseAuthentication
from restapi.types import Response, ResponseContent
from restapi.utilities.logs import handle_log_output, log, obfuscate_dict


def handle_marshmallow_errors(error: Exception) -> Response:

    try:

        if request.args:
            if request.args.get(GET_SCHEMA_KEY, False):  # pragma: no cover
                schema = cast(Schema, error.data.get("schema"))  # type: ignore
                return ResponseMaker.respond_with_schema(schema)

        elif j := request.get_json():
            if j.get(GET_SCHEMA_KEY, False):  # pragma: no cover
                schema = cast(Schema, error.data.get("schema"))  # type: ignore
                return ResponseMaker.respond_with_schema(schema)

        elif request.form:
            if request.form.get(GET_SCHEMA_KEY, False):
                schema = cast(Schema, error.data.get("schema"))  # type: ignore
                return ResponseMaker.respond_with_schema(schema)

    except Exception as e:  # pragma: no cover
        log.error(e)

    errors = {}

    error_messages = cast(
        Dict[str, Dict[str, str]], error.data.get("messages")  # type: ignore
    )
    for key, messages in error_messages.items():
        for k, msg in messages.items():
            if not msg:  # pragma: no cover
                continue
            log.error("[{}] {}: {}", key, k, msg)
            errors[k] = msg

    return (errors, 400, {})


def obfuscate_query_parameters(raw_url: str) -> str:
    url = urllib_parse.urlparse(raw_url)
    try:
        params = urllib_parse.unquote(
            urllib_parse.urlencode(handle_log_output(url.query))
        )
        url = url._replace(query=params)
        # remove http(s)://
        url = url._replace(scheme="")
        # remove hostname:port
        url = url._replace(netloc="")
    except TypeError:  # pragma: no cover
        log.error("Unable to url encode the following parameters:")
        print(url.query)
        return urllib_parse.urlunparse(url)

    return urllib_parse.urlunparse(url)


def get_data_from_request() -> str:
    # If it is an upload, DO NOT consume request.data or request.json,
    # otherwise the content gets lost
    try:
        if request.mimetype in ["application/octet-stream", "multipart/form-data"]:
            return " STREAM_UPLOAD"

        if request.data:
            if data := handle_log_output(request.data):
                return f" {data}"

        if request.form:
            if data := obfuscate_dict(request.form):
                return f" {data}"

    except Exception as e:  # pragma: no cover
        log.debug(e)

    return ""


def handle_response(response: FlaskResponse) -> FlaskResponse:

    response.headers["_RV"] = str(version)

    PROJECT_VERSION = get_project_configuration("project.version", default="0")
    if PROJECT_VERSION is not None:
        response.headers["Version"] = str(PROJECT_VERSION)

    data_string = get_data_from_request()

    url = obfuscate_query_parameters(request.url)

    if (
        GZIP_ENABLE
        and not response.is_streamed
        and "gzip" in request.headers.get("Accept-Encoding", "").lower()
    ):
        response.direct_passthrough = False
        content, headers = ResponseMaker.gzip_response(
            response.data,
            response.status_code,
            response.headers.get("Content-Encoding"),
            response.headers.get("Content-Type"),
        )
        if content:
            response.data = content
            response.headers.update(headers)

    resp = str(response).replace("<Response ", "").replace(">", "")
    ip = BaseAuthentication.get_remote_ip(raise_warnings=False)

    is_healthcheck = (
        ip == "127.0.0.1" and request.method == "GET" and url == "/api/status"
    )
    if is_healthcheck:
        log.debug(
            "{} {} {}{} -> {} [HEALTHCHECK]",
            ip,
            request.method,
            url,
            data_string,
            resp,
        )
    else:
        log.info(
            "{} {} {}{} -> {}",
            ip,
            request.method,
            url,
            data_string,
            resp,
        )

    return response


class ExtendedJSONEncoder(JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, set):
            return list(o)
        if isinstance(o, (datetime, date)):
            return o.isoformat()
        if isinstance(o, decimal.Decimal):
            return float(o)
        if isinstance(o, Path):
            return str(o)
        # Otherwise: TypeError: Object of type xxx is not JSON serializable
        return super().default(o)  # pragma: no cover


class ResponseMaker:

    # Have a look here: (from flask import request)
    # request.user_agent.browser
    @staticmethod
    def get_accepted_formats() -> List[str]:
        """
        Possible outputs:
        '*/*'
        'application/json'
        'text/html'
        'application/xml'
        'text/csv'
        """
        for val in request.headers:
            if val[0] == "Accept":
                return [x.strip() for x in val[1].split(",")]
        return ["*/*"]

    @staticmethod
    def is_binary(content_type: Optional[str]) -> bool:
        if not content_type:
            return False

        if content_type == "application/json":
            return False

        if content_type.startswith("text/"):
            return False

        if content_type.startswith("image/"):
            return True

        if content_type.startswith("audio/"):
            return True

        if content_type.startswith("video/"):
            return True

        if content_type.startswith("application/"):
            return True

        log.warning("Unknown Content-Type: {}", content_type)
        return False

    @staticmethod
    def get_html(
        content: ResponseContent, code: int, headers: Dict[str, str]
    ) -> Tuple[str, Dict[str, str]]:

        if isinstance(content, list):  # pragma: no cover
            content = content.pop()

        headers["Content-Type"] = "text/html; charset=UTF-8"

        html_data = {"body_content": content, "is_error": code >= 400}
        html_page = render_template("index.html", **html_data)

        return html_page, headers

    @staticmethod
    def gzip_response(
        content: bytes,
        code: int,
        content_encoding: Optional[str],
        content_type: Optional[str],
    ) -> Tuple[Optional[bytes], Dict[str, str]]:
        if code < 200 or code >= 300 or content_encoding is not None:
            return None, {}

        # Do not compress binary contents (like images) due to small benefits expected
        if ResponseMaker.is_binary(content_type):  # pragma: no cover
            # log.warning("Skipping gzip compression on {}", content_type)
            return None, {}

        # Do not compress small contents
        if (nbytes := sys.getsizeof(content)) < GZIP_THRESHOLD:
            return None, {}

        start_time = time.time()

        gzip_buffer = BytesIO()
        # compresslevel: an integer from 0 to 9 controlling the level of compression;
        # 1 is fastest and produces the least compression
        # 9 is slowest and produces the most compression (default)
        # 0 is no compression
        gzip_file = gzip.GzipFile(
            mode="w", fileobj=gzip_buffer, compresslevel=GZIP_LEVEL
        )

        gzip_file.write(content)
        gzip_file.close()

        gzipped_content = gzip_buffer.getvalue()

        headers = {
            "Content-Encoding": "gzip",
            "Vary": "Accept-Encoding",
            "Content-Length": str(len(gzipped_content)),
        }

        end_time = time.time()
        t = int(1000 * (end_time - start_time))
        new_size = sys.getsizeof(gzipped_content)
        ratio = 1 - new_size / nbytes

        log.info(
            "[GZIP] {} bytes compressed in {} ms -> {} bytes ({:.2f} %)",
            nbytes,
            "< 1" if t < 1 else t,
            new_size,
            100 * ratio,
        )
        # This a debug code use to detect content types that should not be compressed
        if ratio < 0.1:  # pragma: no cover
            log.warning(
                "Small benefit due to gzip compression on Content-Type: {} ({:.2f} %)",
                content_type,
                100 * ratio,
            )
        return gzipped_content, headers

    @staticmethod
    def convert_model_to_schema(schema: Schema) -> List[Dict[str, Any]]:

        schema_fields = []
        for field, field_def in schema.declared_fields.items():

            f: Dict[str, Any] = {}

            f["key"] = field_def.data_key or field

            if "label" in field_def.metadata:
                f["label"] = field_def.metadata["label"]
            elif f["key"] == f["key"].lower():
                f["label"] = f["key"].title()
            else:
                f["label"] = f["key"]

            if "description" in field_def.metadata:
                f["description"] = field_def.metadata["description"]
            else:
                f["description"] = f["label"]
            f["required"] = field_def.required

            f["type"] = ResponseMaker.get_schema_type(field, field_def)

            if autocomplete_endpoint := field_def.metadata.get("autocomplete_endpoint"):
                f["autocomplete_endpoint"] = autocomplete_endpoint
                f["autocomplete_show_id"] = field_def.metadata.get(
                    "autocomplete_show_id", False
                )

            if autocomplete_id_bind := field_def.metadata.get("autocomplete_id_bind"):
                f["autocomplete_id_bind"] = autocomplete_id_bind

            if autocomplete_label_bind := field_def.metadata.get(
                "autocomplete_label_bind"
            ):
                f["autocomplete_label_bind"] = autocomplete_label_bind

            if not isinstance(field_def.dump_default, _Missing):
                f["default"] = field_def.dump_default
            elif not isinstance(field_def.load_default, _Missing):  # pragma: no cover
                f["default"] = field_def.load_default

            validators: List[validate.Validator] = []
            if field_def.validate:
                validators.append(field_def.validate)  # type: ignore

            # activated in case of fields.List(fields.SomeThing) with an inner validator
            if isinstance(field_def, fields.List) and field_def.inner.validate:
                validators.append(field_def.inner.validate)

            for validator in validators:
                if isinstance(validator, validate.Length):

                    if validator.min is not None:
                        f["min"] = validator.min
                    if validator.max is not None:
                        f["max"] = validator.max
                    if validator.equal is not None:
                        f["min"] = validator.equal
                        f["max"] = validator.equal

                elif isinstance(validator, validate.Range):

                    if validator.min is not None:
                        f["min"] = validator.min
                        if not validator.min_inclusive:
                            f["min"] += 1

                    if validator.max is not None:
                        f["max"] = validator.max
                        if not validator.max_inclusive:
                            f["max"] -= 1

                elif isinstance(validator, validate.OneOf):

                    choices = validator.choices
                    labels = validator.labels
                    if len(tuple(labels)) != len(tuple(choices)):
                        labels = choices
                    f["options"] = dict(zip(choices, labels))

                else:  # pragma: no cover

                    log.warning(
                        "Unsupported validation schema: {}.{}",
                        type(validator).__module__,
                        type(validator).__name__,
                    )

            if f["type"] == "nested":
                f["schema"] = ResponseMaker.convert_model_to_schema(
                    field_def.schema  # type: ignore
                )

            schema_fields.append(f)
        return schema_fields

    @staticmethod
    def respond_with_schema(schema: Schema) -> Response:

        try:
            fields = ResponseMaker.convert_model_to_schema(schema)
            return (jsonify(fields), 200, {})
        except Exception as e:  # pragma: no cover
            log.error(e)
            content = {"Server internal error": "Failed to retrieve input schema"}
            return (jsonify(content), 500, {})

    @staticmethod
    def get_schema_type(
        field: str, schema: marshmallow_fields.Field, default: Optional[Any] = None
    ) -> str:

        if schema.metadata.get("password", False):
            return "password"
        # types from https://github.com/danohu/py2ng
        # https://github.com/danohu/py2ng/blob/master/py2ng/__init__.py
        if isinstance(schema, fields.Bool) or isinstance(schema, fields.Boolean):
            return "boolean"
        if isinstance(schema, fields.Date):
            return "date"
        # Include both AwareDateTime and NaiveDateTime that extend DateTime
        if isinstance(schema, fields.DateTime):
            return "date"
        if isinstance(schema, fields.Decimal):
            return "number"
        if isinstance(schema, fields.Dict):
            return "dictionary"
        if isinstance(schema, fields.Email):
            return "email"
        # if isinstance(schema, fields.Field):
        #     return 'any'
        if isinstance(schema, fields.Float):
            return "number"
        if isinstance(schema, fields.Int) or isinstance(schema, fields.Integer):
            return "int"
        if isinstance(schema, fields.List):
            key = schema.data_key or field
            inner_type = ResponseMaker.get_schema_type(field, schema.inner, default=key)
            return f"{inner_type}[]"
        if isinstance(schema, fields.Nested):
            return "nested"
        if isinstance(schema, fields.Number):
            return "number"
        if isinstance(schema, fields.Str) or isinstance(schema, fields.String):
            return "string"

        # Reached with lists of custom types
        if default:
            return str(default)

        log.error("Unknown schema type: {}", type(schema))

        return "string"
