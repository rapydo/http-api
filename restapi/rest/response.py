import gzip
import sys
import time
from io import BytesIO
from urllib import parse as urllib_parse

from flask import jsonify, render_template, request
from marshmallow.utils import _Missing

from restapi import __version__ as version
from restapi.config import (
    GZIP_ENABLE,
    GZIP_LEVEL,
    GZIP_THRESHOLD,
    get_project_configuration,
)
from restapi.models import GET_SCHEMA_KEY, fields, validate
from restapi.services.authentication import BaseAuthentication
from restapi.utilities.logs import handle_log_output, log, obfuscate_dict


def handle_marshmallow_errors(error):

    try:

        if request.args:
            if request.args.get(GET_SCHEMA_KEY, False):
                return ResponseMaker.respond_with_schema(error.data.get("schema"))

        elif j := request.get_json():
            if j.get(GET_SCHEMA_KEY, False):
                return ResponseMaker.respond_with_schema(error.data.get("schema"))

        elif request.form:
            if request.form.get(GET_SCHEMA_KEY, False):
                return ResponseMaker.respond_with_schema(error.data.get("schema"))

    except BaseException as e:  # pragma: no cover
        log.error(e)

    errors = {}

    for key, messages in error.data.get("messages").items():
        for k, msg in messages.items():
            if not msg:  # pragma: no cover
                continue
            log.error("[{}] {}: {}", key, k, msg)
            errors[k] = msg

    return (errors, 400, {})


def obfuscate_query_parameters(raw_url):
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
        return url

    return urllib_parse.urlunparse(url)


def handle_response(response):

    response.headers["_RV"] = str(version)

    PROJECT_VERSION = get_project_configuration("project.version", default=None)
    if PROJECT_VERSION is not None:
        response.headers["Version"] = str(PROJECT_VERSION)
    # If it is an upload, DO NOT consume request.data or request.json,
    # otherwise the content gets lost
    try:
        if request.mimetype in ["application/octet-stream", "multipart/form-data"]:
            data = "STREAM_UPLOAD"
        elif request.data:
            data = handle_log_output(request.data)
        elif request.form:
            data = obfuscate_dict(request.form)
        else:
            data = ""

        if data:
            data = f" {data}"
    except Exception as e:  # pragma: no cover
        log.debug(e)
        data = ""

    url = obfuscate_query_parameters(request.url)

    if GZIP_ENABLE and "gzip" in request.headers.get("Accept-Encoding", "").lower():
        content, headers = ResponseMaker.gzip_response(
            response.data,
            response.status_code,
            response.headers.get("Content-Encoding"),
        )
        if content:
            response.direct_passthrough = False
            response.data = content

            try:
                response.headers.update(headers)
            # Back-compatibility for Werkzeug 0.16.1 as used in B2STAGE
            except AttributeError:  # pragma: no cover
                for k, v in headers.items():
                    response.headers.set(k, v)

    resp = str(response).replace("<Response ", "").replace(">", "")
    log.info(
        "{} {} {}{} -> {}",
        BaseAuthentication.get_remote_ip(),
        request.method,
        url,
        data,
        resp,
    )

    return response


class ResponseMaker:

    # Have a look here: (from flask import request)
    # request.user_agent.browser
    @staticmethod
    def get_accepted_formats():
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
    def get_html(content, code, headers):

        if isinstance(content, list):
            content = content.pop()

        headers["Content-Type"] = "text/html; charset=UTF-8"

        html_data = {"body_content": content, "is_error": code >= 400}
        html_page = render_template("index.html", **html_data)

        return html_page, headers

    @staticmethod
    def gzip_response(content, code, content_encoding):
        if code < 200 or code >= 300 or content_encoding is not None:
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
            "Content-Length": len(gzipped_content),
        }

        end_time = time.time()
        t = int(1000 * (end_time - start_time))
        new_size = sys.getsizeof(gzipped_content)
        log.info(
            "[GZIP] {} bytes compressed in {} ms -> {} bytes",
            nbytes,
            "< 1" if t < 1 else t,
            new_size,
        )
        return gzipped_content, headers

    @staticmethod
    def convert_model_to_schema(schema):
        schema_fields = []
        for field, field_def in schema.declared_fields.items():

            f = {}

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

            if field_def.metadata.get("multiple"):
                f["multiple"] = True

            if not isinstance(field_def.missing, _Missing):
                f["default"] = field_def.missing
            elif not isinstance(field_def.default, _Missing):
                f["default"] = field_def.default

            validators = []
            if field_def.validate:
                validators.append(field_def.validate)

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
                            f["max"] += 1

                elif isinstance(validator, validate.OneOf):

                    choices = validator.choices
                    labels = validator.labels
                    if len(tuple(labels)) != len(tuple(choices)):
                        labels = choices
                    f["options"] = dict(zip(choices, labels))

                else:

                    log.warning(
                        "Unsupported validation schema: {}.{}",
                        type(validator).__module__,
                        type(validator).__name__,
                    )

            if f["type"] == "nested":
                f["schema"] = ResponseMaker.convert_model_to_schema(field_def.schema)

            schema_fields.append(f)
        return schema_fields

    @staticmethod
    def respond_with_schema(schema):

        try:
            fields = ResponseMaker.convert_model_to_schema(schema)
            return (jsonify(fields), 200, {})
        except BaseException as e:  # pragma: no cover
            log.error(e)
            content = {"Server internal error": "Failed to retrieve input schema"}
            return (jsonify(content), 500, {})

    @staticmethod
    def get_schema_type(field, schema, default=None):

        if schema.metadata.get("password", False):
            return "password"
        # types from https://github.com/danohu/py2ng
        # https://github.com/danohu/py2ng/blob/master/py2ng/__init__.py
        if isinstance(schema, fields.Bool) or isinstance(schema, fields.Boolean):
            return "boolean"
        # if isinstance(schema, fields.Constant):
        #     return 'any'
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
        # if isinstance(schema, fields.Function):
        #     return 'any'
        if isinstance(schema, fields.Int) or isinstance(schema, fields.Integer):
            return "int"
        if isinstance(schema, fields.List):
            key = schema.data_key or field
            inner_type = ResponseMaker.get_schema_type(field, schema.inner, default=key)
            return f"{inner_type}[]"
        # if isinstance(schema, fields.Mapping):
        #     return 'any'
        # if isinstance(schema, fields.Method):
        #     return 'any'
        if isinstance(schema, fields.Nested):
            return "nested"
        if isinstance(schema, fields.Number):
            return "number"
        # if isinstance(schema, fields.Raw):
        #     return 'any'
        if isinstance(schema, fields.Str) or isinstance(schema, fields.String):
            return "string"
        # if isinstance(schema, fields.TimeDelta):
        #     return 'any'

        if default:
            return default

        log.error("Unknown schema type: {}", type(schema))

        return "string"
