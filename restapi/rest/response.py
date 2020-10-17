from urllib import parse as urllib_parse

from flask import jsonify, render_template, request
from marshmallow.utils import _Missing

from restapi import __version__ as version
from restapi.confs import get_project_configuration
from restapi.models import GET_SCHEMA_KEY, fields, validate
from restapi.services.authentication import BaseAuthentication
from restapi.utilities.logs import handle_log_output, log, obfuscate_dict


def handle_marshmallow_errors(error):

    try:

        params = request.args or request.get_json() or request.form or {}

        if params.get(GET_SCHEMA_KEY, False):
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


def log_response(response):

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

    # Obfuscating query parameters
    url = urllib_parse.urlparse(request.url)
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

    url = urllib_parse.urlunparse(url)
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
    def convert_model_to_schema(schema):
        schema_fields = []
        for field, field_def in schema.declared_fields.items():
            if field == GET_SCHEMA_KEY:
                continue

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
            f["required"] = "true" if field_def.required else "false"

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
                    if len(labels) != len(choices):
                        labels = choices
                    f["enum"] = dict(zip(choices, labels))

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
