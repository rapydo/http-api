# -*- coding: utf-8 -*-

from flask import Response, request, render_template, jsonify
from werkzeug.wrappers import Response as WerkzeugResponse
from marshmallow import fields, validate
from urllib import parse as urllib_parse

from restapi import __version__ as version
from restapi.confs import get_project_configuration
from restapi.utilities.logs import log
from restapi.utilities.logs import handle_log_output, MAX_CHAR_LEN


def handle_marshmallow_errors(error):

    try:
        req_json = request.get_json()
        if req_json:
            get_schema = req_json.get("get_schema", False)
            if get_schema or get_schema == 1 or get_schema == "1":
                return ResponseMaker.respond_with_schema(
                    error.data.get('schema')
                )
    except BaseException as e:
        log.error(e)

    return (error.data.get("messages"), 400, {})


def log_response(response):

    response.headers["_RV"] = str(version)

    PROJECT_VERSION = get_project_configuration(
        "project.version", default=None
    )
    if PROJECT_VERSION is not None:
        response.headers["Version"] = str(PROJECT_VERSION)
    # NOTE: if it is an upload,
    # I must NOT consume request.data or request.json,
    # otherwise the content gets lost
    do_not_log_types = ['application/octet-stream', 'multipart/form-data']

    if request.mimetype in do_not_log_types:
        data = 'STREAM_UPLOAD'
    else:
        try:
            data = handle_log_output(request.data)
            # Limit the parameters string size, sometimes it's too big
            for k in data:
                try:
                    if isinstance(data[k], dict):
                        for kk in data[k]:
                            v = str(data[k][kk])
                            if len(v) > MAX_CHAR_LEN:
                                v = v[:MAX_CHAR_LEN] + "..."
                            data[k][kk] = v
                        continue

                    if not isinstance(data[k], str):
                        data[k] = str(data[k])

                    if len(data[k]) > MAX_CHAR_LEN:
                        data[k] = data[k][:MAX_CHAR_LEN] + "..."
                except IndexError:
                    pass
        except Exception:
            data = 'OTHER_UPLOAD'

    # Obfuscating query parameters
    url = urllib_parse.urlparse(request.url)
    try:
        params = urllib_parse.unquote(
            urllib_parse.urlencode(handle_log_output(url.query))
        )
        url = url._replace(query=params)
        # remove http(s)://
        url = url._replace(scheme='')
        # remove hostname:port
        url = url._replace(netloc='')
    except TypeError:
        log.error("Unable to url encode the following parameters:")
        print(url.query)

    url = urllib_parse.urlunparse(url)
    resp = str(response).replace("<Response ", "").replace(">", "")
    log.info("{} {} {} - {}", request.method, url, data, resp)

    return response


class ResponseMaker:

    @staticmethod
    def get_accepted_formats():

        for val in request.headers:
            if val[0] == "Accept":
                return [x.strip() for x in val[1].split(',')]
        return ['*/*']

    @staticmethod
    def add_to_dict(mydict, content, key='content'):
        if content is None:
            content = {}
        elif not isinstance(content, dict):
            content = {key: content}
        mydict.update(content)
        return mydict

    @staticmethod
    def respond_to_browser(content, errors, code, headers):
        log.debug("Request from a browser: reply with HTML.")

        if errors:
            if isinstance(content, list):
                errors = errors.pop()
            html_data = {'body_content': errors, 'is_error': True}
        else:
            html_data = {'body_content': content, 'is_error': False}
        html_page = render_template('index.html', **html_data)
        return Response(
            html_page,
            mimetype='text/html',
            status=code,
            headers=headers
        )

    @staticmethod
    def generate_response(content, code, errors, headers,
                          head_method, meta, response_wrapper=None):
        """
        Generating from our user/custom/internal response
        the data necessary for a Flask response (make_response() method):
        a tuple (content, status, headers)
        """

        accepted_formats = ResponseMaker.get_accepted_formats()

        if 'text/html' in accepted_formats:
            return ResponseMaker.respond_to_browser(content, errors, code, headers)

        if response_wrapper is not None:
            # {Response: DEFINED_CONTENT, Meta: HEADERS_AND_STATUS}
            final_content = response_wrapper(content, code, errors, meta)
        elif content is not None:
            final_content = content
        else:
            final_content = errors

        if '*/*' in accepted_formats or 'application/json' in accepted_formats:
            final_content = jsonify(final_content)

        elif 'application/xml' in accepted_formats:
            # TODO: we should convert final_content in XML
            pass

        elif 'text/csv' in accepted_formats:
            # TODO: we should convert final_content in CSV
            pass

        else:
            log.warning("Unknown accepted format: {}", accepted_formats)

        # return a standard flask response tuple(content, code, headers)
        return (final_content, code, headers)

    @staticmethod
    def wrapped_response(
        content=None, code=None, errors=None, custom_metas=None
    ):

        if isinstance(content, WerkzeugResponse):
            return content

        # Our normal content
        try:
            data_type = str(type(content))

            if content is None:
                elements = 0
            elif isinstance(content, str):
                elements = 1
            else:
                elements = len(content)

            if errors is None:
                total_errors = 0
            else:
                total_errors = len(errors)

            code = int(code)
        except Exception as e:
            log.critical("Could not build response! {}", e)
            # Revert to defaults
            content = None
            errors = ['Failed to build response {}'.format(e)]
            data_type = str(type(content))
            elements = 0
            total_errors = 1
            code = 503

        resp = {
            "Response": {
                'data': content,
                'errors': errors
            },
            "Meta": {
                'data_type': data_type,
                'elements': elements,
                'errors': total_errors,
                'status': code,
            },
        }

        if custom_metas is not None:
            resp['Meta'].update(custom_metas)

        return resp

    @staticmethod
    def respond_with_schema(schema):

        fields = []
        try:
            for field, field_def in schema._declared_fields.items():

                f = {}

                if field_def.data_key is None:
                    key = field
                else:
                    key = field_def.data_key

                f["key"] = key

                if "label" in field_def.metadata:
                    f["label"] = field_def.metadata["label"]
                elif key == key.lower():
                    f["label"] = key.title()
                else:
                    f["label"] = key

                if "description" in field_def.metadata:
                    f["description"] = field_def.metadata["description"]
                else:
                    f["description"] = f["label"]
                f["required"] = "true" if field_def.required else "false"

                f["type"] = ResponseMaker.get_schema_type(field_def)

                if field_def.validate is not None:
                    if isinstance(field_def.validate, validate.Length):

                        if field_def.validate.min is not None:
                            f["min"] = field_def.validate.min
                        if field_def.validate.max is not None:
                            f["max"] = field_def.validate.max
                        if field_def.validate.equal is not None:
                            f["min"] = field_def.validate.equal
                            f["max"] = field_def.validate.equal

                    elif isinstance(field_def.validate, validate.Range):

                        if field_def.validate.min is not None:
                            f["min"] = field_def.validate.min
                            if not field_def.validate.min_inclusive:
                                f["min"] += 1

                        if field_def.validate.max is not None:
                            f["max"] = field_def.validate.max
                            if not field_def.validate.max_inclusive:
                                f["max"] += 1

                    elif isinstance(field_def.validate, validate.OneOf):

                        choices = field_def.validate.choices
                        labels = field_def.validate.labels
                        if len(labels) != len(choices):
                            labels = choices
                        f["enum"] = dict(zip(choices, labels))

                    else:

                        log.warning(
                            "Unsupported validation schema: {}.{}",
                            type(field_def.validate).__module__,
                            type(field_def.validate).__name__
                        )

                fields.append(f)
            return ResponseMaker.generate_response(
                content=fields,
                errors=None,
                code=200,
                headers={},
                head_method=False,
                meta=None
            )
        except BaseException as e:
            log.error(e)
            return ResponseMaker.generate_response(
                content=None,
                errors={"Server internal error": "Failed to retrieve input schema"},
                code=500,
                headers={},
                head_method=False,
                meta=None
            )

    @staticmethod
    def get_schema_type(schema):

        if schema.metadata.get("password", False):
            return "password"
        # types from https://github.com/danohu/py2ng
        # https://github.com/danohu/py2ng/blob/master/py2ng/__init__.py
        if isinstance(schema, fields.Bool):
            return 'boolean'
        if isinstance(schema, fields.Boolean):
            return 'boolean'
        # if isinstance(schema, fields.Constant):
        #     return 'any'
        if isinstance(schema, fields.Date):
            return 'date'
        if isinstance(schema, fields.DateTime):
            return 'date'
        if isinstance(schema, fields.Decimal):
            return 'number'
        # if isinstance(schema, fields.Dict):
        #     return 'object'
        if isinstance(schema, fields.Email):
            return 'email'
        # if isinstance(schema, fields.Field):
        #     return 'any'
        if isinstance(schema, fields.Float):
            return 'number'
        # if isinstance(schema, fields.Function):
        #     return 'any'
        if isinstance(schema, fields.Int):
            return 'int'
        if isinstance(schema, fields.Integer):
            return 'int'
        # if isinstance(schema, fields.List):
        #     return 'any[]'
        # if isinstance(schema, fields.Mapping):
        #     return 'any'
        # if isinstance(schema, fields.Method):
        #     return 'any'
        # if isinstance(schema, fields.Nested):
        #     return 'any'
        if isinstance(schema, fields.Number):
            return 'number'
        # if isinstance(schema, fields.Raw):
        #     return 'any'
        if isinstance(schema, fields.Str):
            return 'string'
        if isinstance(schema, fields.String):
            return 'string'
        # if isinstance(schema, fields.TimeDelta):
        #     return 'any'
        if isinstance(schema, fields.URL):
            return 'string'
        if isinstance(schema, fields.Url):
            return 'string'
        if isinstance(schema, fields.UUID):
            return 'string'

        log.error("Unknown schema type: {}", type(schema))

        return "string"
