# -*- coding: utf-8 -*-

from flask import Response, render_template, jsonify
from werkzeug.wrappers import Response as WerkzeugResponse
from restapi.utilities.htmlcodes import hcodes
from restapi.utilities.logs import log


class ResponseMaker:

    @staticmethod
    def get_accepted_formats():
        from flask import request

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
            code = hcodes.HTTP_SERVICE_UNAVAILABLE

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
