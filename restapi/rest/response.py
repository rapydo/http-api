# -*- coding: utf-8 -*-

from flask import Response, jsonify, render_template
# from werkzeug import exceptions as wsgi_exceptions
from restapi.utilities.htmlcodes import hcodes
from restapi.utilities.logs import log

MIMETYPE_JSON = 'application/json'
MIMETYPE_XML = 'application/xml'
MIMETYPE_HTML = 'text/html'
MIMETYPE_CSV = 'text/csv'


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

        if errors is not None:
            html_data = {'body_content': errors, 'is_error': True}
        else:
            html_data = {'body_content': content, 'is_error': False}
        html_page = render_template('index.html', **html_data)
        return Response(
            html_page,
            mimetype=MIMETYPE_HTML,
            status=code,
            headers=headers
        )

    @staticmethod
    def generate_response(content, code, errors, headers,
                          head_method, elements, meta, response_wrapper=None):
        """
        Generating from our user/custom/internal response
        the data necessary for a Flask response (make_response() method):
        a tuple (content, status, headers)
        """

        if code is None:
            code = hcodes.HTTP_OK_BASIC

        # # Is that really needed?
        # if errors and not isinstance(errors, list):
        #     errors = [errors]

        if errors is None and content is None:
            if not head_method or code is None:
                log.warning("RESPONSE: Warning, no data and no errors")
                code = hcodes.HTTP_OK_NORESPONSE
        elif errors is None:
            if code >= 300:
                log.warning("Forcing 200 OK because no errors are raised")
                code = hcodes.HTTP_OK_BASIC
        elif content is None:
            if code < 400:
                log.warning("Forcing 500 SERVER ERROR because only errors are returned")
                code = hcodes.HTTP_SERVER_ERROR

        accepted_formats = ResponseMaker.get_accepted_formats()

        if MIMETYPE_HTML in accepted_formats:
            return ResponseMaker.respond_to_browser(content, errors, code, headers)

        if response_wrapper is not None:
            # {Response: DEFINED_CONTENT, Meta: HEADERS_AND_STATUS}
            final_content = response_wrapper(content, elements, code, errors, meta)
        elif content is not None:
            final_content = content
        else:
            final_content = errors

        if MIMETYPE_JSON in accepted_formats:
            # final_content is already JSON based
            pass

        elif MIMETYPE_XML in accepted_formats:
            # TODO: we should convert final_content in XML
            pass

        elif MIMETYPE_CSV in accepted_formats:
            # TODO: we should convert final_content in CSV
            pass

        else:
            log.warning("Unknown accepted format: {}", accepted_formats)

        # return a standard flask response tuple(content, code, headers)
        return (final_content, code, headers)

    @staticmethod
    def wrapped_response(
        content=None, elements=None, code=None, errors=None, custom_metas=None
    ):

        # Our normal content
        try:
            data_type = str(type(content))
            if elements is None:
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

        Response = {
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
            Response['Meta'].update(custom_metas)

        return Response
