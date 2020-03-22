# -*- coding: utf-8 -*-

from flask import Response, jsonify, render_template
# from werkzeug import exceptions as wsgi_exceptions
from restapi.utilities.htmlcodes import hcodes
from restapi.utilities.logs import log

MIMETYPE_JSON = 'application/json'
MIMETYPE_XML = 'application/xml'
MIMETYPE_HTML = 'text/html'
MIMETYPE_CSV = 'text/csv'


########################
# Flask custom response
########################
class InternalResponse(Response):
    """
    adding a few extra checks on the original flask response
    """

    def __init__(self, *args, **kwargs):
        """
        If the application is not responding JSON (e.g. HTML),
        This call is not executed
        """

        if 'mimetype' not in kwargs and 'contenttype' not in kwargs:
            kwargs['mimetype'] = MIMETYPE_JSON  # our default

        self._latest_response = super().__init__(*args, **kwargs)

    @classmethod
    def force_type(cls, rv, environ=None):
        """ Copy/paste from Miguel's tutorial """

        if isinstance(rv, dict):
            try:
                rv = jsonify(rv)
            except BaseException:
                log.error("Cannot jsonify rv:")
                from prettyprinter import pprint
                pprint(rv)

        return super(InternalResponse, cls).force_type(rv, environ)


###################################
# Flask response internal builder #
###################################
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
                          head_method, elements, meta):
        """
        Generating from our user/custom/internal response
        the data necessary for a Flask response (make_response() method):
        a tuple (content, status, headers)
        """

        # 1. Fix code range

        if code is None:
            code = hcodes.HTTP_OK_BASIC

        # Is that really needed?
        if errors and not isinstance(errors, list):
            errors = [errors]

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

        # 2. Encapsulate response and other things in a standard json obj:
        # {Response: DEFINED_CONTENT, Meta: HEADERS_AND_STATUS}
        final_content = ResponseMaker.standard_response_content(
            content, elements, code, errors, meta
        )

        # 3. Return what is necessary to build a standard flask response
        # from all that was gathered so far
        response = (final_content, code, headers)

        accepted_formats = ResponseMaker.get_accepted_formats()

        if MIMETYPE_HTML in accepted_formats:
            return ResponseMaker.respond_to_browser(content, errors, code, headers)

        if MIMETYPE_JSON in accepted_formats:
            return response

        if MIMETYPE_XML in accepted_formats:
            # TODO: we should convert in XML
            pass

        if MIMETYPE_CSV in accepted_formats:
            # TODO: we should convert in CSV
            pass

        # The client does not support any particular format, use the default
        return response

    @staticmethod
    def standard_response_content(
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
