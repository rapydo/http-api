# -*- coding: utf-8 -*-

"""

Handle the response 'algorithm'
(also see EUDAT-B2STAGE/http-api-base#7)

force_response (base.py)    or              simple return
[ResponseElements()]        [obj / (content,status) / (content,status,headers)]
        |                                           |
        ---------------------------------------------
                            |
            Overriden Flask.make_response (server.py) - called internally
             |- x = ResponseMaker(rv) instance __init__
             |- x.generate_response()
                    |
                get_errors
                set_standard to output ({Response: OUT, Meta: ...})
                return tuple (data, status, headers)
                                        |
            Flask handle over to overridden Werkzeug Response
             |- force_type: jsonify
                    |
                   THE END

"""

import attr
import json
from flask import Response, jsonify, render_template
from werkzeug import exceptions as wsgi_exceptions
from werkzeug.wrappers import Response as WerkzeugResponse
from restapi.attributes import ResponseElements
from restapi.utilities.htmlcodes import hcodes
from restapi.utilities.logs import log

MIMETYPE_JSON = 'application/json'
MIMETYPE_XML = 'application/xml'
MIMETYPE_HTML = 'text/html'
MIMETYPE_CSV = 'text/csv'


########################
# Utility
########################
def request_from_browser():
    """
    Was a browser asking current request?

    # NOTE: this utility is used by some projects to check the browser
    # e.g. for a landing page
    """

    from flask import request

    # agent = request.headers.get('User-Agent')
    return request.user_agent.browser is not None


def get_accepted_formats():
    from flask import request

    for val in request.headers:
        if val[0] == "Accept":
            return [x.strip() for x in val[1].split(',')]
    return ['*/*']


def add_to_dict(mydict, content, key='content'):
    if content is None:
        content = {}
    elif not isinstance(content, dict):
        content = {key: content}
    mydict.update(content)
    return mydict


def respond_to_browser(r):
    log.debug("Request from a browser: reply with HTML.")

    array = False
    content = r.get('defined_content')
    if isinstance(content, str):
        html_content = content
    else:
        html_content = getattr(content, 'HTML', None)

    if html_content is None:
        data = {}
        data = add_to_dict(data, content, key='data')
        data = add_to_dict(data, r.get('errors'), key='errors')
        array = True
    else:
        data = html_content

    html_data = {'body_content': data, 'array': array}
    html_page = render_template('index.html', **html_data)
    return Response(
        html_page,
        mimetype=MIMETYPE_HTML,
        status=r.get('code'),
        headers=r.get('headers')
    )


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
            # if response.startswith('<?xml'):
            #     kwargs['mimetype'] = MIMETYPE_XML

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


########################
# Flask response internal builder
########################
class ResponseMaker:

    def __init__(self, response):
        """
        Executed before building the final response.

        We would receive most of the time a ResponseElements class
        that we have to parse.
        So we call our parse to find out things about the current context.
        The parser will find out if inside there is either:
        - an original Flask/Werkzeug Response
        - A Flask Exception (e.g. NotFound)
        """

        # Build a flask response
        self._response = self.parse_elements(response)

    def parse_elements(self, response):

        # PRE-CHECK: is it a flask response?
        if self.is_internal_response(response):
            return response

        # Initialize the array of data
        elements = {}

        if isinstance(response, ResponseElements):
            elements = attr.asdict(response)
        else:
            for element in attr.fields(ResponseElements):
                elements[element.name] = element.default
            elements['defined_content'] = None

            # A Flask tuple. Possibilities:
            # obj / (content,status) / (content,status,headers)
            if isinstance(response, tuple):

                # try to unjsonify response, if Flask did it already
                main = None
                try:
                    main = json.loads(response[0])
                except BaseException:
                    main = response[0]

                if len(response) > 0:
                    elements['defined_content'] = main
                # FIXME: should add more checks to 2nd and 3rd element?
                # Should also make sure that 2nd is integer
                # and headers is a dictionary?
                if len(response) > 1:
                    if response[1] > hcodes.HTTP_TRESHOLD:
                        elements['defined_content'] = None
                        elements['errors'] = main
                    elements['code'] = response[1]
                if len(response) > 2:
                    elements['headers'] = response[2]
            # Anything that remains is just a content
            else:
                elements['defined_content'] = response

        # POST-CHECK: is it a flask response?
        if self.is_internal_response(elements['defined_content']):
            return elements['defined_content']

        return elements

    def get_original_response(self):
        return self._response

    @staticmethod
    def is_internal_response(response):
        """ damn you hierarchy! """
        # print("DEBUG", response, isinstance(response, WerkzeugResponse))

        # return isinstance(response, InternalResponse)
        # return isinstance(response, Response)
        return isinstance(response, WerkzeugResponse)

    @staticmethod
    def is_internal_exception(response):
        """
        See if this is an exception inside the list of wsgi exceptions
        """
        try:
            response_name = str(response.__class__.__name__)
            if response_name in dir(wsgi_exceptions):
                return True
        except BaseException:
            pass

        return False

    def already_converted(self):
        return self.is_internal_response(self._response)

    def generate_response(self):
        """
        Generating from our user/custom/internal response
        the data necessary for a Flask response (make_response() method):
        a tuple (content, status, headers)
        """

        # 1. Use response elements
        r = self._response

        if self.already_converted():
            log.warning("Response already converted")
            return r

        # 2. Fix code range

        if r['code'] is None:
            # flask exception?
            if self.is_internal_exception(r['defined_content']):
                exception = r['defined_content']
                r['code'] = exception.code
                r['errors'] = {exception.name: exception.description}
            else:
                r['code'] = hcodes.HTTP_OK_BASIC

        # Is that really needed?
        if r['errors'] and not isinstance(r['errors'], list):
            r['errors'] = [r['errors']]

        if r['errors'] is None and r['defined_content'] is None:
            if not r['head_method'] or r['code'] is None:
                log.warning("RESPONSE: Warning, no data and no errors")
                r['code'] = hcodes.HTTP_OK_NORESPONSE
        elif r['errors'] is None:
            if r['code'] >= 300:
                log.warning("Forcing 200 OK because no errors are raised")
                r['code'] = hcodes.HTTP_OK_BASIC
        elif r['defined_content'] is None:
            if r['code'] < 400:
                log.warning("Forcing 500 SERVER ERROR because only errors are returned")
                r['code'] = hcodes.HTTP_SERVER_ERROR

        # 3. Encapsulate response and other things in a standard json obj:
        # {Response: DEFINED_CONTENT, Meta: HEADERS_AND_STATUS}
        final_content = self.standard_response_content(
            r['defined_content'], r['elements'], r['code'], r['errors'], r['meta']
        )

        # 4. Return what is necessary to build a standard flask response
        # from all that was gathered so far
        response = (final_content, r['code'], r['headers'])

        accepted_formats = get_accepted_formats()

        if MIMETYPE_HTML in accepted_formats:
            # skip in case of errors, for now
            if r['errors'] is None:
                return respond_to_browser(r)

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
        defined_content=None, elements=None, code=None, errors=None, custom_metas=None
    ):
        """
        Try conversions and compute types and length
        """

        ###################
        # Handle original Flask wsgi_exceptions
        if ResponseMaker.is_internal_exception(defined_content):
            # Up to here the exception should be already parsed
            # for error and code in the previous step, so clean the content
            defined_content = None

        ###################
        # Our normal content
        try:
            data_type = str(type(defined_content))
            if elements is None:
                if defined_content is None:
                    elements = 0
                elif isinstance(defined_content, str):
                    elements = 1
                else:
                    elements = len(defined_content)

            if errors is None:
                total_errors = 0
            else:
                total_errors = len(errors)

            code = int(code)
        except Exception as e:
            log.critical("Could not build response! {}", e)
            # Revert to defaults
            defined_content = None
            errors = ['Failed to build response {}'.format(e)]
            data_type = str(type(defined_content))
            elements = 0
            total_errors = 1
            code = hcodes.HTTP_SERVICE_UNAVAILABLE

        Response = {
            "Response": {
                'data': defined_content,
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


########################
# FIXME: Explode the normal response content?
def get_content_from_response(http_out):

    response = None

    # Read a real flask response
    if isinstance(http_out, WerkzeugResponse):
        try:
            response = json.loads(http_out.get_data().decode())
        except Exception as e:
            log.error("Failed to load response:\n{}", e)
            raise ValueError(
                "Malformed response: {}".format(http_out)
            )
    # Or convert an half-way made response
    elif isinstance(http_out, ResponseElements):
        tmp = ResponseMaker(http_out).generate_response()
        response = tmp[0]

    # Check what we have so far
    # Should be {Response: DATA, Meta: RESPONSE_METADATA}
    if not isinstance(response, dict) or len(response) != 2:
        raise ValueError(
            "Malformed response: {}".format(response)
        )

    Response = response.get("Response")
    Meta = response.get("Meta")

    if Response is None or Meta is None:
        raise ValueError(
            "Malformed response: {}".format(response)
        )

    content = Response.get('data')
    err = Response.get('errors')
    code = Meta.get('status')

    return content, err, Meta, code
