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
                get_custom_or_default_response_method
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
from flask import Response, jsonify
from werkzeug import exceptions as wsgi_exceptions
from werkzeug.wrappers import Response as WerkzeugResponse
from rapydo.decorators import get_response, set_response
from rapydo.utils import htmlcodes as hcodes
from rapydo.attributes import ResponseElements
from rapydo.utils.logs import get_logger

log = get_logger(__name__)


########################
# Flask custom response
########################

class InternalResponse(Response):
    """
    Note: basically the response cannot be modified anymore at this point
    """

    # def __init__(self, response, **kwargs):
    def __init__(self, *args, **kwargs):

        if 'mimetype' not in kwargs and 'contenttype' not in kwargs:
            # our default
            kwargs['mimetype'] = 'application/json'

            # if response.startswith('<?xml'):
            #     kwargs['mimetype'] = 'application/xml'

        self._latest_response = \
            super().__init__(*args, **kwargs)
        #    super().__init__(response, **kwargs)  # THIS WAS A HUGE BUG :/

    @classmethod
    def force_type(cls, rv, environ=None):
        """ Copy/paste from Miguel's tutorial """

        if isinstance(rv, dict):
            try:
                rv = jsonify(rv)
            except BaseException:
                print("DEBUG", rv)
                log.error("Cannot jsonify rv")

        return super(InternalResponse, cls).force_type(rv, environ)


########################
# Flask response internal builder
########################
class ResponseMaker(object):

    _content_key = "Response"
    _content_meta = "Meta"

    def __init__(self, response):
        """
        We would receive most of the time a ResponseElements class
        that we have to parse.

        The parser will find out if inside there is either:
        - an original Flask/Werkzeug Response
        - A Flask Exception (e.g. NotFound)
        """
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
                # TOFIX: should add more checks to 2nd and 3rd element?
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
        except:
            pass

        return False

    @staticmethod
    def default_response(content):
        """
        Our default for response content
        """
## Follow jsonapi.org?
        return content

    def already_converted(self):
        return self.is_internal_response(self._response)

    def generate_response(self):
        """
        Generating from our user/custom/internal response
        the data necessary for a Flask response (make_response() method):
        a tuple (content, status, headers)
        """

        if self.already_converted():
            return self._response

        # 1. Use response elements
        r = self._response
        # log.pp(r)

        # 2. Apply DEFAULT or CUSTOM manipulation
        # (strictly to the sole content)
        method = get_response()
        log.very_verbose("Response method: %s" % method.__name__)
        r['defined_content'] = method(r['defined_content'])

        # 3. Recover correct status and errors
        r['code'], r['errors'] = self.get_errors_and_status(
            r['defined_content'], r['code'], r['errors'])

        # 4. Encapsulate response and other things in a standard json obj:
        # {Response: DEFINED_CONTENT, Meta: HEADERS_AND_STATUS}
        final_content = self.standard_response_content(
            r['defined_content'], r['elements'],
            r['code'], r['errors'], r['meta'])

        if r['extra'] is not None:
            log.warning("NOT IMPLEMENTED YET: " +
                           "what to do with extra field?\n%s" % r['extra'])

        # 5. Return what is necessary to build a standard flask response
        # from all that was gathered so far
        response = (final_content, r['code'], r['headers'])

        return response

    def get_errors_and_status(
            self, defined_content=None, code=None, errors=None):
        """
        Handle OUR standard response following criteria described in
        https://github.com/EUDAT-B2STAGE/http-api-base/issues/7
        """

        if code is None:
            # flask exception?
            if self.is_internal_exception(defined_content):
                exception = defined_content
                code = exception.code
                errors = {exception.name: exception.description}
            else:
                code = hcodes.HTTP_OK_BASIC

        #########################
        # errors and conseguent status code range

        # Convert errors in a list, always
        if errors is not None:
            if not isinstance(errors, list):
                # if not isinstance(errors, dict):
                    # errors = {'Generic error': errors}
                errors = [errors]

        # Decide code range
        if errors is None and defined_content is None:
            log.warning("RESPONSE: Warning, no data and no errors")
            code = hcodes.HTTP_OK_NORESPONSE
        elif errors is None:
            if code not in range(0, hcodes.HTTP_MULTIPLE_CHOICES):
                code = hcodes.HTTP_OK_BASIC
        elif defined_content is None:
            if code < hcodes.HTTP_BAD_REQUEST:
                # code = hcodes.HTTP_BAD_REQUEST
                code = hcodes.HTTP_SERVER_ERROR
        else:
            # warnings:
            # range 300 < 400
            pass

        return code, errors

    @staticmethod
    def standard_response_content(defined_content=None, elements=None,
                                  code=None, errors=None, custom_metas=None):
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
            log.critical("Could not build response!\n%s" % e)
            # Revert to defaults
            defined_content = None,
            data_type = str(type(defined_content))
            elements = 0
            # Also set the error
            code = hcodes.HTTP_SERVICE_UNAVAILABLE
            errors = [{'Failed to build response': str(e)}]
            total_errors = len(errors)

        contents = {
            'data': defined_content,
            'errors': errors,
        }

        metas = {
            'data_type': data_type,
            'elements': elements,
            'errors': total_errors,
            'status': code
        }

        if custom_metas is not None:
            # sugar syntax for merging dictionaries
            metas = {**metas, **custom_metas}

        return {
            ResponseMaker._content_key: contents,
            ResponseMaker._content_meta: metas
        }

    @staticmethod
    def flask_response(data, status=hcodes.HTTP_OK_BASIC, headers=None):

        raise DeprecationWarning("Useless mimic of Flask response")
#         """
#         Was inspired by
#         http://blog.miguelgrinberg.com/
#             post/customizing-the-flask-response-class


########################
# Set default response
# as the user may support its own response
set_response(
    # Note: original here means the Flask simple response
    original=False,
    first_call=True,
    custom_method=ResponseMaker.default_response)


########################
# TOFIX: Explode the normal response content?
def get_content_from_response(http_out):

    response = None

    # Read a real flask response
    if isinstance(http_out, WerkzeugResponse):
        try:
            response = json.loads(http_out.get_data().decode())
        except Exception as e:
            log.critical("Failed to load response:\n%s" % e)
            raise ValueError(
                "Trying to recover informations" +
                " from a malformed response:\n%s" % http_out)
    # Or convert an half-way made response
    elif isinstance(http_out, ResponseElements):
        tmp = ResponseMaker(http_out).generate_response()
        response = tmp[0]

    # Check what we have so far
    # Should be {Response: DATA, Meta: RESPONSE_METADATA}
    if not isinstance(response, dict) or len(response) != 2:
        raise ValueError(
            "Trying to recover informations" +
            " from a malformed response:\n%s" % response)

    # Split
    content = response[ResponseMaker._content_key]['data']
    err = response[ResponseMaker._content_key]['errors']
    meta = response[ResponseMaker._content_meta]
    code = meta['status']

    return content, err, meta, code
