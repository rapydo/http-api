"""
The most basic (and standard) Rest Resource
we could provide back then
"""

from flask import Response, make_response
from flask_apispec import MethodResource
from flask_restful import Resource, reqparse, request
from jsonschema.exceptions import ValidationError

from restapi.confs import API_URL
from restapi.exceptions import RestApiException
from restapi.rest.bearer import HTTPTokenAuth
from restapi.rest.response import ResponseMaker
from restapi.services.authentication import ADMIN_ROLE, LOCAL_ADMIN_ROLE
from restapi.services.detect import AUTH_NAME, detector
from restapi.swagger import input_validation
from restapi.utilities.globals import mem
from restapi.utilities.logs import log, obfuscate_dict

###################
# Paging costants
CURRENTPAGE_KEY = "currentpage"
DEFAULT_CURRENTPAGE = 1
PERPAGE_KEY = "perpage"
DEFAULT_PERPAGE = 10


###################
# Extending the concept of rest generic resource
class EndpointResource(Resource):

    baseuri = API_URL
    depends_on = []
    labels = ["undefined"]
    """
    Implements a generic Resource for our Restful APIs model
    """

    def __init__(self):
        super().__init__()

        self.auth = self.load_authentication()
        self.get_service_instance = detector.get_service_instance
        try:
            # to be deprecated
            self.init_parameters()
        except RuntimeError:
            # Once converted everything to FastApi remove this init_parameters
            # Find other warning like this by searching:
            # **FASTAPI**
            # log.warning(
            #     "self.init_parameters should be removed since handle by webargs")
            pass

    @staticmethod
    def load_authentication():
        # Authentication instance is always needed at each request
        auth = detector.get_service_instance(AUTH_NAME)
        auth.db = detector.get_service_instance(detector.authentication_service)

        return auth

    # @staticmethod
    # def get_service_instance(service_name, **kwargs):
    #     return detector.get_service_instance(service_name, **kwargs)

    # to be deprecated (in conjuction with get_input)
    def init_parameters(self):
        # Make sure you can parse arguments at every call
        self._args = {}
        self._json_args = {}

        # Query parameters
        self._parser = reqparse.RequestParser()

        classname = self.__class__.__name__
        uri = str(request.url_rule)
        method = request.method.lower()

        # FIXME: this works only for 'query' parameters
        # recover from the global mem parameters query parameters
        current_params = (
            mem.customizer._query_params.get(classname, {}).get(uri, {}).get(method, {})
        )

        # Deprecated since 0.7.4
        if len(current_params) > 0:  # pragma: no cover

            act = "store"  # store is normal, append is a list
            loc = ["headers", "values"]  # multiple locations
            trim = True

            for param, data in current_params.items():

                # FIXME: Add a method to convert types swagger <-> flask
                tmptype = data.get("type", "string")
                if tmptype == "boolean":
                    mytype = bool
                if tmptype == "number":
                    mytype = int
                else:
                    mytype = str

                # TO CHECK: I am creating an option to handle arrays
                if tmptype == "select":
                    act = "append"

                self._parser.add_argument(
                    param,
                    type=mytype,
                    default=data.get("default", None),
                    required=data.get("required", False),
                    trim=trim,
                    action=act,
                    location=loc,
                )
                log.verbose("Accept param '{}' type {}", param, mytype)

    # to be deprecated (and after: init_parameters)
    def get_input(self):  # pragma: no cover
        """
        Recover parameters from current requests.

        Note that we talk about JSON only when having a PUT method,
        while there is URL encoding for GET, DELETE
        and Headers encoding with POST.

        Non-JSON Parameters are already parsed at this point,
        while JSON parameters may be already saved from another previous call
        """

        # Parameters may be necessary at any method: Parse them all.
        self._args = self._parser.parse_args()

        # if is an upload in streaming, I must not consume
        # request.data or request.json, otherwise it get lost
        if len(self._json_args) < 1 and request.mimetype != "application/octet-stream":
            try:
                self._json_args = request.get_json(force=True)
            except Exception as e:
                log.verbose("Error retrieving input parameters, {}", e)

            # json payload and formData cannot co-exist
            if len(self._json_args) < 1:
                self._json_args = request.form

            # NOTE: if JSON all parameters are just string at the moment...
            for key, value in self._json_args.items():

                if value is None:
                    continue
                # TODO: remove and check
                # how to fix the `request.form` emptiness

                if key in self._args and self._args[key] is not None:
                    key += "_json"
                self._args[key] = value

        if len(self._args) > 0:
            log.verbose("Parameters {}", obfuscate_dict(self._args))
        return self._args

    # Deprecated since 0.7.4
    def get_paging(self, force_read_parameters=False):  # pragma: no cover

        log.warning(
            "Deprecated use of get_paging, use @decorators.get_pagination instead"
        )

        if force_read_parameters:
            self.get_input()
        # NOTE: you have to call self.get_input before to use this method
        limit = self._args.get(PERPAGE_KEY, DEFAULT_PERPAGE)
        current_page = self._args.get(CURRENTPAGE_KEY, DEFAULT_CURRENTPAGE)

        if limit is None:
            limit = DEFAULT_PERPAGE
        if current_page is None:
            current_page = DEFAULT_CURRENTPAGE

        try:
            limit = int(limit)
        except ValueError:
            log.warning("{} is expected to be an int, not {}", PERPAGE_KEY, limit)
            limit = DEFAULT_PERPAGE

        try:
            current_page = int(current_page)
        except ValueError:
            log.warning(
                "{} is expected to be an int, not {}", CURRENTPAGE_KEY, current_page
            )
            current_page = DEFAULT_CURRENTPAGE

        return (current_page, limit)

    def get_token(self):
        if not hasattr(self, "unpacked_token"):
            return None
        return self.unpacked_token[1]

    def get_user(self):
        if not hasattr(self, "unpacked_token"):
            return None
        return self.unpacked_token[3]

    def verify_admin(self):
        """ Check if current user has administration role """
        return self.auth.verify_roles(self.get_user(), [ADMIN_ROLE], warnings=False)

    def verify_local_admin(self):
        return self.auth.verify_roles(
            self.get_user(), [LOCAL_ADMIN_ROLE], warnings=False
        )

    # Deprecated since 0.7.4
    def get_current_user(self):  # pragma: no cover
        """
        Return the associated User OBJECT if:
        - the endpoint requires authentication
        - a valid token was provided
        in the current endpoint call.

        Note: this method works because of actions inside
        authentication/__init__.py@verify_token method
        """

        log.warning(
            "self.get_current_user() is deprecated, replace with self.get_user()"
        )

        return self.get_user()

    def response(
        self, content=None, errors=None, code=None, headers=None, head_method=False
    ):

        if headers is None:
            headers = {}

        if code is None:
            code = 200

        # Deprecated since 0.7.4
        if errors is not None:  # pragma: no cover
            log.warning(
                "Deprecated use of errors in response, use raise RestApiException or "
                "response(content, code>=400)"
            )
            content = errors
            if code < 400:
                log.warning("Forcing 500 SERVER ERROR because errors are returned")
                code = 500

        if content is None and code != 204 and not head_method:
            log.warning("RESPONSE: Warning, no data and no errors")
            code = 204

        # Request from a ApiSpec endpoint, skipping all flask-related following steps
        if isinstance(self, MethodResource):

            # Do not bypass FlaskApiSpec response management otherwise marshalling
            # will be not applied. Consider the following scenario:
            # @marshal(OnlyOneFieldSchema)
            # def get():
            #    return self.response(all_information)
            # If you bypass the marshalling you will expose the all_information by
            # retrieving it from a browser (or by forcing the Accept header)
            # i.e. html responses will only work on non-MethodResource endpoints
            # If you accept the risk or you do not use marshalling add to endpoint class
            # ALLOW_HTML_RESPONSE = True
            if hasattr(self, "ALLOW_HTML_RESPONSE") and self.ALLOW_HTML_RESPONSE:
                accepted_formats = ResponseMaker.get_accepted_formats()
                if "text/html" in accepted_formats:
                    content, headers = ResponseMaker.get_html(content, code, headers)
                    return Response(
                        content, mimetype="text/html", status=code, headers=headers
                    )

            return (content, code, headers)

        # to be deprecated

        # Convert the response in a Flask response, i.e. make_response(tuple)
        r = ResponseMaker.generate_response(
            content=content, code=code, headers=headers, head_method=head_method
        )

        response = make_response(r)

        # Avoid duplicated Content-type
        content_type = None  # pragma: no cover
        for idx, val in enumerate(response.headers):  # pragma: no cover
            if val[0] != "Content-Type":
                continue
            if content_type is None:
                content_type = idx
                continue
            log.warning(
                "Duplicated Content-Type, removing {} and keeping {}",
                response.headers[content_type][1],
                val[1],
            )
            response.headers.pop(content_type)
            break

        return response

    def empty_response(self):
        """ Empty response as defined by the protocol """
        return self.response("", code=204)

    def get_user_if_logged(self, allow_access_token_parameter=False):
        """
        Helper to be used inside an endpoint that doesn't explicitly
        ask for authentication, but might want to do some extra behaviour
        when a valid token is presented
        """

        auth_type, token = HTTPTokenAuth.get_authorization_token(
            allow_access_token_parameter=allow_access_token_parameter
        )

        if auth_type is None:
            return None

        unpacked_token = self.auth.verify_token(token)
        if not unpacked_token[0]:
            return None

        return unpacked_token[3]

    # to be deprecated
    # Only used in mistral
    # this is a simple wrapper of restapi.swagger.input_validation
    @staticmethod
    def validate_input(json_parameters, definitionName):  # pragma: no cover

        try:
            return input_validation(json_parameters, definitionName)
        except ValidationError as e:
            raise RestApiException(e.message, status_code=400)
