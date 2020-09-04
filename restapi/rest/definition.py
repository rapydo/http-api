"""
The most basic (and standard) Rest Resource
we could provide back then
"""

from flask import Response
from flask_apispec import MethodResource
from flask_restful import Resource, request

from restapi.confs import API_URL
from restapi.rest.bearer import HTTPTokenAuth
from restapi.rest.response import ResponseMaker
from restapi.services.authentication import Role
from restapi.services.detect import AUTH_NAME, detector
from restapi.utilities.logs import log, obfuscate_dict

###################
# Paging costants
CURRENTPAGE_KEY = "currentpage"
DEFAULT_CURRENTPAGE = 1
PERPAGE_KEY = "perpage"
DEFAULT_PERPAGE = 10


###################
# Extending the concept of rest generic resource
class EndpointResource(MethodResource, Resource):

    baseuri = API_URL
    depends_on = []
    labels = ["undefined"]
    private = False
    """
    Implements a generic Resource for our Restful APIs model
    """

    def __init__(self):
        super().__init__()

        self.auth = self.load_authentication()
        self.get_service_instance = detector.get_service_instance
        self._json_args = {}

    @staticmethod
    def load_authentication():
        # Authentication instance is always needed at each request
        auth = detector.get_service_instance(AUTH_NAME)
        auth.db = detector.get_service_instance(detector.authentication_service)

        return auth

    # Deprecated since 0.7.5
    def get_input(self):  # pragma: no cover

        log.warning(
            "Deprecated use of self.get_input(), use webargs-defined parameters instead"
        )
        # if is an upload in streaming, I must not consume
        # request.data or request.json, otherwise it get lost
        if not self._json_args and request.mimetype != "application/octet-stream":
            try:
                self._json_args = request.get_json(force=True)
            except Exception as e:
                log.verbose("Error retrieving input parameters, {}", e)

            # json payload and formData cannot co-exist
            if not self._json_args:
                self._json_args = request.form

        if self._json_args:
            log.verbose("Parameters {}", obfuscate_dict(self._json_args))

        # Convert a Flask object to a normal dict... prevent uncatchable errors like:
        # werkzeug.exceptions.BadRequestKeyError
        # When accessing this object
        parameters = {}
        for k, v in self._json_args.items():
            parameters[k] = v
        return parameters

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
        return self.auth.verify_roles(self.get_user(), [Role.ADMIN], warnings=False)

    def verify_local_admin(self):
        return self.auth.verify_roles(
            self.get_user(), [Role.LOCAL_ADMIN], warnings=False
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

    # Only used in mistral
    # Deprecated since 0.7.6
    @staticmethod
    def validate_input(json_parameters, definitionName):  # pragma: no cover

        log.warning("Deprecated use of validate_input, use webargs instead")

        return True
