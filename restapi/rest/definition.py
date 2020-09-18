"""
The most basic (and standard) Rest Resource
we could provide back then
"""

from flask import Response
from flask_apispec import MethodResource
from flask_restful import Resource

from restapi.confs import API_URL
from restapi.rest.bearer import HTTPTokenAuth
from restapi.rest.response import ResponseMaker
from restapi.services.authentication import Role
from restapi.services.detect import AUTH_NAME, detector
from restapi.utilities.logs import log

###################
# Paging costants
CURRENTPAGE_KEY = "currentpage"
DEFAULT_CURRENTPAGE = 1
PERPAGE_KEY = "perpage"
DEFAULT_PERPAGE = 10


###################
# Extending the concept of rest generic resource
class EndpointResource(MethodResource, Resource):

    ALLOW_HTML_RESPONSE = False
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

    @staticmethod
    def load_authentication():
        # Authentication instance is always needed at each request
        auth = detector.get_service_instance(AUTH_NAME)
        auth.db = detector.get_service_instance(detector.authentication_service)

        return auth

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

    def response(self, content=None, code=None, headers=None, head_method=False):

        if headers is None:
            headers = {}

        if code is None:
            code = 200

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
        # If you accept the risk or you do not use marshalling unlock html responses
        # by adding `ALLOW_HTML_RESPONSE = True` to the endpoint class
        if self.ALLOW_HTML_RESPONSE:
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

    # This function has to be coupled with a marshal_with(TotalSchema, code=206)
    def pagination_total(self, total):
        return self.response({"total": total}, code=206)

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
