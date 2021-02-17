from typing import Any, Dict, List, Optional, Tuple, Union

from flask import Response as FlaskResponse
from flask_apispec import MethodResource
from flask_restful import Resource

from restapi.config import API_URL
from restapi.connectors import Connector
from restapi.rest.bearer import HTTPTokenAuth
from restapi.rest.response import ResponseMaker
from restapi.services.authentication import BaseAuthentication, Role
from restapi.services.cache import Cache
from restapi.utilities.logs import Events, log, save_event_log

CURRENTPAGE_KEY = "currentpage"
DEFAULT_CURRENTPAGE = 1
PERPAGE_KEY = "perpage"
DEFAULT_PERPAGE = 10

Response = Union[FlaskResponse, Tuple[Any, int, Dict[str, str]]]


class EndpointResource(MethodResource, Resource):

    baseuri = API_URL
    depends_on: List[str] = []
    labels = ["undefined"]
    private = False
    events = Events

    def __init__(self):
        super().__init__()

        self.__auth = None

    # Used to set keys with Flask-Caching memoize
    def __repr__(self):
        return self.__class__.__module__

    @property
    def auth(self):
        if not self.__auth:
            self.__auth = Connector.get_authentication_instance()

        return self.__auth

    def get_token(self):
        if not hasattr(self, "unpacked_token"):
            return None
        return self.unpacked_token[1]

    def get_user(self):
        if not hasattr(self, "unpacked_token"):
            return None
        return self.unpacked_token[3]

    def verify_admin(self):
        """ Check if current user has Administration role """
        return self.auth.verify_roles(self.get_user(), [Role.ADMIN], warnings=False)

    def verify_staff(self):
        """ Check if current user has Staff role """
        return self.auth.verify_roles(self.get_user(), [Role.STAFF], warnings=False)

    def verify_coordinator(self):
        return self.auth.verify_roles(
            self.get_user(), [Role.COORDINATOR], warnings=False
        )

    @staticmethod
    def response(
        content: Any = None,
        code: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
        head_method: bool = False,
        allow_html: bool = False,
    ) -> Response:

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
        # by the adding `allow_html=True` flag
        if allow_html:
            if "text/html" in ResponseMaker.get_accepted_formats():
                content, headers = ResponseMaker.get_html(content, code, headers)
                return FlaskResponse(
                    content, mimetype="text/html", status=code, headers=headers
                )

        return (content, code, headers)

    def empty_response(self) -> Response:
        """ Empty response as defined by the protocol """
        return self.response("", code=204)

    # This function has to be coupled with a marshal_with(TotalSchema, code=206)
    def pagination_total(self, total: int) -> Response:
        return self.response({"total": total}, code=206)

    # Deprecated since 1.0
    def get_user_if_logged(
        self, allow_access_token_parameter=False
    ):  # pragma: no cover
        """
        Helper to be used inside an endpoint that doesn't explicitly
        ask for authentication, but might want to do some extra behaviour
        when a valid token is presented
        """

        log.warning(
            "Deprecated use of self.get_user_if_logged, "
            "decorate the endpoint with @decorators.auth.optional() instead"
        )
        auth_type, token = HTTPTokenAuth.get_authorization_token(
            allow_access_token_parameter=allow_access_token_parameter
        )

        if auth_type is None:
            return None

        unpacked_token = self.auth.verify_token(token)
        if not unpacked_token[0]:
            return None

        return unpacked_token[3]

    def clear_endpoint_cache(self):
        Cache.invalidate(self.get)

    # Mostly copied in authentication.py
    def log_event(
        self,
        event: Events,
        target: Optional[Any] = None,
        payload: Optional[Dict[str, Any]] = None,
        user: Optional[Any] = None,
    ) -> None:

        if not user:
            user = self.get_user()

        save_event_log(
            event=event,
            target=target,
            payload=payload,
            user=user,
            ip=BaseAuthentication.get_remote_ip(),
        )
