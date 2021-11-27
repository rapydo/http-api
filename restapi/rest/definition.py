import warnings
from typing import Any, Dict, List, Optional

from flask import Response as FlaskResponse
from flask import request
from flask_apispec import MethodResource
from flask_restful import Resource

from restapi.connectors import Connector
from restapi.rest.response import ResponseMaker
from restapi.services.authentication import BaseAuthentication, User
from restapi.services.cache import Cache
from restapi.types import Response, ResponseContent
from restapi.utilities.logs import Events, log, save_event_log

CURRENTPAGE_KEY = "currentpage"
DEFAULT_CURRENTPAGE = 1
PERPAGE_KEY = "perpage"
DEFAULT_PERPAGE = 10


# Base type MethodResource becomes "Any" due to an unfollowed import
# Base type Resource becomes "Any" due to an unfollowed import
class EndpointResource(MethodResource, Resource):  # type: ignore

    depends_on: List[str] = []
    labels = ["undefined"]
    private = False
    events = Events

    def __init__(self) -> None:
        super().__init__()

        self.__auth: Optional[BaseAuthentication] = None
        # extracted from the token, if provided and verified
        self.authorized_user: Optional[str] = None

    # Used to set keys with Flask-Caching memoize
    def __repr__(self) -> str:
        return self.__class__.__module__

    @property
    def auth(self) -> BaseAuthentication:
        if not self.__auth:
            self.__auth = Connector.get_authentication_instance()

        return self.__auth

    # Deprecated since 2.1
    def get_user(self) -> Optional[User]:  # pragma: no cover
        warnings.warn(
            "Deprecated use of self.get_user(), user is now injected in the endpoint"
        )
        return self.auth.get_user(user_id=self.authorized_user)

    @staticmethod
    def response(
        content: ResponseContent = None,
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
        """Empty response as defined by the protocol"""
        return self.response("", code=204)

    # This function has to be coupled with a marshal_with(TotalSchema, code=206)
    def pagination_total(self, total: int) -> Response:
        return self.response({"total": total}, code=206)

    def clear_endpoint_cache(self) -> None:
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
            user = self.auth.get_user(user_id=self.authorized_user)

        save_event_log(
            event=event,
            target=target,
            payload=payload,
            user=user,
            ip=BaseAuthentication.get_remote_ip(),
            url=request.path,
        )
