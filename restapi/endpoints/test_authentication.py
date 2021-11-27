from typing import Any, Dict, Optional

from restapi import decorators
from restapi.config import TESTING
from restapi.exceptions import Unauthorized
from restapi.models import fields
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import Role, User

if TESTING:

    class TestAuthenticationNotRequired(EndpointResource):
        @decorators.endpoint(
            path="/tests/noauth",
            summary="Only resp a fixed response, no authenticataion is required",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(self) -> Response:

            return self.response("OK")

    class TestAuthentication(EndpointResource):
        @decorators.auth.require()
        @decorators.endpoint(
            path="/tests/authentication",
            summary="Only echos received token and corresponding user",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(self, user: User) -> Response:

            return self.response({"email": user.email})

    class TestOptionalAuthentication(EndpointResource):
        @decorators.auth.optional()
        @decorators.endpoint(
            path="/tests/optionalauthentication",
            summary="Only echos received token and corresponding user, if any",
            description="Only enabled in testing mode",
            responses={
                200: "Tests executed with auth",
                204: "Tests executed without auth",
            },
        )
        def get(self, user: Optional[User]) -> Response:

            if user:
                return self.response({"email": user.email})
            return self.empty_response()

    class TestQueryParameterAuthentication(EndpointResource):
        @decorators.auth.require(allow_access_token_parameter=True)
        @decorators.endpoint(
            path="/tests/queryauthentication",
            summary="Only echos received token and corresponding user",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(self, user: User) -> Response:

            return self.response({"email": user.email})

    class TestOptionalQueryParameterAuthentication(EndpointResource):
        @decorators.auth.optional(allow_access_token_parameter=True)
        @decorators.endpoint(
            path="/tests/optionalqueryauthentication",
            summary="Only echos received token and corresponding user, if any",
            description="Only enabled in testing mode",
            responses={
                200: "Tests executed with auth",
                204: "Tests executed without auth",
            },
        )
        def get(self, user: Optional[User]) -> Response:

            if user:
                return self.response({"email": user.email})
            return self.empty_response()

    class TestAuthenticationWithMultipleRoles(EndpointResource):
        @decorators.auth.require_any(Role.ADMIN, Role.USER)
        @decorators.endpoint(
            path="/tests/manyrolesauthentication",
            summary="Only echos received token and corresponding user",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(self, user: User) -> Response:

            return self.response({"email": user.email})

    # Note: this endpoint requires a role that does not exist!
    class TestAuthenticationWithMissingRole(EndpointResource):
        @decorators.auth.require_any("UnknownRole")
        @decorators.endpoint(
            path="/tests/unknownroleauthentication",
            summary="Only echos received token and corresponding user, if any",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        # no cover because this endpoint will be never called
        # because it requires an Unknown Role to be accessed
        def get(self, user: User) -> Response:  # pragma: no cover

            return self.response({"email": user.email})

    def verify_uuid_value(endpoint: EndpointResource, uuid: str) -> Dict[str, Any]:

        user = endpoint.auth.get_user(user_id=uuid)
        if not user or not endpoint.auth.is_admin(user):
            raise Unauthorized("You are not authorized")

        # Returned values if any will be injected into the endpoint as fn parameters
        return {"target_user": user}
        # Otherwise can simply return None to inject nothing
        # return None

    # Note: this endpoint has a preload callback to verify the uuid and inject the user
    class TestPreloadCallback(EndpointResource):
        @decorators.auth.require()
        @decorators.preload(callback=verify_uuid_value)
        @decorators.use_kwargs({"test": fields.Bool(required=True)}, location="query")
        @decorators.endpoint(
            path="/tests/preloadcallback/<uuid>",
            summary="Only authorized if uuid corresponds to an admin user",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        # Note: target_user is injected by the preload decorator
        def get(self, uuid: str, test: bool, user: User, target_user: User) -> Response:
            return self.response({"email": target_user.email})
