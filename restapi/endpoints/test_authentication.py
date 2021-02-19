from restapi import decorators
from restapi.config import TESTING
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import Role

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
        def get(self) -> Response:
            user = self.get_user()

            resp = {}
            resp["token"] = self.get_token()
            resp["user"] = user.email
            return self.response(resp)

    class TestOptionalAuthentication(EndpointResource):
        @decorators.auth.optional()
        @decorators.endpoint(
            path="/tests/optionalauthentication",
            summary="Only echos received token and corresponding user, if any",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(self) -> Response:

            resp = {}
            resp["token"] = self.get_token()
            if user := self.get_user():
                resp["user"] = user.email
            else:
                resp["user"] = None

            return self.response(resp)

    class TestQueryParameterAuthentication(EndpointResource):
        @decorators.auth.require(allow_access_token_parameter=True)
        @decorators.endpoint(
            path="/tests/queryauthentication",
            summary="Only echos received token and corresponding user",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(self) -> Response:
            user = self.get_user()

            resp = {}
            resp["token"] = self.get_token()
            resp["user"] = user.email
            return self.response(resp)

    class TestOptionalQueryParameterAuthentication(EndpointResource):
        @decorators.auth.optional(allow_access_token_parameter=True)
        @decorators.endpoint(
            path="/tests/optionalqueryauthentication",
            summary="Only echos received token and corresponding user, if any",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(self) -> Response:
            resp = {}
            resp["token"] = self.get_token()
            if user := self.get_user():
                resp["user"] = user.email
            else:
                resp["user"] = None

            return self.response(resp)

    class TestAuthenticationWithMultipleRoles(EndpointResource):
        @decorators.auth.require_any(Role.ADMIN, Role.USER)
        @decorators.endpoint(
            path="/tests/manyrolesauthentication",
            summary="Only echos received token and corresponding user",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(self) -> Response:

            resp = {}
            resp["token"] = self.get_token()
            user = self.get_user()
            resp["user"] = user.email

            return self.response(resp)

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
        def get(self) -> Response:  # pragma: no cover
            resp = {}
            resp["token"] = self.get_token()
            if user := self.get_user():
                resp["user"] = user.email
            else:
                resp["user"] = None

            return self.response(resp)
