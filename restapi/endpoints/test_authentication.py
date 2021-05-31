from restapi import decorators
from restapi.config import TESTING
from restapi.customizer import FlaskRequest
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
        def get(self) -> Response:
            user = self.get_user()
            email = user.email if user else "N/A"
            resp = {
                "token": self.get_token(),
                "user": email,
            }
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

            email = user.email if user else "N/A"
            resp = {
                "token": self.get_token(),
                "user": email,
            }
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

            user = self.get_user()
            email = user.email if user else "N/A"

            resp = {
                "token": self.get_token(),
                "user": email,
            }

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

    def verify_uuid_value(request: FlaskRequest, user: User) -> None:
        # request.method == GET
        # request.path == /tests/authcallback/12345...67890
        # request.headers == { ... }
        # request.url_rule == /tests/authcallback/<uuid>
        # request.url == http(s)://.../tests/authcallback/12345...67890
        # request.view_args == {'uuid': '1234567890'}

        if request.view_args.get("uuid") != user.uuid:
            raise Unauthorized("You are not authorized")

    # Note: this endpoint has an authentication callback
    class TestAuthenticationCallback(EndpointResource):
        @decorators.auth.require(callback=verify_uuid_value)
        @decorators.use_kwargs({"test": fields.Bool(required=True)}, location="query")
        @decorators.endpoint(
            path="/tests/authcallback/<uuid>",
            summary="Only authorized if uuid matches the user uuid",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(self, uuid: str, test: bool) -> Response:
            return self.response(True)
