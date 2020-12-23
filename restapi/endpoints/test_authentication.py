from restapi import decorators
from restapi.config import TESTING
from restapi.rest.definition import EndpointResource

if TESTING:

    class TestAuthentication(EndpointResource):
        @decorators.auth.require()
        @decorators.endpoint(
            path="/tests/authentication",
            summary="Only echos received token and corresponding user",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(self):
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
        def get(self):

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
        def get(self):
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
        def get(self):
            resp = {}
            resp["token"] = self.get_token()
            if user := self.get_user():
                resp["user"] = user.email
            else:
                resp["user"] = None

            return self.response(resp)
