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

            return self.response(
                {
                    "token": self.get_token(),
                    "user": user,
                    "unpacked_user": user.email,
                }
            )

    class TestOptionalAuthentication(EndpointResource):
        @decorators.auth.optional()
        @decorators.endpoint(
            path="/tests/optionalauthentication",
            summary="Only echos received token and corresponding user, if any",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(self):
            if not (user := self.get_user_if_logged()):
                return {"token": self.get_token(), "user": user}

            return self.response(
                {
                    "token": self.get_token(),
                    "user": user,
                    "unpacked_user": user.email,
                }
            )
