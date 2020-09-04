from restapi import decorators
from restapi.confs import TESTING
from restapi.rest.definition import EndpointResource

if TESTING:

    class TestAuthentication(EndpointResource):
        @decorators.endpoint(
            path="/tests/authentication",
            summary="Only echos received token and corresponding user",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(self):
            """
            The rational behind this test is that get_user_if_logged does not updated
            the unpacked_token reference of the endpoint, so both self.get_token and
            self.get_user will always be None, even if a token is provided.
            """
            if not (user := self.get_user_if_logged()):
                return {"token": self.get_token(), "user": self.get_user()}

            return self.response(
                {
                    "token": self.get_token(),
                    "user": self.get_user(),
                    "unpacked_user": user.email,
                }
            )
