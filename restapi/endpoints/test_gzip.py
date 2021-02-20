from restapi import decorators
from restapi.config import TESTING
from restapi.exceptions import RestApiException
from restapi.rest.definition import EndpointResource, Response

if TESTING:

    class TestGzipEncoding(EndpointResource):

        labels = ["tests"]

        @decorators.endpoint(
            path="/tests/gzip/<size>",
            summary="Execute tests gzip encoding",
            description="Only enabled in testing mode",
            responses={
                200: "Content sent",
                416: "Invalid size",
            },
        )
        def get(self, size: str) -> Response:

            # No type check... but it is only used from a very specific test...
            # So... who cares?? :-)
            if int(size) <= 0:
                raise RestApiException("Invalid size", status_code=416)

            # Just to prevent super giant responses
            return self.response("a" * min(int(size), 1_000_000))
