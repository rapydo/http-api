from restapi import decorators
from restapi.config import TESTING
from restapi.exceptions import RestApiException
from restapi.rest.definition import EndpointResource

if TESTING:

    class TestGzipEncoding(EndpointResource):

        labels = ["tests"]

        @decorators.endpoint(
            path="/tests/gzip/<size>",
            summary="Execute tests gzip encoding",
            description="Only enabled in testing mode",
            responses={
                200: "Content sent executed",
                416: "Invalid size",
            },
        )
        def get(self, size):

            if size <= 0:
                raise RestApiException("Invalid size", status_code=416)

            # Just to prevent super giant responses
            return self.response("a" * min(size, 1_000_000))
