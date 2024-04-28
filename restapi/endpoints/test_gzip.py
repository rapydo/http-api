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
            size_int = int(size)

            if size_int <= 0:
                raise RestApiException("Invalid size", status_code=416)

            # Just to prevent super giant responses
            return self.response("a" * min(size_int, 1_000_000))
