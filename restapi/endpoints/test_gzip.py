from restapi import decorators
from restapi.config import TESTING
from restapi.exceptions import BadRequest, RestApiException
from restapi.rest.definition import EndpointResource, Response
from restapi.utilities.logs import log

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

            size_int = 0
            try:
                size_int = int(size)
            except Exception as e:
                log.error("Invalid int value {} -> {}", size, e)
                raise BadRequest("Invalid numeric value {size}")

            if size_int <= 0:
                raise RestApiException("Invalid size", status_code=416)

            # Just to prevent super giant responses
            return self.response("a" * min(size_int, 1_000_000))
