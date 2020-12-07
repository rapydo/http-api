import time

from restapi import decorators
from restapi.config import TESTING
from restapi.rest.definition import EndpointResource

if TESTING:

    class TestCache(EndpointResource):

        labels = ["tests"]

        @decorators.endpoint(
            path="/tests/cache",
            summary="Execute tests on cached responses",
            description="Only enabled in testing mode",
            responses={
                200: "Content sent",
            },
        )
        @decorators.cache(timeout=2)
        def patch(self):

            time.sleep(1)
            return self.response("OK")

        @decorators.endpoint(
            path="/tests/cache",
            summary="Execute tests on cached responses",
            description="Only enabled in testing mode",
            responses={
                200: "Content sent",
            },
        )
        @decorators.cache(timeout=200)
        def get(self):

            time.sleep(1)
            return self.response("OK")

        @decorators.endpoint(
            path="/tests/cache",
            summary="Clear endpoint cache",
            description="Only enabled in testing mode",
            responses={
                204: "Endpoint cache cleared",
            },
        )
        def delete(self):

            self.clear_endpoint_cache()
            return self.empty_response()
