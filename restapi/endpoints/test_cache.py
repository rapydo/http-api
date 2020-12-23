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
        @decorators.cache(timeout=4)
        def patch(self):

            time.sleep(2)
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

            time.sleep(2)
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

    class TestAuthCache(EndpointResource):

        labels = ["tests"]

        # Increased at each request... except cached responses of course
        counter = 0

        @decorators.auth.require()
        @decorators.endpoint(
            path="/tests/authcache",
            summary="Execute tests of cached responses from authenticated endpoints",
            description="Only enabled in testing mode",
            responses={
                200: "Content sent",
            },
        )
        @decorators.cache(timeout=200)
        def get(self):

            TestAuthCache.counter += 1
            return self.response((self.get_user().uuid, TestAuthCache.counter))

    class TestSemiAuthCache(EndpointResource):

        labels = ["tests"]

        # Increased at each request... except cached responses of course
        counter = 0

        @decorators.auth.optional()
        @decorators.endpoint(
            path="/tests/semiauthcache",
            summary="Execute tests of cached responses from optionally auth. endpoints",
            description="Only enabled in testing mode",
            responses={
                200: "Content sent",
            },
        )
        @decorators.cache(timeout=200)
        def get(self):

            user = self.get_user()

            if user:
                uuid = user.uuid
            else:
                uuid = "N/A"

            TestSemiAuthCache.counter += 1
            return self.response((uuid, TestSemiAuthCache.counter))
