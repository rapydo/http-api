from restapi import decorators
from restapi.config import TESTING
from restapi.rest.definition import EndpointResource

if TESTING:

    class TestShortCache(EndpointResource):
        """
        Used to test cache autocleaning at expiration
        """

        labels = ["tests"]
        counter = 0  # Increased at each request... except cached responses of course

        @decorators.endpoint(
            path="/tests/cache/short",
            summary="Execute tests on cached responses",
            description="Only enabled in testing mode",
            responses={
                200: "Content sent",
            },
        )
        @decorators.cache(timeout=1)
        def get(self):

            TestSemiAuthCache.counter += 1
            return self.response(TestSemiAuthCache.counter)

    class TestLongCache(EndpointResource):
        """
        Used to test cache cleaning with manual methods
        """

        labels = ["tests"]
        counter = 0  # Increased at each request... except cached responses of course

        @decorators.endpoint(
            path="/tests/cache/long",
            summary="Execute tests on cached responses",
            description="Only enabled in testing mode",
            responses={
                200: "Content sent",
            },
        )
        @decorators.cache(timeout=200)
        def get(self):

            TestSemiAuthCache.counter2 += 1
            return self.response(TestSemiAuthCache.counter2)

        @decorators.endpoint(
            path="/tests/cache/long",
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
        """
        Used to test cache of authenticated endpoints
        (cache keys are token dependent)
        """

        labels = ["tests"]

        counter = 0  # Increased at each request... except cached responses of course

        @decorators.auth.require()
        @decorators.endpoint(
            path="/tests/cache/auth",
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
        """
        Used to test cache of optionally authenticated endpoints
        (cache keys are token dependent, if tokens are provided and valid)
        """

        labels = ["tests"]

        counter = 0  # Increased at each request... except cached responses of course

        @decorators.auth.optional()
        @decorators.endpoint(
            path="/tests/cache/optionalauth",
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
