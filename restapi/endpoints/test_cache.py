from typing import Optional

from restapi import decorators
from restapi.config import TESTING
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import User

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
        def get(self) -> Response:

            TestShortCache.counter += 1
            return self.response(TestShortCache.counter)

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
        def get(self) -> Response:

            TestLongCache.counter += 1
            return self.response(TestLongCache.counter)

        @decorators.endpoint(
            path="/tests/cache/long",
            summary="Clear endpoint cache",
            description="Only enabled in testing mode",
            responses={
                204: "Endpoint cache cleared",
            },
        )
        def delete(self) -> Response:

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
        def get(self, user: User) -> Response:

            TestAuthCache.counter += 1
            return self.response((user.uuid, TestAuthCache.counter))

    class TestOptionalAuthCache(EndpointResource):
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
        def get(self, user: Optional[User]) -> Response:

            TestOptionalAuthCache.counter += 1
            uuid = user.uuid if user else "N/A"
            return self.response((uuid, TestOptionalAuthCache.counter))

    class TestParamAuthCache(EndpointResource):
        """
        Used to test cache of authenticated endpoints that accept access token param
        (cache keys are token dependent)
        """

        labels = ["tests"]

        counter = 0  # Increased at each request... except cached responses of course

        @decorators.auth.require(allow_access_token_parameter=True)
        @decorators.endpoint(
            path="/tests/cache/paramauth",
            summary="Execute tests of cached responses auth. endpoints with parameter",
            description="Only enabled in testing mode",
            responses={
                200: "Content sent",
            },
        )
        @decorators.cache(timeout=200)
        def get(self, user: User) -> Response:

            TestParamAuthCache.counter += 1
            return self.response((user.uuid, TestParamAuthCache.counter))

    class TestOptionalParamAuthCache(EndpointResource):
        """
        Used to test cache of optionally authenticated endpoints
        that accept access token param
        (cache keys are token dependent, if tokens are provided and valid)
        """

        labels = ["tests"]

        counter = 0  # Increased at each request... except cached responses of course

        @decorators.auth.optional(allow_access_token_parameter=True)
        @decorators.endpoint(
            path="/tests/cache/optionalparamauth",
            summary="Execute tests of caches of optionally auth. endpoints with param",
            description="Only enabled in testing mode",
            responses={
                200: "Content sent",
            },
        )
        @decorators.cache(timeout=200)
        def get(self, user: Optional[User]) -> Response:

            TestOptionalParamAuthCache.counter += 1
            uuid = user.uuid if user else "N/A"
            return self.response((uuid, TestOptionalParamAuthCache.counter))
