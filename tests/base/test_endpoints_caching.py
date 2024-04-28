import time
from datetime import datetime

import pytest
from flask import Flask

from restapi.connectors import Connector
from restapi.env import Env
from restapi.exceptions import ServiceUnavailable
from restapi.services.cache import Cache
from restapi.tests import API_URI, BaseTests, FlaskClient
from restapi.utilities.logs import log

UUID = 0
COUNTER = 1

CONNECTOR_AVAILABLE = Connector.check_availability("redis")


@pytest.mark.skipif(
    CONNECTOR_AVAILABLE, reason="This test needs Redis to be not available"
)
class TestAppNoRedis(BaseTests):
    def test_caching_autocleaning(self, app: Flask) -> None:
        with pytest.raises(ServiceUnavailable):
            Cache.get_instance(app)


@pytest.mark.skipif(
    not CONNECTOR_AVAILABLE, reason="This test needs Redis to be available"
)
class TestAppWithRedis(BaseTests):
    def test_caching_autocleaning(self, client: FlaskClient) -> None:
        headers, _ = self.do_login(client, None, None)

        # Syncronize this test to start at the beginning of the next second and
        # prevent the test to overlap a change of second
        # Since the caching is rounded to the second, few milliseconds cann make the
        # difference, for example:
        # A first request at 00:00:00.997 is cached
        # A second request at 00:00:01.002 is no longer cached, even if only 5 millisec
        # elapsed because the second changed
        # Added 0.01 just to avoid to exactly start at the beginning of the second
        t = 1.01 - datetime.now().microsecond / 1000000.0
        log.critical("Sleeping {} sec", t)
        time.sleep(t)

        # the GET method is cached for 1 second

        # First response is not cached
        r = client.get(f"{API_URI}/tests/cache/short")
        assert r.status_code == 200
        counter1 = self.get_content(r)

        # Second response is cached
        r = client.get(f"{API_URI}/tests/cache/short")
        assert r.status_code == 200
        assert self.get_content(r) == counter1

        # Third response is no longer cached
        time.sleep(1)

        r = client.get(f"{API_URI}/tests/cache/short")
        assert r.status_code == 200
        counter2 = self.get_content(r)
        assert counter2 != counter1

        # Fourth response is cached again
        r = client.get(f"{API_URI}/tests/cache/short")
        assert r.status_code == 200
        assert self.get_content(r) == counter2

        # Endpoint is unauthenticated, headers are ignored when building the cache key
        r = client.get(f"{API_URI}/tests/cache/short", headers=headers)
        assert r.status_code == 200
        assert self.get_content(r) == counter2

        # Tokens are ignored even if invalid
        r = client.get(
            f"{API_URI}/tests/cache/short", headers={"Authorization": "Bearer invalid"}
        )
        assert r.status_code == 200
        assert self.get_content(r) == counter2

    def test_caching_general_clearing(self, client: FlaskClient) -> None:
        headers, _ = self.do_login(client, None, None)

        # get method is cached for 200 seconds

        # First response is not cached
        r = client.get(f"{API_URI}/tests/cache/long")
        assert r.status_code == 200
        counter1 = self.get_content(r)

        # Second response is cached
        r = client.get(f"{API_URI}/tests/cache/long")
        assert r.status_code == 200
        assert self.get_content(r) == counter1

        # Empty all the cache
        Cache.clear()

        # Third response is no longer cached
        r = client.get(f"{API_URI}/tests/cache/long")
        assert r.status_code == 200
        counter2 = self.get_content(r)
        assert counter2 != counter1

        # Response is still cached
        r = client.get(f"{API_URI}/tests/cache/long")
        assert r.status_code == 200
        assert self.get_content(r) == counter2

        # Empty the endpoint cache
        client.delete(f"{API_URI}/tests/cache/long")

        # Second response is no longer cached
        r = client.get(f"{API_URI}/tests/cache/long")
        assert r.status_code == 200
        counter3 = self.get_content(r)
        assert counter3 != counter2

        # Response is still cached
        r = client.get(f"{API_URI}/tests/cache/long")
        assert r.status_code == 200
        assert self.get_content(r) == counter3

        # Endpoint is unauthenticated, headers are ignored when building the cache key
        r = client.get(f"{API_URI}/tests/cache/long", headers=headers)
        assert r.status_code == 200
        assert self.get_content(r) == counter3

        # Tokens are ignored even if invalid
        r = client.get(
            f"{API_URI}/tests/cache/long", headers={"Authorization": "Bearer invalid"}
        )
        assert r.status_code == 200
        assert self.get_content(r) == counter3

    def test_cached_authenticated_endpoint(self, client: FlaskClient) -> None:
        headers1, _ = self.do_login(client, None, None)

        r = client.get(f"{API_URI}/tests/cache/auth", headers=headers1)
        assert r.status_code == 200
        resp1 = self.get_content(r)
        assert isinstance(resp1, list)
        # counter is 1 because this is the first request to this endpoint
        assert resp1[COUNTER] == 1

        r = client.get(f"{API_URI}/tests/cache/auth", headers=headers1)
        assert r.status_code == 200
        resp2 = self.get_content(r)
        assert isinstance(resp2, list)
        assert resp2[UUID] == resp1[UUID]
        # Same counter as above, because the response is replied from the cache
        assert resp2[COUNTER] == 1

        r = client.get(
            f"{API_URI}/tests/cache/auth", headers={"Authorization": "Bearer invalid"}
        )
        assert r.status_code == 401

        # Wrong token does not affected the cache
        r = client.get(f"{API_URI}/tests/cache/auth", headers=headers1)
        assert r.status_code == 200
        resp2bis = self.get_content(r)
        assert isinstance(resp2bis, list)
        assert resp2bis[UUID] == resp1[UUID]
        # Same counter as above, because the response is replied from the cache
        assert resp2bis[COUNTER] == 1

        headers2, _ = self.do_login(client, None, None)
        # Same user but different token, the cache should not be used
        r = client.get(f"{API_URI}/tests/cache/auth", headers=headers2)
        assert r.status_code == 200
        resp3 = self.get_content(r)
        assert isinstance(resp3, list)
        assert resp3[UUID] == resp1[UUID]
        assert resp3[UUID] == resp2[UUID]
        assert resp3[COUNTER] == 2

        if Env.get_bool("MAIN_LOGIN_ENABLE"):
            # Create a new user on the fly to test the cached endpoint
            uuid, data = self.create_user(client)
            headers3, _ = self.do_login(client, data["email"], data["password"])

            # Another user, the response must change
            r = client.get(f"{API_URI}/tests/cache/auth", headers=headers3)
            assert r.status_code == 200
            resp4 = self.get_content(r)
            assert isinstance(resp4, list)
            assert resp4[UUID] == uuid
            assert resp4[UUID] != resp1[UUID]
            assert resp4[UUID] != resp2[UUID]
            assert resp4[UUID] != resp3[UUID]
            # The counter changed, because the response is not replied from the cache
            assert resp4[COUNTER] == 3

            # Same token, response must be cached
            r = client.get(f"{API_URI}/tests/cache/auth", headers=headers3)
            assert r.status_code == 200
            resp5 = self.get_content(r)
            assert isinstance(resp5, list)
            assert resp5[UUID] == uuid
            assert resp5[UUID] == resp4[UUID]
            # Same counter as above, because the response is replied from the cache
            assert resp5[COUNTER] == 3

            self.delete_user(client, uuid)

    def test_cached_semiauthenticated_endpoint(self, client: FlaskClient) -> None:
        r = client.get(f"{API_URI}/tests/cache/optionalauth")
        assert r.status_code == 200
        nonauthenticated1 = self.get_content(r)
        assert isinstance(nonauthenticated1, list)
        assert nonauthenticated1[UUID] == "N/A"
        # counter is 1 because this is the first request to this endpoint
        assert nonauthenticated1[COUNTER] == 1

        r = client.get(f"{API_URI}/tests/cache/optionalauth")
        assert r.status_code == 200
        nonauthenticated2 = self.get_content(r)
        assert isinstance(nonauthenticated2, list)
        assert nonauthenticated2[UUID] == "N/A"
        # Same counter as above, because the response is replied from the cache
        assert nonauthenticated2[COUNTER] == 1

        headers, _ = self.do_login(client, None, None)
        r = client.get(f"{API_URI}/tests/cache/optionalauth", headers=headers)
        assert r.status_code == 200
        authenticated1 = self.get_content(r)
        assert isinstance(authenticated1, list)
        assert authenticated1[UUID] != "N/A"
        # The counter changed, because the response is not replied from the cache
        assert authenticated1[COUNTER] == 2

        # Token cached => cache should be used
        r = client.get(f"{API_URI}/tests/cache/optionalauth", headers=headers)
        assert r.status_code == 200
        authenticated2 = self.get_content(r)
        assert isinstance(authenticated2, list)
        assert authenticated2[UUID] == authenticated1[UUID]
        # Same counter as above, because the response is replied from the cache
        assert authenticated2[COUNTER] == 2

        # New token => no cache
        headers, _ = self.do_login(client, None, None)
        r = client.get(f"{API_URI}/tests/cache/optionalauth", headers=headers)
        assert r.status_code == 200
        authenticated2 = self.get_content(r)
        assert isinstance(authenticated2, list)
        assert authenticated2[UUID] == authenticated1[UUID]
        # Counter changed
        assert authenticated2[COUNTER] == 3

        r = client.get(
            f"{API_URI}/tests/cache/optionalauth",
            headers={"Authorization": "Bearer invalid"},
        )
        assert r.status_code == 401

    def test_cached_authenticated_param_endpoint(self, client: FlaskClient) -> None:
        headers1, _ = self.do_login(client, None, None)

        r = client.get(f"{API_URI}/tests/cache/paramauth", headers=headers1)
        assert r.status_code == 200
        resp1 = self.get_content(r)
        assert isinstance(resp1, list)
        # counter is 1 because this is the first request to this endpoint
        assert resp1[COUNTER] == 1

        r = client.get(f"{API_URI}/tests/cache/paramauth", headers=headers1)
        assert r.status_code == 200
        resp2 = self.get_content(r)
        assert isinstance(resp2, list)
        assert resp2[UUID] == resp1[UUID]
        # Same counter as above, because the response is replied from the cache
        assert resp2[COUNTER] == resp1[COUNTER]
        assert resp2[COUNTER] == 1

        headers2, token2 = self.do_login(client, None, None)
        # Test by using access_token parameter instead of Headers
        r = client.get(
            f"{API_URI}/tests/cache/paramauth", query_string={"access_token": token2}
        )
        assert r.status_code == 200
        resp3 = self.get_content(r)
        assert isinstance(resp3, list)
        # This is the same user, uuid is unchanged
        assert resp3[UUID] == resp1[UUID]
        # but counter changed, because the response is not replied from the cache
        assert resp3[COUNTER] != resp1[COUNTER]
        assert resp3[COUNTER] == 2

        r = client.get(
            f"{API_URI}/tests/cache/paramauth", query_string={"access_token": token2}
        )
        assert r.status_code == 200
        resp4 = self.get_content(r)
        assert isinstance(resp4, list)
        assert resp4[UUID] == resp1[UUID]
        # Same counter as above, because the response is replied from the cache
        assert resp4[COUNTER] == resp3[COUNTER]
        assert resp4[COUNTER] == 2

        # Cache is stored starting from the access_token parameter,
        # but the token is the same also if provided as header
        r = client.get(f"{API_URI}/tests/cache/paramauth", headers=headers2)
        assert r.status_code == 200
        resp5 = self.get_content(r)
        assert isinstance(resp5, list)
        assert resp5[UUID] == resp1[UUID]
        # Same counter as above, because the response is replied from the cache
        assert resp5[COUNTER] == resp3[COUNTER]
        assert resp5[COUNTER] == 2

    def test_cached_semiauthenticated_param_endpoint(self, client: FlaskClient) -> None:
        r = client.get(f"{API_URI}/tests/cache/optionalparamauth")
        assert r.status_code == 200
        nonauthenticated1 = self.get_content(r)
        assert isinstance(nonauthenticated1, list)
        assert nonauthenticated1[UUID] == "N/A"
        # counter is 1 because this is the first request to this endpoint
        assert nonauthenticated1[COUNTER] == 1

        r = client.get(f"{API_URI}/tests/cache/optionalparamauth")
        assert r.status_code == 200
        nonauthenticated2 = self.get_content(r)
        assert isinstance(nonauthenticated2, list)
        assert nonauthenticated2[UUID] == "N/A"
        # Same counter as above, because the response is replied from the cache
        assert nonauthenticated2[COUNTER] == 1

        headers1, token1 = self.do_login(client, None, None)

        r = client.get(f"{API_URI}/tests/cache/optionalparamauth", headers=headers1)
        assert r.status_code == 200
        authenticated1 = self.get_content(r)
        assert isinstance(authenticated1, list)
        assert authenticated1[UUID] != "N/A"
        # The counter changed, because the response is not replied from the cache
        assert authenticated1[COUNTER] == 2

        r = client.get(f"{API_URI}/tests/cache/optionalparamauth", headers=headers1)
        assert r.status_code == 200
        authenticated2 = self.get_content(r)
        assert isinstance(authenticated2, list)
        assert authenticated2[UUID] != "N/A"
        assert authenticated2[UUID] == authenticated1[UUID]
        # Same counter as above, because the response is replied from the cache
        assert authenticated2[COUNTER] == 2

        # Response is reply from the cache even if the token is provided as query param
        r = client.get(
            f"{API_URI}/tests/cache/optionalparamauth",
            query_string={"access_token": token1},
        )
        assert r.status_code == 200
        authenticated3 = self.get_content(r)
        assert isinstance(authenticated3, list)
        assert authenticated3[UUID] != "N/A"
        assert authenticated3[UUID] == authenticated1[UUID]
        # Same counter as above, because the response is replied from the cache
        assert authenticated3[COUNTER] == 2

        # Let's test another token => new cache key.
        # This time access_token and then headers

        headers2, token2 = self.do_login(client, None, None)
        r = client.get(
            f"{API_URI}/tests/cache/optionalparamauth",
            query_string={"access_token": token2},
        )
        assert r.status_code == 200
        authenticated4 = self.get_content(r)
        assert isinstance(authenticated4, list)
        assert authenticated4[UUID] != "N/A"
        # Different token, but the user is the same
        assert authenticated4[UUID] == authenticated1[UUID]
        # Counter increased
        assert authenticated4[COUNTER] == 3

        r = client.get(
            f"{API_URI}/tests/cache/optionalparamauth",
            query_string={"access_token": token2},
        )
        assert r.status_code == 200
        authenticated5 = self.get_content(r)
        assert isinstance(authenticated5, list)
        assert authenticated5[UUID] != "N/A"
        # Different token, but the user is the same
        assert authenticated5[UUID] == authenticated1[UUID]
        # Counter increased
        assert authenticated5[COUNTER] == authenticated4[COUNTER]
        assert authenticated5[COUNTER] == 3

        r = client.get(f"{API_URI}/tests/cache/optionalparamauth", headers=headers2)
        assert r.status_code == 200
        authenticated6 = self.get_content(r)
        assert isinstance(authenticated6, list)
        assert authenticated6[UUID] != "N/A"
        # Different token, but the user is the same
        assert authenticated6[UUID] == authenticated1[UUID]
        # Counter increased
        assert authenticated6[COUNTER] == authenticated4[COUNTER]
        assert authenticated6[COUNTER] == 3
