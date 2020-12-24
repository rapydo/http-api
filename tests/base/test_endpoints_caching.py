import time

from restapi.services.cache import Cache
from restapi.tests import API_URI, BaseTests


class TestApp(BaseTests):
    def test_caching_autocleaning(self, client):

        headers, _ = self.do_login(client, None, None)

        # get method is cached for 1 second

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

    def test_caching_general_clearing(self, client):

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

    def test_cached_authenticated_endpoint(self, client):

        headers1, _ = self.do_login(client, None, None)
        headers2, _ = self.do_login(client, None, None)

        r = client.get(f"{API_URI}/tests/cache/auth", headers=headers1)
        assert r.status_code == 200
        resp1 = self.get_content(r)
        assert isinstance(resp1, list)
        # counter is 1 because this is the first request to this endpoint
        assert resp1[1] == 1

        r = client.get(f"{API_URI}/tests/cache/auth", headers=headers1)
        assert r.status_code == 200
        resp2 = self.get_content(r)
        assert isinstance(resp2, list)
        assert resp2[0] == resp1[0]
        # Same counter as above, because the response is replied from the cache
        assert resp2[1] == 1

        r = client.get(
            f"{API_URI}/tests/cache/auth", headers={"Authorization": "Bearer invalid"}
        )
        assert r.status_code == 401

        # Wrong token does not affected the cache
        r = client.get(f"{API_URI}/tests/cache/auth", headers=headers1)
        assert r.status_code == 200
        resp2bis = self.get_content(r)
        assert isinstance(resp2bis, list)
        assert resp2bis[0] == resp1[0]
        # Same counter as above, because the response is replied from the cache
        assert resp2bis[1] == 1

        # Same user but different token, the cache should not be used
        r = client.get(f"{API_URI}/tests/cache/auth", headers=headers2)
        assert r.status_code == 200
        resp3 = self.get_content(r)
        assert isinstance(resp3, list)
        assert resp3[0] != resp1[0]
        assert resp3[0] != resp2[0]
        # Same counter as above, because the response is replied from the cache
        assert resp3[1] == 2

        # Create a new user on the fly to test the cached endpoint
        schema = self.getDynamicInputSchema(client, "admin/users", headers1)
        data = self.buildData(schema)
        data["email_notification"] = False
        data["is_active"] = True
        r = client.post(f"{API_URI}/admin/users", data=data, headers=headers1)
        assert r.status_code == 200
        uuid = self.get_content(r)
        headers3, _ = self.do_login(client, data["email"], data["password"])

        # Another user, the response must change
        r = client.get(f"{API_URI}/tests/cache/auth", headers=headers3)
        assert r.status_code == 200
        resp4 = self.get_content(r)
        assert isinstance(resp4, list)
        assert resp4[0] == uuid
        assert resp4[0] != resp1[0]
        assert resp4[0] != resp2[0]
        assert resp4[0] != resp3[0]
        # The counter changed, because the response is not replied from the cache
        assert resp4[1] == 3

        # Same token, response must be cached
        r = client.get(f"{API_URI}/tests/cache/auth", headers=headers3)
        assert r.status_code == 200
        resp5 = self.get_content(r)
        assert isinstance(resp5, list)
        assert resp5[0] == uuid
        assert resp5[0] == resp4[0]
        # Same counter as above, because the response is replied from the cache
        assert resp5[1] == 3

        # Delete the user created on the fly to test the cache
        r = client.delete(f"{API_URI}/admin/users/{uuid}", headers=headers1)
        assert r.status_code == 204

    def test_cached_semiauthenticated_endpoint(self, client):
        r = client.get(f"{API_URI}/tests/cache/optionalauth")
        assert r.status_code == 200
        nonauthenticated1 = self.get_content(r)
        assert isinstance(nonauthenticated1, list)
        assert nonauthenticated1[0] == "N/A"
        # counter is 1 because this is the first request to this endpoint
        assert nonauthenticated1[1] == 1

        r = client.get(f"{API_URI}/tests/cache/optionalauth")
        assert r.status_code == 200
        nonauthenticated2 = self.get_content(r)
        assert isinstance(nonauthenticated2, list)
        assert nonauthenticated2[0] == "N/A"
        # Same counter as above, because the response is replied from the cache
        assert nonauthenticated2[1] == 1

        headers, _ = self.do_login(client, None, None)
        r = client.get(f"{API_URI}/tests/cache/optionalauth", headers=headers)
        assert r.status_code == 200
        authenticated1 = self.get_content(r)
        assert isinstance(authenticated1, list)
        assert authenticated1[0] != "N/A"
        # The counter changed, because the response is not replied from the cache
        assert authenticated1[1] == 2

        # Token cached => cache should be used
        headers, _ = self.do_login(client, None, None)
        r = client.get(f"{API_URI}/tests/cache/optionalauth", headers=headers)
        assert r.status_code == 200
        authenticated2 = self.get_content(r)
        assert isinstance(authenticated2, list)
        assert authenticated2[0] != authenticated1[0]
        # Same counter as above, because the response is replied from the cache
        assert authenticated2[1] == 3

        r = client.get(
            f"{API_URI}/tests/cache/optionalauth",
            headers={"Authorization": "Bearer invalid"},
        )
        assert r.status_code == 401

    def test_cached_authenticated_param_endpoint(self, client):

        headers1, _ = self.do_login(client, None, None)
        headers2, token2 = self.do_login(client, None, None)

        r = client.get(f"{API_URI}/tests/cache/auth", headers=headers1)
        assert r.status_code == 200
        resp1 = self.get_content(r)
        assert isinstance(resp1, list)
        # counter is 1 because this is the first request to this endpoint
        assert resp1[1] == 1

        r = client.get(f"{API_URI}/tests/cache/auth", headers=headers1)
        assert r.status_code == 200
        resp2 = self.get_content(r)
        assert isinstance(resp2, list)
        assert resp2[0] == resp1[0]
        # Same counter as above, because the response is replied from the cache
        assert resp2[1] == resp1[1]
        assert resp2[1] == 1

        # Test by using access_token parameter instead of Headers
        r = client.get(
            f"{API_URI}/tests/cache/auth", query_string={"access_token": token2}
        )
        assert r.status_code == 200
        resp3 = self.get_content(r)
        assert isinstance(resp3, list)
        # This is the same user, uuid is unchanged
        assert resp3[0] == resp1[0]
        # but counter changed, because the response is not replied from the cache
        assert resp3[1] != resp1[1]
        assert resp3[1] == 2

        r = client.get(
            f"{API_URI}/tests/cache/auth", query_string={"access_token": token2}
        )
        assert r.status_code == 200
        resp4 = self.get_content(r)
        assert isinstance(resp4, list)
        assert resp4[0] == resp1[0]
        # Same counter as above, because the response is replied from the cache
        assert resp4[1] == resp3[1]
        assert resp4[1] == 2

        # Cache is stored from access_token parameter,
        # but the token is the same if provided in the headers
        r = client.get(f"{API_URI}/tests/cache/auth", headers=headers2)
        assert r.status_code == 200
        resp5 = self.get_content(r)
        assert isinstance(resp5, list)
        assert resp5[0] == resp1[0]
        # Same counter as above, because the response is replied from the cache
        assert resp5[1] == resp3[1]
        assert resp5[1] == 2

    def test_cached_semiauthenticated_param_endpoint(self, client):
        r = client.get(f"{API_URI}/tests/cache/optionalauth")
        assert r.status_code == 200
        nonauthenticated1 = self.get_content(r)
        assert isinstance(nonauthenticated1, list)
        assert nonauthenticated1[0] == "N/A"
        # counter is 1 because this is the first request to this endpoint
        assert nonauthenticated1[1] == 1

        r = client.get(f"{API_URI}/tests/cache/optionalauth")
        assert r.status_code == 200
        nonauthenticated2 = self.get_content(r)
        assert isinstance(nonauthenticated2, list)
        assert nonauthenticated2[0] == "N/A"
        # Same counter as above, because the response is replied from the cache
        assert nonauthenticated2[1] == 1

        headers1, token1 = self.do_login(client, None, None)
        headers2, token2 = self.do_login(client, None, None)

        r = client.get(f"{API_URI}/tests/cache/optionalauth", headers=headers1)
        assert r.status_code == 200
        authenticated1 = self.get_content(r)
        assert isinstance(authenticated1, list)
        assert authenticated1[0] != "N/A"
        # The counter changed, because the response is not replied from the cache
        assert authenticated1[1] == 2

        r = client.get(f"{API_URI}/tests/cache/optionalauth", headers=headers1)
        assert r.status_code == 200
        authenticated2 = self.get_content(r)
        assert isinstance(authenticated2, list)
        assert authenticated2[0] != "N/A"
        assert authenticated2[0] == authenticated1[0]
        # Same counter as above, because the response is replied from the cache
        assert authenticated2[1] == 2

        # Response is reply from the cache even if the token is provided as query param
        r = client.get(
            f"{API_URI}/tests/cache/optionalauth", query_string={"access_token": token1}
        )
        assert r.status_code == 200
        authenticated3 = self.get_content(r)
        assert isinstance(authenticated3, list)
        assert authenticated3[0] != "N/A"
        assert authenticated3[0] == authenticated1[0]
        # Same counter as above, because the response is replied from the cache
        assert authenticated3[1] == 2

        # Let's test another token => new cache key.
        # This time access_token and then headers

        r = client.get(
            f"{API_URI}/tests/cache/optionalauth", query_string={"access_token": token2}
        )
        assert r.status_code == 200
        authenticated4 = self.get_content(r)
        assert isinstance(authenticated4, list)
        assert authenticated4[0] != "N/A"
        # Different token, but the user is the same
        assert authenticated4[0] == authenticated1[0]
        # Counter increased
        assert authenticated4[1] == 3

        r = client.get(
            f"{API_URI}/tests/cache/optionalauth", query_string={"access_token": token2}
        )
        assert r.status_code == 200
        authenticated5 = self.get_content(r)
        assert isinstance(authenticated5, list)
        assert authenticated5[0] != "N/A"
        # Different token, but the user is the same
        assert authenticated5[0] == authenticated1[0]
        # Counter increased
        assert authenticated5[1] == authenticated4[1]
        assert authenticated5[1] == 3

        r = client.get(f"{API_URI}/tests/cache/optionalauth", headers=headers2)
        assert r.status_code == 200
        authenticated6 = self.get_content(r)
        assert isinstance(authenticated6, list)
        assert authenticated6[0] != "N/A"
        # Different token, but the user is the same
        assert authenticated6[0] == authenticated1[0]
        # Counter increased
        assert authenticated6[1] == authenticated4[1]
        assert authenticated6[1] == 3
