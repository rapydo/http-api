import time
from datetime import datetime

from restapi.services.cache import Cache
from restapi.tests import API_URI, BaseTests


class TestApp(BaseTests):
    def test_caching_autocleaning(self, client):
        # patch method is cached for 4 seconds

        # First response is not cached, expected time is greater than 2 second
        start_time = datetime.now()
        r = client.patch(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert self.get_content(r) == "OK"
        assert (end_time - start_time).total_seconds() > 2

        # Second response is cached, expected time is lower than 2 second
        start_time = datetime.now()
        r = client.patch(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert self.get_content(r) == "OK"
        assert (end_time - start_time).total_seconds() < 2

        # Third response is no longer cached, expected time is greater than 2 second
        time.sleep(4)
        start_time = datetime.now()
        r = client.patch(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert self.get_content(r) == "OK"
        assert (end_time - start_time).total_seconds() > 2

        # Fourth response is cached again, expected time is lower than 2 second
        start_time = datetime.now()
        r = client.patch(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert self.get_content(r) == "OK"
        assert (end_time - start_time).total_seconds() < 2

    def test_caching_general_clearing(self, client):
        # get method is cached for 200 seconds

        # First response is not cached, expected time is greater than 2 second
        start_time = datetime.now()
        r = client.get(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert (end_time - start_time).total_seconds() > 2

        # Second response is cached, expected time is lower than 2 second
        start_time = datetime.now()
        r = client.get(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert (end_time - start_time).total_seconds() < 2

        # Empty all the cache
        Cache.clear()

        # Third response is no longer cached, expected time is greater than 2 second
        start_time = datetime.now()
        r = client.get(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert (end_time - start_time).total_seconds() > 2

    def test_caching_endpoint_clearing(self, client):

        # First response is still cached, expected time is lower than 2 second
        start_time = datetime.now()
        r = client.get(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert (end_time - start_time).total_seconds() < 2

        # Empty the endpoint cache
        client.delete(f"{API_URI}/tests/cache")

        # Second response is no longer cached, expected time is greater than 2 second
        start_time = datetime.now()
        r = client.get(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert (end_time - start_time).total_seconds() > 2

    def test_cached_authenticated_endpoint(self, client):

        headers, _ = self.do_login(client, None, None)

        r = client.get(f"{API_URI}/tests/authcache", headers=headers)
        assert r.status_code == 200
        resp1 = self.get_content(r)
        assert isinstance(resp1, list)
        # counter is 1 because this is the first request to this endpoint
        assert resp1[1] == 1

        r = client.get(f"{API_URI}/tests/authcache", headers=headers)
        assert r.status_code == 200
        resp2 = self.get_content(r)
        assert isinstance(resp2, list)
        assert resp2[0] == resp1[0]
        # Same counter as above, because the response is replied from the cache
        assert resp2[1] == 1

        # Create a new user on the fly to test the cached endpoint
        schema = self.getDynamicInputSchema(client, "admin/users", headers)
        data = self.buildData(schema)
        data["email_notification"] = False
        data["is_active"] = True
        r = client.post(f"{API_URI}/admin/users", data=data, headers=headers)
        assert r.status_code == 200
        uuid = self.get_content(r)
        headers2, _ = self.do_login(client, schema["email"], schema["password"])

        r = client.get(f"{API_URI}/tests/authcache", headers=headers2)
        assert r.status_code == 200
        resp3 = self.get_content(r)
        assert isinstance(resp3, list)
        assert resp3[0] == uuid
        assert resp3[0] != resp1[0]
        # The counter changed, because the response is not replied from the cache
        assert resp3[1] == 2

        r = client.get(f"{API_URI}/tests/authcache", headers=headers2)
        assert r.status_code == 200
        resp4 = self.get_content(r)
        assert isinstance(resp4, list)
        assert resp4[0] == uuid
        assert resp4[0] != resp1[0]
        # Same counter as above, because the response is replied from the cache
        assert resp4[1] == 2

    def test_cached_semiauthenticated_endpoint(self, client):
        r = client.get(f"{API_URI}/tests/semiauthcache")
        assert r.status_code == 200
        nonauthenticated1 = self.get_content(r)
        assert isinstance(nonauthenticated1, list)
        assert nonauthenticated1[0] == "N/A"
        # counter is 1 because this is the first request to this endpoint
        assert nonauthenticated1[1] == 1

        r = client.get(f"{API_URI}/tests/semiauthcache")
        assert r.status_code == 200
        nonauthenticated2 = self.get_content(r)
        assert isinstance(nonauthenticated2, list)
        assert nonauthenticated2[0] == "N/A"
        # Same counter as above, because the response is replied from the cache
        assert nonauthenticated2[1] == 1

        headers, _ = self.do_login(client, None, None)
        r = client.get(f"{API_URI}/tests/semiauthcache", headers=headers)
        assert r.status_code == 200
        authenticated1 = self.get_content(r)
        assert isinstance(authenticated1, list)
        assert authenticated1[0] != "N/A"
        # The counter changed, because the response is not replied from the cache
        assert authenticated1[1] == 2

        headers, _ = self.do_login(client, None, None)
        r = client.get(f"{API_URI}/tests/semiauthcache", headers=headers)
        assert r.status_code == 200
        authenticated2 = self.get_content(r)
        assert isinstance(authenticated2, list)
        assert authenticated2[0] == authenticated1[0]
        # Same counter as above, because the response is replied from the cache
        assert authenticated2[1] == 2
