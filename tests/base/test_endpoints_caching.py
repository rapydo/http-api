import time
from datetime import datetime

from restapi.services.cache import Cache
from restapi.tests import API_URI, BaseTests


class TestApp(BaseTests):
    def test_caching_autocleaning(self, client):
        # patch method is cached for 2 seconds

        # First response is not cached, expected time is greater than 1 second
        start_time = datetime.now()
        r = client.patch(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert self.get_content(r) == "OK"
        assert (end_time - start_time).total_seconds() > 2

        # Second response is cached, expected time is lower than 1 second
        start_time = datetime.now()
        r = client.patch(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert self.get_content(r) == "OK"
        assert (end_time - start_time).total_seconds() < 2

        # Third response is no longer cached, expected time is greater than 1 second
        time.sleep(4)
        start_time = datetime.now()
        r = client.patch(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert self.get_content(r) == "OK"
        assert (end_time - start_time).total_seconds() > 2

        # Fourth response is cached again, expected time is lower than 1 second
        start_time = datetime.now()
        r = client.patch(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert self.get_content(r) == "OK"
        assert (end_time - start_time).total_seconds() < 2

    def test_caching_general_clearing(self, client):
        # get method is cached for 200 seconds

        # First response is not cached, expected time is greater than 1 second
        start_time = datetime.now()
        r = client.get(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert (end_time - start_time).total_seconds() > 2

        # Second response is cached, expected time is lower than 1 second
        start_time = datetime.now()
        r = client.get(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert (end_time - start_time).total_seconds() < 2

        # Empty all the cache
        Cache.clear()

        # Third response is no longer cached, expected time is greater than 1 second
        start_time = datetime.now()
        r = client.get(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert (end_time - start_time).total_seconds() > 2

    def test_caching_endpoint_clearing(self, client):

        # First response is still cached, expected time is lower than 1 second
        start_time = datetime.now()
        r = client.get(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert (end_time - start_time).total_seconds() < 1

        # Empty the endpoint cache
        client.delete(f"{API_URI}/tests/cache")

        # Second response is no longer cached, expected time is greater than 1 second
        start_time = datetime.now()
        r = client.get(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert (end_time - start_time).total_seconds() > 1
