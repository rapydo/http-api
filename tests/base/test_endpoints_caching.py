import time
from datetime import datetime

from restapi.services.cache import Cache
from restapi.tests import API_URI, BaseTests


class TestApp(BaseTests):
    def test_caching(self, client):
        """ Test that the flask server is running and reachable """

        # First response is not cached, expected time is greater than 1 second
        start_time = datetime.now()
        r = client.get(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert self.get_content(r) == "OK"
        assert (end_time - start_time).total_seconds() > 1

        # Second response is cached, expected time is lower than 1 second
        start_time = datetime.now()
        r = client.get(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert self.get_content(r) == "OK"
        assert (end_time - start_time).total_seconds() < 1

        # Third response is no longer cached, expected time is greater than 1 second
        time.sleep(2)
        start_time = datetime.now()
        r = client.get(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert self.get_content(r) == "OK"
        assert (end_time - start_time).total_seconds() > 1

        # Fourth response is cached again, expected time is lower than 1 second
        start_time = datetime.now()
        r = client.get(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert self.get_content(r) == "OK"
        assert (end_time - start_time).total_seconds() < 1

        # First response is not cached, expected time is greater than 1 second
        start_time = datetime.now()
        r = client.patch(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert (end_time - start_time).total_seconds() > 1

        # Second response is cached, expected time is lower than 1 second
        start_time = datetime.now()
        r = client.patch(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert (end_time - start_time).total_seconds() < 1

        # Empty the cache
        Cache.clear()

        # Third response is no longer cached, expected time is greater than 1 second
        start_time = datetime.now()
        r = client.patch(f"{API_URI}/tests/cache")
        end_time = datetime.now()
        assert r.status_code == 200
        assert (end_time - start_time).total_seconds() > 1
