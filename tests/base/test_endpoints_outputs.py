from datetime import datetime
from typing import Any

from restapi.tests import API_URI, BaseTests, FlaskClient


class TestApp(BaseTests):
    def test_outputs(self, client: FlaskClient) -> None:

        response: Any = "just to fake mypy :p"

        r = client.post(f"{API_URI}/tests/outputs/string")
        assert r.status_code == 200
        response = self.get_content(r)
        assert isinstance(response, str)
        assert response == "string"

        r = client.post(f"{API_URI}/tests/outputs/whatever")
        assert r.status_code == 200
        response = self.get_content(r)
        assert isinstance(response, str)
        assert response == "string"

        r = client.post(f"{API_URI}/tests/outputs/list")
        assert r.status_code == 200
        response = self.get_content(r)
        assert isinstance(response, list)
        assert response == ["a", "b", "c", "c"]

        r = client.post(f"{API_URI}/tests/outputs/tuple")
        assert r.status_code == 200
        response = self.get_content(r)
        # Tuples are serialized as lists
        assert isinstance(response, list)
        assert response == ["a", "b", "c", "c"]

        r = client.post(f"{API_URI}/tests/outputs/set")
        assert r.status_code == 200
        response = self.get_content(r)
        # Sets are serialized as lists
        assert isinstance(response, list)
        # But without duplicates :-)
        assert response == ["a", "b", "c"]

        r = client.post(f"{API_URI}/tests/outputs/dict")
        assert r.status_code == 200
        response = self.get_content(r)
        assert isinstance(response, dict)
        assert response == {"a": 1, "b": 2, "c": 3}

        r = client.post(f"{API_URI}/tests/outputs/datetime")
        assert r.status_code == 200
        response = self.get_content(r)
        assert isinstance(response, datetime)
