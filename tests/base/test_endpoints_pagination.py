from restapi.tests import API_URI, BaseTests, FlaskClient

# from restapi.utilities.logs import log


class TestApp(BaseTests):
    def test_GET_specs(self, client: FlaskClient) -> None:
        r = client.get(f"{API_URI}/tests/pagination")
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) == 20
        assert content[0] == 1
        assert content[19] == 20

        r = client.get(f"{API_URI}/tests/pagination", query_string={"get_total": True})
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, int)
        assert content == 150

        # Check precedence: get_total wins
        data = {"get_total": True, "page": 1, "size": 20}
        r = client.get(f"{API_URI}/tests/pagination", query_string=data)
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, int)
        assert content == 150

        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, int)
        assert content == 150

        r = client.get(f"{API_URI}/tests/pagination", query_string={"page": 2})
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) == 20
        assert content[0] == 21
        assert content[19] == 40

        data = {"page": 2, "size": 10}
        r = client.get(f"{API_URI}/tests/pagination", query_string=data)
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) == 10
        assert content[0] == 11
        assert content[9] == 20

        data = {"page": 2, "size": 100}
        r = client.get(f"{API_URI}/tests/pagination", query_string=data)
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) == 50
        assert content[0] == 101
        assert content[49] == 150

        r = client.get(f"{API_URI}/tests/pagination", query_string={"page": 20})
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) == 0

        r = client.get(f"{API_URI}/tests/pagination", query_string={"size": 101})
        assert r.status_code == 400

        r = client.get(f"{API_URI}/tests/pagination", query_string={"page": -5})
        assert r.status_code == 400

        r = client.get(f"{API_URI}/tests/pagination", query_string={"size": -5})
        assert r.status_code == 400

        data = {"page": -5, "size": -5}
        r = client.get(f"{API_URI}/tests/pagination", query_string=data)
        assert r.status_code == 400

        r = client.post(f"{API_URI}/tests/pagination", json={})
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) == 20
        assert content[0] == 1
        assert content[19] == 20

        r = client.post(f"{API_URI}/tests/pagination", json={"get_total": True})
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, int)
        assert content == 150

        # Check precedence: get_total wins
        data = {"get_total": True, "page": 1, "size": 20}
        r = client.post(f"{API_URI}/tests/pagination", json=data)
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, int)
        assert content == 150

        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, int)
        assert content == 150

        r = client.post(f"{API_URI}/tests/pagination", json={"page": 2})
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) == 20
        assert content[0] == 21
        assert content[19] == 40

        r = client.post(f"{API_URI}/tests/pagination", json={"page": 2, "size": 10})
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) == 10
        assert content[0] == 11
        assert content[9] == 20

        r = client.post(f"{API_URI}/tests/pagination", json={"page": 2, "size": 100})
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) == 50
        assert content[0] == 101
        assert content[49] == 150

        r = client.post(f"{API_URI}/tests/pagination", json={"page": 20})
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) == 0

        r = client.post(f"{API_URI}/tests/pagination", json={"size": 101})
        assert r.status_code == 400

        r = client.post(f"{API_URI}/tests/pagination", json={"page": -5})
        assert r.status_code == 400

        r = client.post(f"{API_URI}/tests/pagination", json={"size": -5})
        assert r.status_code == 400

        r = client.post(f"{API_URI}/tests/pagination", json={"page": -5, "size": -5})
        assert r.status_code == 400

        # Final check:
        # get only accept query parameters
        # post only accept body parameters

        r = client.get(f"{API_URI}/tests/pagination", json={"get_total": True})
        assert r.status_code == 200
        content = self.get_content(r)
        # Request get_total as body parameter but is ignored => sent a list of elements
        assert isinstance(content, list)

        # Request get_total as query parameter but is ignored => sent a list of elements
        r = client.post(
            f"{API_URI}/tests/pagination", json={}, query_string={"get_total": True}
        )
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)
