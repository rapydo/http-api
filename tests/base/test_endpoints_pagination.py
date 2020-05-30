from restapi.tests import BaseTests, API_URI
# from restapi.utilities.logs import log


class TestApp(BaseTests):

    def test_GET_specs(self, client):

        # Old specs produced by swagger inputs - to be deprecated
        r = client.get(f"{API_URI}/tests/pagination")
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) == 20
        assert content[0] == 1
        assert content[19] == 20

        data = {"get_total": True, "page": 1, "size": 20}
        r = client.get(f"{API_URI}/tests/pagination", data=data)
        assert r.status_code == 200
        content = self.get_content(r)
        assert content == 150

        assert r.status_code == 200
        content = self.get_content(r)
        assert content == 150

        r = client.get(f"{API_URI}/tests/pagination", data={"page": 2})
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) == 20
        assert content[0] == 21
        assert content[19] == 40

        r = client.get(f"{API_URI}/tests/pagination", data={"page": 2, "size": 10})
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) == 10
        assert content[0] == 21
        assert content[19] == 30

        r = client.get(f"{API_URI}/tests/pagination", data={"page": 20})
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) == 0

        r = client.get(f"{API_URI}/tests/pagination", data={"size": 200})
        assert r.status_code == 200
        content = self.get_content(r)
        # Size is capped to 100
        assert len(content) == 100

        r = client.get(f"{API_URI}/tests/pagination", data={"page": -5})
        assert r.status_code == 400

        r = client.get(f"{API_URI}/tests/pagination", data={"size": -5})
        assert r.status_code == 400

        r = client.get(f"{API_URI}/tests/pagination", data={"page": -5, "size": -5})
        assert r.status_code == 400
