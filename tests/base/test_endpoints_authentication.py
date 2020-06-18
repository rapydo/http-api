from restapi.services.authentication import BaseAuthentication
from restapi.tests import API_URI, BaseTests


class TestApp(BaseTests):
    def test_auth(self, client):

        r = client.get(f"{API_URI}/tests/authentication")
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) == 2
        assert "token" in content
        assert "user" in content
        assert "unpacked_user" not in content
        assert content["token"] is None
        assert content["user"] is None

        headers, _ = self.do_login(client, None, None)

        r = client.get(f"{API_URI}/tests/authentication", headers=headers)
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) == 3
        assert "token" in content
        assert "user" in content
        assert "unpacked_user" in content
        assert content["token"] is None
        assert content["user"] is None
        assert content["unpacked_user"] is not None
        assert content["unpacked_user"] == BaseAuthentication.default_user
