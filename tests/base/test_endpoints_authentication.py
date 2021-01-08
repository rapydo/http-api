from restapi.env import Env
from restapi.services.authentication import BaseAuthentication
from restapi.tests import API_URI, BaseTests, FlaskClient


class TestApp(BaseTests):
    def test_no_auth(self, client: FlaskClient) -> None:

        r = client.get(f"{API_URI}/tests/noauth")
        assert r.status_code == 200
        assert self.get_content(r) == "OK"

        headers, _ = self.do_login(client, None, None)

        # Tokens are ignored
        r = client.get(f"{API_URI}/tests/noauth", headers=headers)
        assert r.status_code == 200
        assert self.get_content(r) == "OK"

        # Tokens are ignored even if invalid
        r = client.get(
            f"{API_URI}/tests/noauth", headers={"Authorization": "Bearer invalid"}
        )
        assert r.status_code == 200
        assert self.get_content(r) == "OK"

    def test_auth(self, client: FlaskClient) -> None:

        r = client.get(f"{API_URI}/tests/authentication")
        assert r.status_code == 401

        r = client.get(
            f"{API_URI}/tests/authentication",
            headers={"Authorization": "Bearer invalid"},
        )
        assert r.status_code == 401

        headers, token = self.do_login(client, None, None)

        r = client.get(f"{API_URI}/tests/authentication", headers=headers)
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) == 2
        assert "token" in content
        assert "user" in content
        assert content["token"] == token
        assert content["user"] == BaseAuthentication.default_user

        if not Env.get_bool("ALLOW_ACCESS_TOKEN_PARAMETER"):
            # access token parameter is not allowed by default
            r = client.get(
                f"{API_URI}/tests/authentication", query_string={"access_token": token}
            )
            assert r.status_code == 401

    def test_optional_auth(self, client: FlaskClient) -> None:

        # Optional authentication can accept missing tokens
        r = client.get(f"{API_URI}/tests/optionalauthentication")
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) == 2
        assert "token" in content
        assert "user" in content
        assert content["token"] is None
        assert content["user"] is None

        headers, token = self.do_login(client, None, None)

        # Or valid tokens
        r = client.get(f"{API_URI}/tests/optionalauthentication", headers=headers)
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) == 2
        assert "token" in content
        assert "user" in content
        assert content["token"] == token
        assert content["user"] == BaseAuthentication.default_user

        # But not invalid tokens, i.e. if presented the tokens is always validated
        r = client.get(
            f"{API_URI}/tests/authentication",
            headers={"Authorization": "Bearer invalid"},
        )
        assert r.status_code == 401

        # access token parameter is not allowed by default
        r = client.get(
            f"{API_URI}/tests/optionalauthentication",
            query_string={"access_token": token},
        )
        # query token is ignored but the endpoint accepts missing tokens
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) == 2
        assert "token" in content
        assert "user" in content
        assert content["token"] is None
        assert content["user"] is None

        r = client.get(
            f"{API_URI}/tests/optionalauthentication",
            query_string={"access_token": "invalid"},
        )
        # invalid tokens should be rejected, but query token is ignored
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) == 2
        assert "token" in content
        assert "user" in content
        assert content["token"] is None
        assert content["user"] is None

    def test_access_token_parameter(self, client: FlaskClient) -> None:

        r = client.get(f"{API_URI}/tests/queryauthentication")
        assert r.status_code == 401

        r = client.get(
            f"{API_URI}/tests/queryauthentication",
            headers={"Authorization": "Bearer invalid"},
        )
        assert r.status_code == 401

        headers, token = self.do_login(client, None, None)

        r = client.get(f"{API_URI}/tests/queryauthentication", headers=headers)
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) == 2
        assert "token" in content
        assert "user" in content
        assert content["token"] == token
        assert content["user"] == BaseAuthentication.default_user

        r = client.get(
            f"{API_URI}/tests/queryauthentication", query_string={"access_token": token}
        )
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) == 2
        assert "token" in content
        assert "user" in content
        assert content["token"] == token
        assert content["user"] == BaseAuthentication.default_user

        r = client.get(
            f"{API_URI}/tests/queryauthentication",
            query_string={"access_token": "invalid"},
        )
        assert r.status_code == 401

    def test_optional_access_token_parameter(self, client: FlaskClient) -> None:

        # Optional authentication can accept missing tokens
        r = client.get(f"{API_URI}/tests/optionalqueryauthentication")
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) == 2
        assert "token" in content
        assert "user" in content
        assert content["token"] is None
        assert content["user"] is None

        headers, token = self.do_login(client, None, None)

        # Or valid tokens
        r = client.get(f"{API_URI}/tests/optionalqueryauthentication", headers=headers)
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) == 2
        assert "token" in content
        assert "user" in content
        assert content["token"] == token
        assert content["user"] == BaseAuthentication.default_user

        # But not invalid tokens, i.e. if presented the tokens is always validated
        r = client.get(
            f"{API_URI}/tests/optionalqueryauthentication",
            headers={"Authorization": "Bearer invalid"},
        )
        assert r.status_code == 401

        r = client.get(
            f"{API_URI}/tests/optionalqueryauthentication",
            query_string={"access_token": token},
        )
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) == 2
        assert "token" in content
        assert "user" in content
        assert content["token"] == token
        assert content["user"] == BaseAuthentication.default_user

        r = client.get(
            f"{API_URI}/tests/optionalqueryauthentication",
            query_string={"access_token": "invalid"},
        )
        # invalid tokens should be rejected, but query token is ignored
        assert r.status_code == 401
