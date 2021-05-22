from restapi.env import Env
from restapi.services.authentication import BaseAuthentication, Role
from restapi.tests import API_URI, BaseTests, FlaskClient
from restapi.utilities.logs import log


class TestApp(BaseTests):
    def test_no_auth(self, client: FlaskClient) -> None:

        r = client.get(f"{API_URI}/tests/noauth")
        assert r.status_code == 200
        assert self.get_content(r) == "OK"

        if Env.get_bool("AUTH_ENABLE"):
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

        if not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping authentication tests")
            return

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

        if not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping authentication tests")
            return

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

        if not Env.get_bool("ALLOW_ACCESS_TOKEN_PARAMETER"):
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

        if not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping authentication tests")
            return

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

        if not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping authentication tests")
            return

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

    def test_authentication_with_multiple_roles(self, client: FlaskClient) -> None:

        if not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping authentication tests")
            return

        r = client.get(f"{API_URI}/tests/manyrolesauthentication")
        assert r.status_code == 401

        r = client.get(f"{API_URI}/tests/unknownroleauthentication")
        assert r.status_code == 401

        admin_headers, admin_token = self.do_login(client, None, None)

        r = client.get(
            f"{API_URI}/tests/manyrolesauthentication", headers=admin_headers
        )
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) == 2
        assert "token" in content
        assert "user" in content
        assert content["token"] == admin_token
        assert content["user"] == BaseAuthentication.default_user

        r = client.get(
            f"{API_URI}/tests/unknownroleauthentication", headers=admin_headers
        )
        assert r.status_code == 401

        if Env.get_bool("MAIN_LOGIN_ENABLE"):
            uuid, data = self.create_user(client, roles=[Role.USER])
            user_header, user_token = self.do_login(
                client, data.get("email"), data.get("password")
            )

            r = client.get(
                f"{API_URI}/tests/manyrolesauthentication", headers=user_header
            )
            assert r.status_code == 200
            content = self.get_content(r)
            assert len(content) == 2
            assert "token" in content
            assert "user" in content
            assert content["token"] == user_token
            assert content["user"] == data.get("email")

            r = client.get(
                f"{API_URI}/tests/unknownroleauthentication", headers=user_header
            )
            assert r.status_code == 401

            self.delete_user(client, uuid)
