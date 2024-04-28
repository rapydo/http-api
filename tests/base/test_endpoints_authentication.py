from restapi.connectors import Connector
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
        assert isinstance(content, dict)
        assert len(content) == 1
        assert "email" in content
        assert content["email"] == BaseAuthentication.default_user

        # Token type is case insensitive.
        r = client.get(
            f"{API_URI}/tests/authentication",
            headers={"Authorization": f"bearer {token}"},
        )
        assert r.status_code == 200
        r = client.get(
            f"{API_URI}/tests/authentication",
            headers={"Authorization": f"BEARER {token}"},
        )
        assert r.status_code == 200
        r = client.get(
            f"{API_URI}/tests/authentication",
            headers={"Authorization": f"BeArEr {token}"},
        )
        assert r.status_code == 200

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
        assert r.status_code == 204

        headers, token = self.do_login(client, None, None)

        # Or valid tokens
        r = client.get(f"{API_URI}/tests/optionalauthentication", headers=headers)
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, dict)
        assert len(content) == 1
        assert "email" in content
        assert content["email"] == BaseAuthentication.default_user

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
            assert r.status_code == 204

            r = client.get(
                f"{API_URI}/tests/optionalauthentication",
                query_string={"access_token": "invalid"},
            )
            # invalid tokens should be rejected, but query token is ignored
            assert r.status_code == 204

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
        assert isinstance(content, dict)
        assert len(content) == 1
        assert "email" in content
        assert content["email"] == BaseAuthentication.default_user

        r = client.get(
            f"{API_URI}/tests/queryauthentication", query_string={"access_token": token}
        )
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, dict)
        assert len(content) == 1
        assert "email" in content
        assert content["email"] == BaseAuthentication.default_user

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
        assert r.status_code == 204

        headers, token = self.do_login(client, None, None)

        # Or valid tokens
        r = client.get(f"{API_URI}/tests/optionalqueryauthentication", headers=headers)
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, dict)
        assert len(content) == 1
        assert "email" in content
        assert content["email"] == BaseAuthentication.default_user

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
        assert isinstance(content, dict)
        assert len(content) == 1
        assert "email" in content
        assert content["email"] == BaseAuthentication.default_user

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

        admin_headers, _ = self.do_login(client, None, None)

        r = client.get(
            f"{API_URI}/tests/manyrolesauthentication", headers=admin_headers
        )
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, dict)
        assert len(content) == 1
        assert "email" in content
        assert content["email"] == BaseAuthentication.default_user

        r = client.get(
            f"{API_URI}/tests/unknownroleauthentication", headers=admin_headers
        )
        assert r.status_code == 401

        if Env.get_bool("MAIN_LOGIN_ENABLE"):
            uuid, data = self.create_user(client, roles=[Role.USER])
            user_header, _ = self.do_login(
                client, data.get("email"), data.get("password")
            )

            r = client.get(
                f"{API_URI}/tests/manyrolesauthentication", headers=user_header
            )
            assert r.status_code == 200
            content = self.get_content(r)
            assert isinstance(content, dict)
            assert len(content) == 1
            assert "email" in content
            assert content["email"] == data.get("email")

            r = client.get(
                f"{API_URI}/tests/unknownroleauthentication", headers=user_header
            )
            assert r.status_code == 401

            self.delete_user(client, uuid)

    def test_authentication_with_auth_callback(self, client: FlaskClient) -> None:
        if not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping authentication tests")
            return

        auth = Connector.get_authentication_instance()
        user = auth.get_user(username=BaseAuthentication.default_user)

        assert user is not None

        VALID = f"/tests/preloadcallback/{user.uuid}"
        INVALID = "/tests/preloadcallback/12345678-90ab-cdef-1234-567890abcdef"
        admin_headers, _ = self.do_login(client, None, None)

        # Verify both endpoint ...

        r = client.get(
            f"{API_URI}{VALID}", query_string={"test": True}, headers=admin_headers
        )
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, dict)
        assert len(content) == 1
        assert "email" in content
        assert content["email"] == user.email

        r = client.get(
            f"{API_URI}{INVALID}", query_string={"test": True}, headers=admin_headers
        )
        assert r.status_code == 401

        # and get_schema!

        r = client.get(
            f"{API_URI}{VALID}",
            query_string={"get_schema": True},
            headers=admin_headers,
        )
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) == 1
        assert content[0]["key"] == "test"
        assert content[0]["type"] == "boolean"

        r = client.get(
            f"{API_URI}{INVALID}",
            query_string={"get_schema": True},
            headers=admin_headers,
        )
        assert r.status_code == 401
