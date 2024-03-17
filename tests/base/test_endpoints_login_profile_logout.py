import base64
import time

from faker import Faker

from restapi.connectors import Connector
from restapi.env import Env
from restapi.tests import AUTH_URI, BaseAuthentication, BaseTests, FlaskClient
from restapi.utilities.logs import OBSCURE_VALUE, Events, log


class TestApp(BaseTests):
    def test_01_login(self, client: FlaskClient, faker: Faker) -> None:
        """Check that you can login and receive back your token"""

        if not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping login tests")
            return

        log.info("*** VERIFY CASE INSENSITIVE LOGIN")
        # BaseAuthentication.load_default_user()
        # BaseAuthentication.load_roles()
        USER = BaseAuthentication.default_user or "just-to-prevent-None"
        PWD = BaseAuthentication.default_password or "just-to-prevent-None"

        # Login by using upper case username
        self.do_login(client, USER.upper(), PWD)

        events = self.get_last_events(1)
        assert events[0].event == Events.login.value
        assert events[0].user == USER
        assert events[0].url == "/auth/login"

        auth = Connector.get_authentication_instance()
        logins = auth.get_logins(USER)
        login = logins[-1]
        assert login.username == USER

        # Wrong credentials
        # Off course PWD cannot be upper :D
        self.do_login(client, USER, PWD.upper(), status_code=401)

        events = self.get_last_events(1)
        assert events[0].event == Events.failed_login.value
        assert events[0].payload["username"] == USER
        assert events[0].url == "/auth/login"

        logins = auth.get_logins(USER)
        login = logins[-1]
        assert login.username == USER

        log.info("*** VERIFY valid credentials")
        # Login by using normal username (no upper case)
        headers, _ = self.do_login(client, None, None)

        events = self.get_last_events(1)
        assert events[0].event == Events.login.value
        assert events[0].user == USER
        assert events[0].url == "/auth/login"

        time.sleep(5)
        # Verify MAX_PASSWORD_VALIDITY, if set
        headers, token = self.do_login(client, None, None)

        events = self.get_last_events(1)
        assert events[0].event == Events.login.value
        assert events[0].user == USER
        assert events[0].url == "/auth/login"

        self.save("auth_header", headers)
        self.save("auth_token", token)

        # Verify credentials
        r = client.get(f"{AUTH_URI}/status", headers=headers)
        assert r.status_code == 200
        c = self.get_content(r)
        assert isinstance(c, bool) and c

        # this check verifies a BUG with neo4j causing crash of auth module
        # when using a non-email-username to authenticate
        log.info("*** VERIFY with a non-email-username")

        self.do_login(
            client,
            "notanemail",
            "[A-Za-z0-9]+",
            status_code=400,
        )

        # Check failure
        log.info("*** VERIFY invalid credentials")

        random_email = faker.ascii_email()
        self.do_login(
            client,
            random_email,
            faker.password(strong=True),
            status_code=401,
        )

        events = self.get_last_events(1)
        assert events[0].event == Events.failed_login.value
        assert events[0].payload["username"] == random_email
        assert events[0].url == "/auth/login"

    def test_02_GET_profile(self, client: FlaskClient, faker: Faker) -> None:
        """Check if you can use your token for protected endpoints"""

        if not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping profile tests")
            return

        # Check success
        log.info("*** VERIFY valid token")
        r = client.get(f"{AUTH_URI}/profile", headers=self.get("auth_header"))
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, dict)
        uuid = content.get("uuid")

        # Check failure
        log.info("*** VERIFY invalid token")
        r = client.get(f"{AUTH_URI}/profile")
        assert r.status_code == 401

        # Token created for a fake user
        token = self.get_crafted_token("f")
        headers = {"Authorization": f"Bearer {token}"}
        r = client.get(f"{AUTH_URI}/profile", headers=headers)
        assert r.status_code == 401

        # Token created for another user
        token = self.get_crafted_token("x")
        headers = {"Authorization": f"Bearer {token}"}
        r = client.get(f"{AUTH_URI}/profile", headers=headers)
        assert r.status_code == 401

        # Token created for another user
        token = self.get_crafted_token("f", wrong_algorithm=True)
        headers = {"Authorization": f"Bearer {token}"}
        r = client.get(f"{AUTH_URI}/profile", headers=headers)
        assert r.status_code == 401

        # Token created for another user
        token = self.get_crafted_token("f", wrong_secret=True)
        headers = {"Authorization": f"Bearer {token}"}
        r = client.get(f"{AUTH_URI}/profile", headers=headers)
        assert r.status_code == 401

        # token created for the correct user, but from outside the system!!
        token = self.get_crafted_token("f", user_id=uuid)
        headers = {"Authorization": f"Bearer {token}"}
        r = client.get(f"{AUTH_URI}/profile", headers=headers)
        assert r.status_code == 401

        # Immature token
        token = self.get_crafted_token("f", user_id=uuid, immature=True)
        headers = {"Authorization": f"Bearer {token}"}
        r = client.get(f"{AUTH_URI}/profile", headers=headers)
        assert r.status_code == 401

        # Expired token
        token = self.get_crafted_token("f", user_id=uuid, expired=True)
        headers = {"Authorization": f"Bearer {token}"}
        r = client.get(f"{AUTH_URI}/profile", headers=headers)
        assert r.status_code == 401

        # Sending malformed tokens
        headers = {"Authorization": "Bearer"}
        r = client.get(f"{AUTH_URI}/status", headers=headers)
        assert r.status_code == 401

        headers = {"Authorization": f"Bearer '{faker.pystr()}"}
        r = client.get(f"{AUTH_URI}/status", headers=headers)
        assert r.status_code == 401

        # Bearer realm is expected to be case insensitive
        token = self.get("auth_token")
        headers = {"Authorization": f"Bearer {token}"}
        r = client.get(f"{AUTH_URI}/status", headers=headers)
        assert r.status_code == 200

        headers = {"Authorization": f"bearer {token}"}
        r = client.get(f"{AUTH_URI}/status", headers=headers)
        assert r.status_code == 200

        headers = {"Authorization": f"BEARER {token}"}
        r = client.get(f"{AUTH_URI}/status", headers=headers)
        assert r.status_code == 200

        token = self.get("auth_token")
        headers = {"Authorization": f"Bear {token}"}
        r = client.get(f"{AUTH_URI}/status", headers=headers)
        assert r.status_code == 401

        USER = BaseAuthentication.default_user
        PWD = BaseAuthentication.default_password
        # Testing Basic Authentication (not allowed)
        credentials = f"{USER}:{PWD}"
        encoded_credentials = base64.b64encode(str.encode(credentials)).decode("utf-8")

        headers = {"Authorization": f"Basic {encoded_credentials}"}

        r = client.post(f"{AUTH_URI}/login", headers=headers)
        # Response is:
        # {
        #     'password': ['Missing data for required field.'],
        #     'username': ['Missing data for required field.']
        # }
        assert r.status_code == 400

        r = client.get(f"{AUTH_URI}/status", headers=headers)
        assert r.status_code == 401

    def test_03_change_profile(self, client: FlaskClient, faker: Faker) -> None:
        if not Env.get_bool("MAIN_LOGIN_ENABLE") or not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping change profile tests")
            return

        headers, _ = self.do_login(client, None, None)

        # update profile, no auth
        r = client.put(f"{AUTH_URI}/profile")
        assert r.status_code == 401
        # update profile, no auth
        r = client.patch(f"{AUTH_URI}/profile")
        assert r.status_code == 401

        # update profile, no data
        r = client.patch(f"{AUTH_URI}/profile", json={}, headers=headers)
        assert r.status_code == 204

        events = self.get_last_events(1)
        assert events[0].event == Events.modify.value
        assert events[0].user == BaseAuthentication.default_user
        assert events[0].target_type == "User"
        assert events[0].url == "/auth/profile"
        # It is true in the core, but projects may introduce additional values
        # and expand the input dictionary even if initially empty
        # e.g. meteohub adds here the requests_expiration_days parameter
        # assert len(events[0].payload) == 0

        newname = faker.name()
        newuuid = faker.pystr()

        r = client.get(f"{AUTH_URI}/profile", headers=headers)
        assert r.status_code == 200
        c = self.get_content(r)
        assert isinstance(c, dict)
        assert c.get("name") is not None
        assert c.get("name") != newname
        assert c.get("uuid") is not None
        assert c.get("uuid") != newuuid

        # update profile
        data = {"name": newname, "uuid": newuuid}
        r = client.patch(f"{AUTH_URI}/profile", json=data, headers=headers)
        # uuid cannot be modified and will raise an unknown field
        assert r.status_code == 400
        data = {"name": newname}
        r = client.patch(f"{AUTH_URI}/profile", json=data, headers=headers)
        assert r.status_code == 204

        events = self.get_last_events(1)
        assert events[0].event == Events.modify.value
        assert events[0].user == BaseAuthentication.default_user
        assert events[0].target_type == "User"
        assert events[0].url == "/auth/profile"
        # It is true in the core, but projects may introduce additional values
        # and expand the input dictionary even if initially empty
        # e.g. meteohub adds here the requests_expiration_days parameter
        # assert len(events[0].payload) == 1
        assert "name" in events[0].payload

        r = client.get(f"{AUTH_URI}/profile", headers=headers)
        assert r.status_code == 200
        c = self.get_content(r)
        assert isinstance(c, dict)
        assert c.get("name") == newname
        assert c.get("uuid") != newuuid

        # change password, no data
        r = client.put(f"{AUTH_URI}/profile", json={}, headers=headers)
        assert r.status_code == 400
        # Sending a new_password and/or password_confirm without a password
        newpassword = faker.password()
        data = {"new_password": newpassword}
        r = client.put(f"{AUTH_URI}/profile", json=data, headers=headers)
        assert r.status_code == 400
        data = {"password_confirm": newpassword}
        r = client.put(f"{AUTH_URI}/profile", json=data, headers=headers)
        assert r.status_code == 400
        data = {"new_password": newpassword, "password_confirm": newpassword}
        r = client.put(f"{AUTH_URI}/profile", json=data, headers=headers)
        assert r.status_code == 400

        data = {}
        data["password"] = faker.password(length=5)
        r = client.put(f"{AUTH_URI}/profile", json=data, headers=headers)
        assert r.status_code == 400

        data["new_password"] = faker.password(length=5)
        r = client.put(f"{AUTH_URI}/profile", json=data, headers=headers)
        assert r.status_code == 400

        data["password_confirm"] = faker.password(length=5)
        r = client.put(f"{AUTH_URI}/profile", json=data, headers=headers)
        assert r.status_code == 400

        data["password"] = BaseAuthentication.default_password
        r = client.put(f"{AUTH_URI}/profile", json=data, headers=headers)
        assert r.status_code == 400

        # Passwords are too short
        data["password_confirm"] = data["new_password"]
        r = client.put(f"{AUTH_URI}/profile", json=data, headers=headers)
        assert r.status_code == 400

        # Trying to set new password == password... it is not permitted!
        data["password_confirm"] = data["password"]
        data["new_password"] = data["password"]

        if Env.get_bool("AUTH_SECOND_FACTOR_AUTHENTICATION"):
            data["totp_code"] = BaseTests.generate_totp(BaseAuthentication.default_user)

        r = client.put(f"{AUTH_URI}/profile", json=data, headers=headers)
        assert r.status_code == 409

        # Change the password
        data["new_password"] = faker.password(strong=True)
        data["password_confirm"] = data["new_password"]
        r = client.put(f"{AUTH_URI}/profile", json=data, headers=headers)
        assert r.status_code == 204

        # After a change password a spam of delete Token is expected
        # Reverse the list and skip all delete tokens to find the change password event
        events = self.get_last_events(100)
        events.reverse()
        for event in events:
            if event.event == Events.delete.value:
                assert event.target_type == "Token"
                continue

            assert event.event == Events.change_password.value
            assert event.user == BaseAuthentication.default_user
            break

        # verify the new password
        headers, _ = self.do_login(
            client, BaseAuthentication.default_user, data["new_password"]
        )

        # restore the previous password
        data["password"] = data["new_password"]
        data["new_password"] = BaseAuthentication.default_password
        data["password_confirm"] = BaseAuthentication.default_password
        if Env.get_bool("AUTH_SECOND_FACTOR_AUTHENTICATION"):
            data["totp_code"] = BaseTests.generate_totp(BaseAuthentication.default_user)
        r = client.put(f"{AUTH_URI}/profile", json=data, headers=headers)
        assert r.status_code == 204

        # After a change password a spam of delete Token is expected
        # Reverse the list and skip all delete tokens to find the change password event
        events = self.get_last_events(100)
        events.reverse()
        for event in events:
            if event.event == Events.delete.value:
                assert event.target_type == "Token"
                continue

            assert event.event == Events.change_password.value
            assert event.user == BaseAuthentication.default_user
            break

        # verify the new password
        headers, _ = self.do_login(
            client, BaseAuthentication.default_user, BaseAuthentication.default_password
        )

        self.save("auth_header", headers)

    def test_04_logout(self, client: FlaskClient) -> None:
        """Check that you can logout with a valid token"""

        if not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping logout tests")
            return

        # Check success
        log.info("*** VERIFY valid token")
        r = client.get(f"{AUTH_URI}/logout", headers=self.get("auth_header"))
        assert r.status_code == 204

        events = self.get_last_events(2)

        assert events[0].event == Events.delete.value
        assert events[0].user == "-"
        assert events[0].target_type == "Token"
        assert events[0].url == "/auth/logout"

        assert events[1].event == Events.logout.value
        assert events[1].user == BaseAuthentication.default_user
        assert events[1].url == "/auth/logout"

        # Check failure
        log.info("*** VERIFY invalid token")
        r = client.get(f"{AUTH_URI}/logout")
        assert r.status_code == 401

    def test_05_login_failures(self, client: FlaskClient) -> None:
        if Env.get_bool("MAIN_LOGIN_ENABLE") and Env.get_bool("AUTH_ENABLE"):
            # Create a new user on the fly to test the cached endpoint
            _, data = self.create_user(client)
            headers, _ = self.do_login(
                client, data["email"], data["password"], test_failures=True
            )
            r = client.get(f"{AUTH_URI}/logout", headers=headers)
            assert r.status_code == 204

    def test_06_token_ip_validity(self, client: FlaskClient, faker: Faker) -> None:
        if Env.get_bool("MAIN_LOGIN_ENABLE") and Env.get_bool("AUTH_ENABLE"):
            if Env.get_int("AUTH_TOKEN_IP_GRACE_PERIOD") < 10:
                headers, _ = self.do_login(client, None, None)

                r = client.get(f"{AUTH_URI}/status", headers=headers)
                assert r.status_code == 200

                r = client.get(
                    f"{AUTH_URI}/status",
                    headers=headers,
                    environ_base={"REMOTE_ADDR": faker.ipv4()},
                )
                assert r.status_code == 200

                time.sleep(Env.get_int("AUTH_TOKEN_IP_GRACE_PERIOD"))

                r = client.get(
                    f"{AUTH_URI}/status",
                    headers=headers,
                    environ_base={"REMOTE_ADDR": faker.ipv4()},
                )
                assert r.status_code == 401

                # After the failure the token is still valid if used from the correct IP
                r = client.get(f"{AUTH_URI}/status", headers=headers)
                assert r.status_code == 200

                # Another option to provide IP is through the header passed by nginx
                # This only works if PROXIED_CONNECTION is on
                # (disabled by default, for security purpose)
                if Env.get_bool("PROXIED_CONNECTION"):
                    headers["X-Forwarded-For"] = faker.ipv4()  # type: ignore
                    r = client.get(f"{AUTH_URI}/status", headers=headers)
                    assert r.status_code == 401

    if Env.get_bool("AUTH_SECOND_FACTOR_AUTHENTICATION"):

        def test_07_totp_failures(self, client: FlaskClient, faker: Faker) -> None:
            uuid, data = self.create_user(client)

            username = data["email"]
            password = data["password"]
            new_password = faker.password(strong=True)

            invalid_totp = (
                str(faker.pyint(min_value=0, max_value=9)),
                str(faker.pyint(min_value=10, max_value=99)),
                str(faker.pyint(min_value=100, max_value=999)),
                str(faker.pyint(min_value=1000, max_value=9999)),
                str(faker.pyint(min_value=10000, max_value=99999)),
                str(faker.pyint(min_value=1000000, max_value=9999999)),
                faker.pystr(6),
            )
            ###################################
            # Test first password change
            ###################################

            data = {
                "username": username,
                "password": password,
                "new_password": new_password,
                "password_confirm": new_password,
            }

            r = client.post(f"{AUTH_URI}/login", json=data)
            assert r.status_code == 403
            resp = self.get_content(r)
            assert isinstance(resp, dict)

            assert "actions" in resp
            assert "errors" in resp
            assert "FIRST LOGIN" in resp["actions"]
            assert "TOTP" in resp["actions"]
            assert "Please change your temporary password" in resp["errors"]
            assert "You do not provided a valid verification code" in resp["errors"]

            # validate that the QR code is a valid PNG image
            # ... not implemented

            events = self.get_last_events(1)
            assert events[0].event == Events.password_expired.value
            assert events[0].user == username

            data["totp_code"] = "000000"
            r = client.post(f"{AUTH_URI}/login", json=data)
            assert r.status_code == 401
            assert self.get_content(r) == "Verification code is not valid"

            events = self.get_last_events(1)
            assert events[0].event == Events.failed_login.value
            assert events[0].user == username
            assert "totp" in events[0].payload
            assert events[0].payload["totp"] == OBSCURE_VALUE
            assert events[0].url == "/auth/login"

            for totp in invalid_totp:
                data["totp_code"] = totp
                r = client.post(f"{AUTH_URI}/login", json=data)
                assert r.status_code == 400
                resp = self.get_content(r)
                assert isinstance(resp, dict)
                assert "totp_code" in resp
                assert "Invalid TOTP format" in resp["totp_code"]

            data["totp_code"] = self.generate_totp(username)
            r = client.post(f"{AUTH_URI}/login", json=data)
            assert r.status_code == 200

            events = self.get_last_events(1)
            assert events[0].event == Events.login.value
            assert events[0].user == username
            assert events[0].url == "/auth/login"

            password = new_password

            ###################################
            # Test login
            ###################################

            data = {
                "username": username,
                "password": password,
            }
            r = client.post(f"{AUTH_URI}/login", json=data)
            assert r.status_code == 403
            resp = self.get_content(r)
            assert isinstance(resp, dict)
            assert "actions" in resp
            assert "errors" in resp
            assert "TOTP" in resp["actions"]
            assert "You do not provided a valid verification code" in resp["errors"]

            data["totp_code"] = "000000"
            r = client.post(f"{AUTH_URI}/login", json=data)
            assert r.status_code == 401
            assert self.get_content(r) == "Verification code is not valid"

            events = self.get_last_events(1)
            assert events[0].event == Events.failed_login.value
            assert events[0].user == username
            assert "totp" in events[0].payload
            assert events[0].payload["totp"] == OBSCURE_VALUE
            assert events[0].url == "/auth/login"

            for totp in invalid_totp:
                data["totp_code"] = totp
                r = client.post(f"{AUTH_URI}/login", json=data)
                assert r.status_code == 400
                resp = self.get_content(r)
                assert isinstance(resp, dict)
                assert "totp_code" in resp
                assert "Invalid TOTP format" in resp["totp_code"]

            data["totp_code"] = self.generate_totp(username)
            r = client.post(f"{AUTH_URI}/login", json=data)
            assert r.status_code == 200

            events = self.get_last_events(1)
            assert events[0].event == Events.login.value
            assert events[0].user == username
            assert events[0].url == "/auth/login"

            ###################################
            # Test password change
            ###################################
            new_password = faker.password(strong=True)
            headers, _ = self.do_login(client, username, password)

            data = {
                "password": password,
                "new_password": new_password,
                "password_confirm": new_password,
            }

            r = client.put(f"{AUTH_URI}/profile", json=data, headers=headers)
            assert r.status_code == 401
            assert self.get_content(r) == "Verification code is missing"

            data["totp_code"] = "000000"
            r = client.put(f"{AUTH_URI}/profile", json=data, headers=headers)
            assert r.status_code == 401
            assert self.get_content(r) == "Verification code is not valid"

            events = self.get_last_events(1)
            assert events[0].event == Events.failed_login.value
            assert events[0].user == username
            assert "totp" in events[0].payload
            assert events[0].payload["totp"] == OBSCURE_VALUE
            assert events[0].url == "/auth/profile"

            for totp in invalid_totp:
                data["totp_code"] = totp
                r = client.put(f"{AUTH_URI}/profile", json=data, headers=headers)
                assert r.status_code == 400
                resp = self.get_content(r)
                assert isinstance(resp, dict)
                assert "totp_code" in resp
                assert "Invalid TOTP format" in resp["totp_code"]

            data["totp_code"] = self.generate_totp(username)
            r = client.put(f"{AUTH_URI}/profile", json=data, headers=headers)
            assert r.status_code == 204

            # After a change password a spam of delete Token is expected
            # Reverse the list and skip all delete tokens to find the change pwd event
            events = self.get_last_events(100)
            events.reverse()
            for event in events:
                if event.event == Events.delete.value:
                    assert event.target_type == "Token"
                    continue

                assert event.event == Events.change_password.value
                assert event.user == username
                break

            # verify the new password
            headers, _ = self.do_login(client, username, new_password)

            assert headers is not None

            ###################################
            # Goodbye temporary user
            ###################################

            self.delete_user(client, uuid)
