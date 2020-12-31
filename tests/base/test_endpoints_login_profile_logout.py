import base64
import time

from restapi.env import Env
from restapi.tests import AUTH_URI, BaseAuthentication, BaseTests
from restapi.utilities.logs import log


class TestApp(BaseTests):
    def test_01_login(self, client, fake):
        """ Check that you can login and receive back your token """

        log.info("*** VERIFY CASE INSENSITIVE LOGIN")
        BaseAuthentication.load_default_user()
        BaseAuthentication.load_roles()
        USER = BaseAuthentication.default_user or "just-to-prevent-None"
        PWD = BaseAuthentication.default_password or "just-to-prevent-None"
        self.do_login(client, USER.upper(), PWD)

        # Off course PWD cannot be upper :D
        self.do_login(client, USER, PWD.upper(), status_code=401)

        log.info("*** VERIFY valid credentials")
        headers, _ = self.do_login(client, None, None)

        time.sleep(5)
        # Verify MAX_PASSWORD_VALIDITY, if set
        headers, token = self.do_login(client, None, None)

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

        self.do_login(
            client,
            fake.ascii_email(),
            fake.password(strong=True),
            status_code=401,
        )

    def test_02_GET_profile(self, client, fake):
        """ Check if you can use your token for protected endpoints """

        # Check success
        log.info("*** VERIFY valid token")
        r = client.get(f"{AUTH_URI}/profile", headers=self.get("auth_header"))
        assert r.status_code == 200
        uuid = self.get_content(r).get("uuid")

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

        headers = {"Authorization": f"Bearer '{fake.pystr()}"}
        r = client.get(f"{AUTH_URI}/status", headers=headers)
        assert r.status_code == 401

        # Bearer realm is expected to be case sensitive
        token = self.get("auth_token")
        headers = {"Authorization": f"Bearer {token}"}
        r = client.get(f"{AUTH_URI}/status", headers=headers)
        assert r.status_code == 200

        headers = {"Authorization": f"bearer {token}"}
        r = client.get(f"{AUTH_URI}/status", headers=headers)
        assert r.status_code == 401

        headers = {"Authorization": f"BEARER {token}"}
        r = client.get(f"{AUTH_URI}/status", headers=headers)
        assert r.status_code == 401

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

    def test_03_change_profile(self, client, fake):

        # Always enable during core tests
        if not Env.get_bool("MAIN_LOGIN_ENABLE"):  # pragma: no cover
            log.warning("Profile is disabled, skipping tests")
            return True

        headers, _ = self.do_login(client, None, None)

        # update profile, no auth
        r = client.put(f"{AUTH_URI}/profile")
        assert r.status_code == 401
        # update profile, no auth
        r = client.patch(f"{AUTH_URI}/profile")
        assert r.status_code == 401

        # update profile, no data
        r = client.patch(f"{AUTH_URI}/profile", data={}, headers=headers)
        assert r.status_code == 204

        newname = fake.name()
        newuuid = fake.pystr()

        r = client.get(f"{AUTH_URI}/profile", headers=headers)
        assert r.status_code == 200
        c = self.get_content(r)
        assert c.get("name") is not None
        assert c.get("name") != newname
        assert c.get("uuid") is not None
        assert c.get("uuid") != newuuid

        # update profile
        data = {"name": newname, "uuid": newuuid}
        r = client.patch(f"{AUTH_URI}/profile", data=data, headers=headers)
        # uuid cannot be modified and will raise an unknown field
        assert r.status_code == 400
        data = {"name": newname}
        r = client.patch(f"{AUTH_URI}/profile", data=data, headers=headers)
        assert r.status_code == 204

        r = client.get(f"{AUTH_URI}/profile", headers=headers)
        assert r.status_code == 200
        c = self.get_content(r)
        assert c.get("name") == newname
        assert c.get("uuid") != newuuid

        # change password, no data
        r = client.put(f"{AUTH_URI}/profile", data={}, headers=headers)
        assert r.status_code == 400
        # Sending a new_password and/or password_confirm without a password
        newpassword = fake.password()
        data = {"new_password": newpassword}
        r = client.put(f"{AUTH_URI}/profile", data=data, headers=headers)
        assert r.status_code == 400
        data = {"password_confirm": newpassword}
        r = client.put(f"{AUTH_URI}/profile", data=data, headers=headers)
        assert r.status_code == 400
        data = {"new_password": newpassword, "password_confirm": newpassword}
        r = client.put(f"{AUTH_URI}/profile", data=data, headers=headers)
        assert r.status_code == 400

        data = {}
        data["password"] = fake.password(length=5)
        r = client.put(f"{AUTH_URI}/profile", data=data, headers=headers)
        assert r.status_code == 400

        data["new_password"] = fake.password(length=5)
        r = client.put(f"{AUTH_URI}/profile", data=data, headers=headers)
        assert r.status_code == 400

        data["password_confirm"] = fake.password(length=5)
        r = client.put(f"{AUTH_URI}/profile", data=data, headers=headers)
        assert r.status_code == 400

        data["password"] = BaseAuthentication.default_password
        r = client.put(f"{AUTH_URI}/profile", data=data, headers=headers)
        assert r.status_code == 400

        # Passwords are too short
        data["password_confirm"] = data["new_password"]
        r = client.put(f"{AUTH_URI}/profile", data=data, headers=headers)
        assert r.status_code == 400

        # Trying to set new password == password... it is not permitted!
        data["password_confirm"] = data["password"]
        data["new_password"] = data["password"]

        if BaseTests.TOTP:
            data["totp_code"] = BaseTests.generate_totp(BaseAuthentication.default_user)

        r = client.put(f"{AUTH_URI}/profile", data=data, headers=headers)
        assert r.status_code == 409

        # Change the password
        data["new_password"] = fake.password(strong=True)
        data["password_confirm"] = data["new_password"]
        r = client.put(f"{AUTH_URI}/profile", data=data, headers=headers)
        assert r.status_code == 204

        # verify the new password
        headers, _ = self.do_login(
            client, BaseAuthentication.default_user, data["new_password"]
        )

        # restore the previous password
        data["password"] = data["new_password"]
        data["new_password"] = BaseAuthentication.default_password
        data["password_confirm"] = BaseAuthentication.default_password
        if BaseTests.TOTP:
            data["totp_code"] = BaseTests.generate_totp(BaseAuthentication.default_user)
        r = client.put(f"{AUTH_URI}/profile", data=data, headers=headers)
        assert r.status_code == 204

        # verify the new password
        headers, _ = self.do_login(
            client, BaseAuthentication.default_user, BaseAuthentication.default_password
        )

        self.save("auth_header", headers)

    def test_04_logout(self, client):
        """ Check that you can logout with a valid token """

        # Check success
        log.info("*** VERIFY valid token")
        r = client.get(f"{AUTH_URI}/logout", headers=self.get("auth_header"))
        assert r.status_code == 204

        # Check failure
        log.info("*** VERIFY invalid token")
        r = client.get(f"{AUTH_URI}/logout")
        assert r.status_code == 401

    def test_05_failed_login(self, client):
        uuid, data = self.create_user(client)

        max_login_attempts = Env.get_int("AUTH_MAX_LOGIN_ATTEMPTS", 0)

        if max_login_attempts == 0:

            # Login attempts are not registered, let's try to fail the login many times
            for i in range(0, 10):
                self.do_login(client, data["email"], "wrong", status_code=401)

            # and verify that login is still allowed
            headers, _ = self.do_login(client, data["email"], data["password"])
            assert headers is not None

            # Goodbye temporary user
            self.delete_user(client, uuid)
            return

        for i in range(0, max_login_attempts):
            self.do_login(client, data["email"], "wrong", status_code=401)

        # This should fail
        headers, _ = self.do_login(
            client, data["email"], data["password"], status_code=403
        )
        assert headers is None

        # verify that the account is blocked for any other event like:
        #   - reset
        #   - activation

        time.sleep(10)

        headers, _ = self.do_login(client, data["email"], data["password"])
        assert headers is not None

        # Verify that already emitted tokens are not blocked, block again the account
        for i in range(0, max_login_attempts):
            self.do_login(client, data["email"], "wrong", status_code=401)

        # Verify that the account is blocked
        self.do_login(client, data["email"], data["password"], status_code=403)

        # Verify that the previously emitted token is still valid
        r = client.get(f"{AUTH_URI}/status", headers=headers)
        assert r.status_code == 200

        # Goodbye temporary user
        self.delete_user(client, uuid)
