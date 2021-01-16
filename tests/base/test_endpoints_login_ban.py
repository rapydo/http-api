import time

from faker import Faker

from restapi.config import PRODUCTION
from restapi.env import Env
from restapi.tests import AUTH_URI, BaseTests, FlaskClient
from restapi.utilities.logs import log

max_login_attempts = Env.get_int("AUTH_MAX_LOGIN_ATTEMPTS", 0)
ban_duration = Env.get_int("AUTH_LOGIN_BAN_TIME", 10)

BAN_MESSAGE = (
    "Sorry, this account is temporarily blocked "
    + "due to the number of failed login attempts."
)

if max_login_attempts == 0:

    class TestApp1(BaseTests):
        def test_01_login_ban_not_enabled(self, client: FlaskClient) -> None:

            # Adminer is always enabled during tests
            if Env.get_bool("ADMINER_DISABLED"):  # pragma: no cover
                log.warning("Skipping admin/users tests")
                return

            uuid, data = self.create_user(client)
            # Login attempts are not registered, let's try to fail the login many times
            for i in range(0, 10):
                self.do_login(client, data["email"], "wrong", status_code=401)

            # and verify that login is still allowed
            headers, _ = self.do_login(client, data["email"], data["password"])
            assert headers is not None

            # Goodbye temporary user
            self.delete_user(client, uuid)


else:

    # This test executes a sleep(ban_duration)... this assert is to prevent to
    # block the tests due to a too-long ban duration
    assert ban_duration < 60

    class TestApp2(BaseTests):
        def test_01_failed_login_ban(self, client: FlaskClient) -> None:

            # Adminer is always enabled during tests
            if Env.get_bool("ADMINER_DISABLED"):  # pragma: no cover
                log.warning("Skipping admin/users tests")
                return

            uuid, data = self.create_user(client)

            for i in range(0, max_login_attempts):
                self.do_login(client, data["email"], "wrong", status_code=401)

            # This should fail
            headers, _ = self.do_login(
                client, data["email"], data["password"], status_code=403
            )
            assert headers is None

            reset_data = {"reset_email": data["email"]}
            r = client.post(f"{AUTH_URI}/reset", data=reset_data)
            assert r.status_code == 403
            assert self.get_content(r) == BAN_MESSAGE

            time.sleep(ban_duration)

            headers, _ = self.do_login(client, data["email"], data["password"])
            assert headers is not None

            # Verify that already emitted tokens are not blocked
            # 1) Block again the account
            for i in range(0, max_login_attempts):
                self.do_login(client, data["email"], "wrong", status_code=401)

            # 2) Verify that the account is blocked
            self.do_login(client, data["email"], data["password"], status_code=403)

            # 3) Verify that the previously emitted token is still valid
            r = client.get(f"{AUTH_URI}/status", headers=headers)
            assert r.status_code == 200

            # Goodbye temporary user
            self.delete_user(client, uuid)

        def test_02_registration_and_login_ban(
            self, client: FlaskClient, fake: Faker
        ) -> None:
            if Env.get_bool("ALLOW_REGISTRATION"):

                registration_data = {}
                registration_data["email"] = fake.ascii_email()
                registration_data["name"] = fake.first_name()
                registration_data["surname"] = fake.last_name()
                registration_data["password"] = fake.password(strong=True)
                registration_data["password_confirm"] = registration_data["password"]
                r = client.post(f"{AUTH_URI}/profile", data=registration_data)
                # now the user is created but INACTIVE, activation endpoint is needed
                assert r.status_code == 200
                registration_message = "We are sending an email to your email address "
                registration_message += "where you will find the link to activate "
                registration_message += "your account"
                assert self.get_content(r) == registration_message

                mail = self.read_mock_email()
                body = mail.get("body")
                assert body is not None
                assert mail.get("headers") is not None
                # Subject: is a key in the MIMEText
                proto = "https" if PRODUCTION else "http"
                assert f"{proto}://localhost/public/register/" in body

                token = self.get_token_from_body(body)
                assert token is not None

                # 403 because the account is not activated
                self.do_login(
                    client,
                    registration_data["email"],
                    registration_data["password"],
                    status_code=403,
                    # error='Sorry, this account is not active'
                )
                for i in range(0, max_login_attempts):
                    # Event if non activated if password is wrong the status is 401
                    self.do_login(
                        client,
                        registration_data["email"],
                        "wrong",
                        status_code=401,
                        # error='Sorry, this account is not active'
                    )

                # After max_login_attempts the account is not blocked

                # profile activation forbidden due to blocked acount
                r = client.put(f"{AUTH_URI}/profile/activate/{token}")
                assert r.status_code == 403
                assert self.get_content(r) == BAN_MESSAGE

                # request activation forbidden due to blocked acount
                r = client.post(
                    f"{AUTH_URI}/profile/activate",
                    data={"username": registration_data["email"]},
                )
                assert r.status_code == 403
                assert self.get_content(r) == BAN_MESSAGE

                time.sleep(ban_duration)

                r = client.post(
                    f"{AUTH_URI}/profile/activate",
                    data={"username": registration_data["email"]},
                )
                assert r.status_code == 200