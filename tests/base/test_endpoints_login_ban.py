import time

from faker import Faker

from restapi.config import PRODUCTION, get_project_configuration
from restapi.env import Env
from restapi.services.authentication import BaseAuthentication
from restapi.tests import AUTH_URI, BaseTests, FlaskClient
from restapi.utilities.logs import OBSCURE_VALUE, Events, log

max_login_attempts = BaseAuthentication.MAX_LOGIN_ATTEMPTS
ban_duration = Env.get_int("AUTH_LOGIN_BAN_TIME", 10)

BAN_MESSAGE = (
    "Sorry, this account is temporarily blocked "
    + "due to the number of failed login attempts."
)


if max_login_attempts == 0:

    class TestApp1(BaseTests):
        def test_01_login_ban_not_enabled(self, client: FlaskClient) -> None:

            if not Env.get_bool("MAIN_LOGIN_ENABLE"):  # pragma: no cover
                log.warning("Skipping admin/users tests")
                return

            uuid, data = self.create_user(client)
            # Login attempts are not registered, let's try to fail the login many times
            for _ in range(0, 10):
                self.do_login(client, data["email"], "wrong", status_code=401)

            events = self.get_last_events(1)
            assert events[0].event == Events.failed_login.value
            assert events[0].payload["username"] == data["email"]

            # and verify that login is still allowed
            headers, _ = self.do_login(client, data["email"], data["password"])
            assert headers is not None

            events = self.get_last_events(1)
            assert events[0].event == Events.login.value
            assert events[0].user == data["email"]

            # Goodbye temporary user
            self.delete_user(client, uuid)


else:

    # This test executes a sleep(ban_duration)... this assert is to prevent to
    # block the tests due to a too-long ban duration
    assert ban_duration < 60

    class TestApp2(BaseTests):
        def verify_credentials_ban_notification(self) -> None:

            # Verify email sent to notify credentials block
            mail = self.read_mock_email()
            body = mail.get("body")
            project_tile = get_project_configuration(
                "project.title", default="YourProject"
            )

            assert body is not None
            assert mail.get("headers") is not None
            title = "Your credentials have been blocked"
            assert f"Subject: {project_tile}: {title}" in mail.get("headers")
            # Body can't be asserted if can be changed at project level...
            # assert "this email is to inform you that your credentials have been "
            # "temporarily due to the number of failed login attempts" in body
            # assert "inspect the list below to detect any unwanted login" in body
            # assert "Your credentials will be automatically unlocked in" in body

        def test_01_failed_login_ban(self, client: FlaskClient) -> None:

            if not Env.get_bool("MAIN_LOGIN_ENABLE"):  # pragma: no cover
                log.warning("Skipping admin/users tests")
                return

            uuid, data = self.create_user(client)

            self.delete_mock_email()

            for _ in range(0, max_login_attempts):
                self.do_login(client, data["email"], "wrong", status_code=401)

            events = self.get_last_events(1)
            assert events[0].event == Events.failed_login.value
            assert events[0].payload["username"] == data["email"]

            self.verify_credentials_ban_notification()

            # This should fail
            headers, _ = self.do_login(
                client, data["email"], data["password"], status_code=403
            )
            assert headers is None

            events = self.get_last_events(1)
            assert events[0].event == Events.refused_login.value
            assert events[0].payload["username"] == data["email"]
            assert (
                events[0].payload["motivation"]
                == "account blocked due to too many failed logins"
            )

            reset_data = {"reset_email": data["email"]}
            r = client.post(f"{AUTH_URI}/reset", data=reset_data)
            assert r.status_code == 403
            assert self.get_content(r) == BAN_MESSAGE

            events = self.get_last_events(1)
            assert events[0].event == Events.refused_login.value
            assert events[0].payload["username"] == data["email"]
            assert (
                events[0].payload["motivation"]
                == "account blocked due to too many failed logins"
            )

            time.sleep(ban_duration)

            headers, _ = self.do_login(client, data["email"], data["password"])
            assert headers is not None

            events = self.get_last_events(1)
            assert events[0].event == Events.login.value
            assert events[0].user == data["email"]

            # Verify that already emitted tokens are not blocked
            # 1) Block again the account
            for _ in range(0, max_login_attempts):
                self.do_login(client, data["email"], "wrong", status_code=401)

            # 2) Verify that the account is blocked
            self.do_login(client, data["email"], data["password"], status_code=403)

            # 3) Verify that the previously emitted token is still valid
            r = client.get(f"{AUTH_URI}/status", headers=headers)
            assert r.status_code == 200

            # Goodbye temporary user
            self.delete_user(client, uuid)

        def test_02_registration_and_login_ban(
            self, client: FlaskClient, faker: Faker
        ) -> None:
            if Env.get_bool("ALLOW_REGISTRATION"):

                registration_data = {}
                registration_data["email"] = faker.ascii_email()
                registration_data["name"] = faker.first_name()
                registration_data["surname"] = faker.last_name()
                registration_data["password"] = faker.password(strong=True)
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
                )

                events = self.get_last_events(1)
                assert events[0].event == Events.refused_login.value
                assert events[0].payload["username"] == registration_data["email"]
                assert events[0].payload["motivation"] == "account not active"

                self.delete_mock_email()

                for _ in range(0, max_login_attempts):
                    # Event if non activated if password is wrong the status is 401
                    self.do_login(
                        client,
                        registration_data["email"],
                        "wrong",
                        status_code=401,
                    )

                events = self.get_last_events(1)
                assert events[0].event == Events.failed_login.value
                assert events[0].payload["username"] == registration_data["email"]

                self.verify_credentials_ban_notification()

                # After max_login_attempts the account is not blocked

                # profile activation forbidden due to blocked acount
                r = client.put(f"{AUTH_URI}/profile/activate/{token}")
                assert r.status_code == 403
                assert self.get_content(r) == BAN_MESSAGE

                events = self.get_last_events(1)
                assert events[0].event == Events.refused_login.value
                assert events[0].payload["username"] == registration_data["email"]
                assert (
                    events[0].payload["motivation"]
                    == "account blocked due to too many failed logins"
                )

                # request activation forbidden due to blocked acount
                r = client.post(
                    f"{AUTH_URI}/profile/activate",
                    data={"username": registration_data["email"]},
                )
                assert r.status_code == 403
                assert self.get_content(r) == BAN_MESSAGE

                events = self.get_last_events(1)
                assert events[0].event == Events.refused_login.value
                assert events[0].payload["username"] == registration_data["email"]
                assert (
                    events[0].payload["motivation"]
                    == "account blocked due to too many failed logins"
                )

                time.sleep(ban_duration)

                r = client.post(
                    f"{AUTH_URI}/profile/activate",
                    data={"username": registration_data["email"]},
                )
                assert r.status_code == 200

        if Env.get_bool("AUTH_SECOND_FACTOR_AUTHENTICATION"):

            def test_03_totp_and_login_ban(self, client: FlaskClient) -> None:

                uuid, data = self.create_user(client)

                # Verify that login still works (TOTP will be automatically added)
                headers, _ = self.do_login(client, data["email"], data["password"])
                assert headers is not None

                # Verify that TOTP is required
                headers, _ = self.do_login(
                    client, data["email"], data["password"], status_code=403
                )
                assert headers is None

                # Verify that wrong totp are refused
                headers, _ = self.do_login(
                    client,
                    data["email"],
                    data["password"],
                    data={"totp_code": "000000"},
                    status_code=401,
                )
                assert headers is not None

                # Verify that correct totp are accepted
                headers, _ = self.do_login(
                    client,
                    data["email"],
                    data["password"],
                    data={"totp_code": self.generate_totp(data["email"])},
                )
                assert headers is not None

                # Verify login ban due to wrong TOTPs

                self.delete_mock_email()

                for _ in range(0, max_login_attempts):
                    self.do_login(
                        client,
                        data["email"],
                        data["password"],
                        data={"totp_code": "000000"},
                        status_code=401,
                    )

                events = self.get_last_events(1)
                assert events[0].event == Events.failed_login.value
                assert "username" not in events[0].payload
                assert "totp" in events[0].payload
                assert events[0].payload["totp"] == OBSCURE_VALUE

                self.verify_credentials_ban_notification()

                # Now the login is blocked
                headers, _ = self.do_login(
                    client, data["email"], data["password"], status_code=403
                )
                assert headers is None

                events = self.get_last_events(1)
                assert events[0].event == Events.refused_login.value
                assert events[0].payload["username"] == data["email"]
                assert (
                    events[0].payload["motivation"]
                    == "account blocked due to too many failed logins"
                )

                time.sleep(ban_duration)

                # Now the login works again
                headers, _ = self.do_login(client, data["email"], data["password"])
                assert headers is not None

                events = self.get_last_events(1)
                assert events[0].event == Events.login.value
                assert events[0].user == data["email"]

                # Goodbye temporary user
                self.delete_user(client, uuid)

        def test_04_no_notification_email_for_wrong_usernames(
            self, client: FlaskClient, faker: Faker
        ) -> None:

            if not Env.get_bool("MAIN_LOGIN_ENABLE"):  # pragma: no cover
                log.warning("Skipping admin/users tests")
                return

            uuid, data = self.create_user(client)

            self.delete_mock_email()

            # Just to verify that email is deleted
            mail = self.read_mock_email()
            assert mail is None

            email = faker.ascii_email()
            # Wrong credentials with a non existing email
            # -> No notification will be sent
            for _ in range(0, max_login_attempts):
                self.do_login(client, email, data["password"], status_code=401)

            # Verify the ban (i.e. status 403)
            headers, _ = self.do_login(client, email, data["password"], status_code=403)
            assert headers is None

            # Verify that there are no mocked email
            mail = self.read_mock_email()
            assert mail is None

            # Goodbye temporary user
            self.delete_user(client, uuid)
