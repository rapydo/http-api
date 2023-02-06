from faker import Faker

from restapi.config import PRODUCTION, get_project_configuration
from restapi.env import Env
from restapi.tests import AUTH_URI, BaseAuthentication, BaseTests, FlaskClient
from restapi.utilities.logs import Events, log


class TestApp(BaseTests):
    def test_password_reset(self, client: FlaskClient, faker: Faker) -> None:
        if not Env.get_bool("ALLOW_PASSWORD_RESET") or not Env.get_bool("AUTH_ENABLE"):
            log.warning("Password reset is disabled, skipping tests")
            return

        project_tile = get_project_configuration("project.title", default="YourProject")
        proto = "https" if PRODUCTION else "http"

        # Request password reset, missing information
        r = client.post(f"{AUTH_URI}/reset")
        assert r.status_code == 400

        # Request password reset, missing information
        r = client.post(f"{AUTH_URI}/reset", json=faker.pydict(2))
        assert r.status_code == 400

        headers, _ = self.do_login(client, None, None)

        # Request password reset, wrong email
        wrong_email = faker.ascii_email()
        data = {"reset_email": wrong_email}
        r = client.post(f"{AUTH_URI}/reset", json=data)
        assert r.status_code == 403
        msg = f"Sorry, {wrong_email} is not recognized as a valid username"
        assert self.get_content(r) == msg

        # Request password reset, correct email
        data = {"reset_email": BaseAuthentication.default_user}
        r = client.post(f"{AUTH_URI}/reset", json=data)
        assert r.status_code == 200

        events = self.get_last_events(1)
        assert events[0].event == Events.reset_password_request.value
        assert events[0].user == data["reset_email"]
        assert events[0].url == "/auth/reset"

        resetmsg = "We'll send instructions to the email provided "
        resetmsg += "if it's associated with an account. "
        resetmsg += "Please check your spam/junk folder."

        assert self.get_content(r) == resetmsg

        mail = self.read_mock_email()
        body = mail.get("body")
        assert body is not None
        assert mail.get("headers") is not None
        # Subject: is a key in the MIMEText
        assert f"Subject: {project_tile}: Password Reset" in mail.get("headers", "")
        assert f"{proto}://localhost/public/reset/" in body

        token = self.get_token_from_body(body)
        assert token is not None

        # Do password reset
        r = client.put(f"{AUTH_URI}/reset/thisisatoken", json={})
        # this token is not valid
        assert r.status_code == 400

        # Check if token is valid
        r = client.put(f"{AUTH_URI}/reset/{token}", json={})
        assert r.status_code == 204

        # Token is still valid because no password still sent
        r = client.put(f"{AUTH_URI}/reset/{token}", json={})
        assert r.status_code == 204

        # Missing information
        data = {
            "new_password": BaseAuthentication.default_password,
        }
        r = client.put(f"{AUTH_URI}/reset/{token}", json=data)
        assert r.status_code == 400
        assert self.get_content(r) == "Invalid password"

        data = {
            "password_confirm": BaseAuthentication.default_password,
        }
        r = client.put(f"{AUTH_URI}/reset/{token}", json=data)
        assert r.status_code == 400
        assert self.get_content(r) == "Invalid password"

        # Request with old password
        data = {
            "new_password": BaseAuthentication.default_password,
            "password_confirm": BaseAuthentication.default_password,
        }
        r = client.put(f"{AUTH_URI}/reset/{token}", json=data)
        assert r.status_code == 409
        error = "The new password cannot match the previous password"
        assert self.get_content(r) == error

        min_pwd_len = Env.get_int("AUTH_MIN_PASSWORD_LENGTH", 9999)

        # Password too short
        data["new_password"] = faker.password(min_pwd_len - 1)
        data["password_confirm"] = faker.password(min_pwd_len - 1)
        r = client.put(f"{AUTH_URI}/reset/{token}", json=data)
        assert r.status_code == 400
        data["password_confirm"] = data["new_password"]
        r = client.put(f"{AUTH_URI}/reset/{token}", json=data)
        assert r.status_code == 400

        data["new_password"] = faker.password(min_pwd_len, strong=True)
        data["password_confirm"] = faker.password(min_pwd_len, strong=True)
        r = client.put(f"{AUTH_URI}/reset/{token}", json=data)
        assert r.status_code == 400
        assert self.get_content(r) == "New password does not match with confirmation"

        new_pwd = faker.password(min_pwd_len, strong=True)
        data["new_password"] = new_pwd
        data["password_confirm"] = new_pwd
        r = client.put(f"{AUTH_URI}/reset/{token}", json=data)
        assert r.status_code == 200

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

        self.do_login(client, None, None, status_code=401)
        headers, _ = self.do_login(client, None, new_pwd)

        # Token is no longer valid
        r = client.put(f"{AUTH_URI}/reset/{token}", json={})
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == "Invalid reset token"

        # Restore the default password
        if Env.get_bool("AUTH_SECOND_FACTOR_AUTHENTICATION"):
            data["totp_code"] = BaseTests.generate_totp(BaseAuthentication.default_user)

        data["password"] = new_pwd
        data["new_password"] = BaseAuthentication.default_password
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

        self.do_login(client, None, new_pwd, status_code=401)
        self.do_login(client, None, None)

        # Token created for another user
        token = self.get_crafted_token("r")
        r = client.put(f"{AUTH_URI}/reset/{token}", json={})
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == "Invalid reset token"

        # Token created for another user
        token = self.get_crafted_token("r", wrong_algorithm=True)
        r = client.put(f"{AUTH_URI}/reset/{token}", json={})
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == "Invalid reset token"

        # Token created for another user
        token = self.get_crafted_token("r", wrong_secret=True)
        r = client.put(f"{AUTH_URI}/reset/{token}", json={})
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == "Invalid reset token"

        headers, _ = self.do_login(client, None, None)
        r = client.get(f"{AUTH_URI}/profile", headers=headers)
        assert r.status_code == 200
        response = self.get_content(r)
        assert isinstance(response, dict)
        uuid = response.get("uuid")

        token = self.get_crafted_token("x", user_id=uuid)
        r = client.put(f"{AUTH_URI}/reset/{token}", json={})
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == "Invalid reset token"

        # token created for the correct user, but from outside the system!!
        token = self.get_crafted_token("r", user_id=uuid)
        r = client.put(f"{AUTH_URI}/reset/{token}", json={})
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == "Invalid reset token"

        # Immature token
        token = self.get_crafted_token("r", user_id=uuid, immature=True)
        r = client.put(f"{AUTH_URI}/reset/{token}", json={})
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == "Invalid reset token"

        # Expired token
        token = self.get_crafted_token("r", user_id=uuid, expired=True)
        r = client.put(f"{AUTH_URI}/reset/{token}", json={})
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == "Invalid reset token: this request is expired"
