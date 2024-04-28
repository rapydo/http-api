import pytest
from faker import Faker

from restapi.config import PRODUCTION, get_project_configuration
from restapi.env import Env
from restapi.tests import API_URI, AUTH_URI, BaseAuthentication, BaseTests, FlaskClient
from restapi.utilities.logs import OBSCURE_VALUE, Events, log


class TestApp(BaseTests):
    def test_registration(self, client: FlaskClient, faker: Faker) -> None:
        if not Env.get_bool("ALLOW_REGISTRATION") or not Env.get_bool("AUTH_ENABLE"):
            log.warning("User registration is disabled, skipping tests")
            return

        project_tile = get_project_configuration("project.title", default="YourProject")
        proto = "https" if PRODUCTION else "http"

        # registration, empty input
        r = client.post(f"{AUTH_URI}/profile")
        assert r.status_code == 400

        # registration, missing information
        r = client.post(f"{AUTH_URI}/profile", json={"x": "y"})
        assert r.status_code == 400

        # Ensure name and surname longer than 3
        name = self.get_first_name(faker)
        surname = self.get_last_name(faker)
        # Ensure an email not containing name and surname and longer than 3
        email = self.get_random_email(faker, name, surname)

        registration_data = {}
        registration_data["password"] = faker.password(5)
        r = client.post(f"{AUTH_URI}/profile", json=registration_data)
        assert r.status_code == 400

        registration_data["email"] = BaseAuthentication.default_user
        r = client.post(f"{AUTH_URI}/profile", json=registration_data)
        assert r.status_code == 400

        registration_data["name"] = name
        r = client.post(f"{AUTH_URI}/profile", json=registration_data)
        assert r.status_code == 400

        registration_data["surname"] = surname
        r = client.post(f"{AUTH_URI}/profile", json=registration_data)
        assert r.status_code == 400

        registration_data["password_confirm"] = faker.password(strong=True)
        r = client.post(f"{AUTH_URI}/profile", json=registration_data)
        assert r.status_code == 400

        min_pwd_len = Env.get_int("AUTH_MIN_PASSWORD_LENGTH", 9999)

        registration_data["password"] = faker.password(min_pwd_len - 1)
        r = client.post(f"{AUTH_URI}/profile", json=registration_data)
        assert r.status_code == 400

        registration_data["password"] = faker.password(min_pwd_len)
        r = client.post(f"{AUTH_URI}/profile", json=registration_data)
        assert r.status_code == 409
        m = f"This user already exists: {BaseAuthentication.default_user}"
        assert self.get_content(r) == m

        registration_data["email"] = email
        r = client.post(f"{AUTH_URI}/profile", json=registration_data)
        assert r.status_code == 409
        assert self.get_content(r) == "Your password doesn't match the confirmation"

        registration_data["password"] = faker.password(min_pwd_len, low=False, up=True)
        registration_data["password_confirm"] = registration_data["password"]
        r = client.post(f"{AUTH_URI}/profile", json=registration_data)
        assert r.status_code == 409
        m = "Password is too weak, missing lower case letters"
        assert self.get_content(r) == m

        registration_data["password"] = faker.password(min_pwd_len, low=True)
        registration_data["password_confirm"] = registration_data["password"]
        r = client.post(f"{AUTH_URI}/profile", json=registration_data)
        assert r.status_code == 409
        m = "Password is too weak, missing upper case letters"
        assert self.get_content(r) == m

        registration_data["password"] = faker.password(min_pwd_len, low=True, up=True)
        registration_data["password_confirm"] = registration_data["password"]
        r = client.post(f"{AUTH_URI}/profile", json=registration_data)
        assert r.status_code == 409
        m = "Password is too weak, missing numbers"
        assert self.get_content(r) == m

        registration_data["password"] = faker.password(
            min_pwd_len, low=True, up=True, digits=True
        )
        registration_data["password_confirm"] = registration_data["password"]
        r = client.post(f"{AUTH_URI}/profile", json=registration_data)
        assert r.status_code == 409
        m = "Password is too weak, missing special characters"
        assert self.get_content(r) == m

        registration_data["password"] = registration_data["email"].split("@")[0]
        registration_data["password"] += "DEFghi345!"
        registration_data["password_confirm"] = registration_data["password"]
        r = client.post(f"{AUTH_URI}/profile", json=registration_data)
        assert r.status_code == 409
        m = "Password is too weak, can't contain your email address"
        assert self.get_content(r) == m

        registration_data["password"] = registration_data["name"] + "LMNopq678="
        registration_data["password_confirm"] = registration_data["password"]
        r = client.post(f"{AUTH_URI}/profile", json=registration_data)
        assert r.status_code == 409
        m = "Password is too weak, can't contain your name"
        assert self.get_content(r) == m

        registration_data["password"] = registration_data["surname"] + "LMNopq678="
        registration_data["password_confirm"] = registration_data["password"]
        r = client.post(f"{AUTH_URI}/profile", json=registration_data)
        assert r.status_code == 409
        m = "Password is too weak, can't contain your name"
        assert self.get_content(r) == m

        registration_data["password"] = faker.password(strong=True)
        registration_data["password_confirm"] = registration_data["password"]
        r = client.post(f"{AUTH_URI}/profile", json=registration_data)
        # now the user is created but INACTIVE, activation endpoint is needed
        assert r.status_code == 200
        registration_message = "We are sending an email to your email address where "
        registration_message += "you will find the link to activate your account"
        assert self.get_content(r) == registration_message

        events = self.get_last_events(1)
        assert events[0].event == Events.create.value
        assert events[0].user == "-"
        assert events[0].target_type == "User"
        assert "name" in events[0].payload
        assert "password" in events[0].payload
        assert events[0].payload["password"] == OBSCURE_VALUE

        # Last sent email is the registration notification to the admin
        mail = self.read_mock_email()
        body = mail.get("body")
        assert body is not None
        assert mail.get("headers") is not None
        # Subject: is a key in the MIMEText
        assert f"Subject: {project_tile}: New user registered" in mail.get(
            "headers", ""
        )
        assert registration_data["email"] in body

        # Previous sent email is the activation link sent to the user
        mail = self.read_mock_email(previous=True)
        body = mail.get("body")
        assert body is not None
        assert mail.get("headers") is not None
        # Subject: is a key in the MIMEText
        assert f"Subject: {project_tile}: Account activation" in mail.get("headers", "")
        assert f"{proto}://localhost/public/register/" in body

        # This will fail because the user is not active
        _, error = self.do_login(
            client,
            registration_data["email"],
            registration_data["password"],
            status_code=403,
        )
        assert error == "Sorry, this account is not active"

        # Also password reset is not allowed
        data = {"reset_email": registration_data["email"]}
        r = client.post(f"{AUTH_URI}/reset", json=data)
        assert r.status_code == 403
        assert self.get_content(r) == "Sorry, this account is not active"

        events = self.get_last_events(2)
        assert events[0].event == Events.refused_login.value
        assert events[0].payload["username"] == data["reset_email"]
        assert events[0].payload["motivation"] == "account not active"

        assert events[1].event == Events.refused_login.value
        assert events[1].payload["username"] == data["reset_email"]
        assert events[1].payload["motivation"] == "account not active"

        # Activation, missing or wrong information
        r = client.post(f"{AUTH_URI}/profile/activate")
        assert r.status_code == 400
        r = client.post(f"{AUTH_URI}/profile/activate", json=faker.pydict(2))
        assert r.status_code == 400
        # It isn't an email
        invalid = faker.pystr(10)
        r = client.post(f"{AUTH_URI}/profile/activate", json={"username": invalid})
        assert r.status_code == 400

        headers, _ = self.do_login(client, None, None)

        activation_message = "We are sending an email to your email address where "
        activation_message += "you will find the link to activate your account"
        # request activation, wrong username
        r = client.post(
            f"{AUTH_URI}/profile/activate", json={"username": faker.ascii_email()}
        )
        # return is 200, but no token will be generated and no mail will be sent
        # but it respond with the activation msg and hides the non existence of the user
        assert r.status_code == 200
        assert self.get_content(r) == activation_message

        events = self.get_last_events(1)
        assert events[0].event != Events.activation.value
        assert events[0].url == "/auth/login"

        with pytest.raises(FileNotFoundError):
            self.read_mock_email()

        # request activation, correct username
        r = client.post(
            f"{AUTH_URI}/profile/activate",
            json={"username": registration_data["email"]},
        )
        assert r.status_code == 200
        assert self.get_content(r) == activation_message

        mail = self.read_mock_email()
        body = mail.get("body")
        assert body is not None
        assert mail.get("headers") is not None
        # Subject: is a key in the MIMEText
        assert f"Subject: {project_tile}: Account activation" in mail.get("headers", "")
        assert f"{proto}://localhost/public/register/" in body

        token = self.get_token_from_body(body)
        assert token is not None

        # profile activation
        r = client.put(f"{AUTH_URI}/profile/activate/thisisatoken")
        # this token is not valid
        assert r.status_code == 400

        # profile activation
        r = client.put(f"{AUTH_URI}/profile/activate/{token}")
        assert r.status_code == 200
        assert self.get_content(r) == "Account activated"

        events = self.get_last_events(1)
        assert events[0].event == Events.activation.value
        assert events[0].user == registration_data["email"]
        assert events[0].target_type == "User"
        assert events[0].url == f"/auth/profile/activate/{token}"

        # Activation token is no longer valid
        r = client.put(f"{AUTH_URI}/profile/activate/{token}")
        assert r.status_code == 400
        assert self.get_content(r) == "Invalid activation token"

        # Token created for another user
        token = self.get_crafted_token("a")
        r = client.put(f"{AUTH_URI}/profile/activate/{token}")
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == "Invalid activation token"

        # Token created for another user
        token = self.get_crafted_token("a", wrong_algorithm=True)
        r = client.put(f"{AUTH_URI}/profile/activate/{token}")
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == "Invalid activation token"

        # Token created for another user
        token = self.get_crafted_token("a", wrong_secret=True)
        r = client.put(f"{AUTH_URI}/profile/activate/{token}")
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == "Invalid activation token"

        headers, _ = self.do_login(client, None, None)
        r = client.get(f"{AUTH_URI}/profile", headers=headers)
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, dict)
        uuid = content.get("uuid")

        token = self.get_crafted_token("x", user_id=uuid)
        r = client.put(f"{AUTH_URI}/profile/activate/{token}")
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == "Invalid activation token"

        # token created for the correct user, but from outside the system!!
        token = self.get_crafted_token("a", user_id=uuid)
        r = client.put(f"{AUTH_URI}/profile/activate/{token}")
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == "Invalid activation token"

        # Immature token
        token = self.get_crafted_token("a", user_id=uuid, immature=True)
        r = client.put(f"{AUTH_URI}/profile/activate/{token}")
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == "Invalid activation token"

        # Expired token
        token = self.get_crafted_token("a", user_id=uuid, expired=True)
        r = client.put(f"{AUTH_URI}/profile/activate/{token}")
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == "Invalid activation token: this request is expired"

        # Testing the following use case:
        # 1 - user registration
        # 2 - user activation using unconventional channel, e.g. by admins
        # 3 - user tries to activate and fails because already active

        registration_data["email"] = faker.ascii_email()
        r = client.post(f"{AUTH_URI}/profile", json=registration_data)
        # now the user is created but INACTIVE, activation endpoint is needed
        assert r.status_code == 200

        # Registration endpoint send 2 mail: the first is the activation link,
        # the second (last) is the admin notification
        mail = self.read_mock_email(previous=True)
        body = mail.get("body")
        assert body is not None
        assert mail.get("headers") is not None
        assert f"{proto}://localhost/public/register/" in body

        token = self.get_token_from_body(body)
        assert token is not None

        headers, _ = self.do_login(client, None, None)

        r = client.get(f"{API_URI}/admin/users", headers=headers)
        assert r.status_code == 200
        users = self.get_content(r)
        assert isinstance(users, list)
        uuid = None
        for u in users:
            if u.get("email") == registration_data["email"]:
                uuid = u.get("uuid")
                break

        assert uuid is not None
        r = client.put(
            f"{API_URI}/admin/users/{uuid}", json={"is_active": True}, headers=headers
        )
        assert r.status_code == 204

        r = client.put(f"{AUTH_URI}/profile/activate/{token}")
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == "Invalid activation token: this request is no longer valid"

        r = client.get(f"{API_URI}/admin/tokens", headers=headers)
        content = self.get_content(r)
        assert isinstance(content, list)

        for t in content:
            if t.get("token") == token:  # pragma: no cover
                pytest.fail(
                    "Token not properly invalidated, still bount to user {}", t.get(id)
                )
