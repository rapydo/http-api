import json

from faker import Faker

from restapi.config import get_project_configuration
from restapi.env import Env
from restapi.services.authentication import BaseAuthentication
from restapi.tests import API_URI, AUTH_URI, BaseTests, FlaskClient
from restapi.utilities.logs import OBSCURE_VALUE, Events, log


class TestApp(BaseTests):
    def test_admin_users(self, client: FlaskClient, faker: Faker) -> None:

        if not Env.get_bool("MAIN_LOGIN_ENABLE"):  # pragma: no cover
            log.warning("Skipping admin/users tests")
            return

        project_tile = get_project_configuration("project.title", default="YourProject")

        headers, _ = self.do_login(client, None, None)
        r = client.get(f"{API_URI}/admin/users", headers=headers)
        assert r.status_code == 200

        schema = self.getDynamicInputSchema(client, "admin/users", headers)
        data = self.buildData(schema)
        data["email_notification"] = True
        data["is_active"] = True
        data["expiration"] = None

        # Event 1: create
        r = client.post(f"{API_URI}/admin/users", data=data, headers=headers)
        assert r.status_code == 200
        uuid = self.get_content(r)

        mail = self.read_mock_email()
        # Subject: is a key in the MIMEText
        assert mail.get("body") is not None
        assert mail.get("headers") is not None
        assert f"Subject: {project_tile}: new credentials" in mail.get("headers")
        assert f"Username: {data.get('email', 'MISSING').lower()}" in mail.get("body")
        assert f"Password: {data.get('password')}" in mail.get("body")

        r = client.get(f"{API_URI}/admin/users/{uuid}", headers=headers)
        assert r.status_code == 200
        users_list = self.get_content(r)
        assert len(users_list) > 0
        # email is saved lowercase
        assert users_list[0].get("email") == data.get("email", "MISSING").lower()

        # Check duplicates
        r = client.post(f"{API_URI}/admin/users", data=data, headers=headers)
        assert r.status_code == 409

        # Create another user
        data2 = self.buildData(schema)
        data2["email_notification"] = True
        data2["is_active"] = True
        data2["expiration"] = None

        # Event 2: create
        r = client.post(f"{API_URI}/admin/users", data=data2, headers=headers)
        assert r.status_code == 200
        uuid2 = self.get_content(r)

        mail = self.read_mock_email()
        # Subject: is a key in the MIMEText
        assert mail.get("body") is not None
        assert mail.get("headers") is not None
        assert f"Subject: {project_tile}: new credentials" in mail.get("headers")
        assert f"Username: {data2.get('email', 'MISSING').lower()}" in mail.get("body")
        assert f"Password: {data2.get('password')}" in mail.get("body")

        # send and invalid user_id
        r = client.put(
            f"{API_URI}/admin/users/invalid",
            data={"name": faker.name()},
            headers=headers,
        )
        assert r.status_code == 404

        # Event 3: modify
        r = client.put(
            f"{API_URI}/admin/users/{uuid}",
            data={"name": faker.name()},
            headers=headers,
        )
        assert r.status_code == 204

        # email cannot be modified
        new_data = {"email": data.get("email")}
        r = client.put(f"{API_URI}/admin/users/{uuid2}", data=new_data, headers=headers)
        # from webargs >= 6 this endpoint no longer return a 204 but a 400
        # because email is an unknown field
        # assert r.status_code == 204
        assert r.status_code == 400

        r = client.get(f"{API_URI}/admin/users/{uuid2}", headers=headers)
        assert r.status_code == 200
        users_list = self.get_content(r)
        assert len(users_list) > 0
        # email is not modified -> still equal to data2, not data1
        assert users_list[0].get("email") != data.get("email", "MISSING").lower()
        assert users_list[0].get("email") == data2.get("email", "MISSING").lower()

        r = client.delete(f"{API_URI}/admin/users/invalid", headers=headers)
        assert r.status_code == 404

        # Event 4: delete
        r = client.delete(f"{API_URI}/admin/users/{uuid}", headers=headers)
        assert r.status_code == 204

        r = client.get(f"{API_URI}/admin/users/{uuid}", headers=headers)
        assert r.status_code == 404

        # change password of user2
        # Event 5: modify
        newpwd = faker.password(strong=True)
        data = {"password": newpwd, "email_notification": True}
        r = client.put(f"{API_URI}/admin/users/{uuid2}", data=data, headers=headers)
        assert r.status_code == 204

        mail = self.read_mock_email()
        # Subject: is a key in the MIMEText
        assert mail.get("body") is not None
        assert mail.get("headers") is not None
        assert f"Subject: {project_tile}: password changed" in mail.get("headers")
        assert f"Username: {data2.get('email', 'MISSING').lower()}" in mail.get("body")
        assert f"Password: {newpwd}" in mail.get("body")

        # login with a newly created user
        headers2, _ = self.do_login(client, data2.get("email"), newpwd)

        # normal users cannot access to this endpoint
        r = client.get(f"{API_URI}/admin/users", headers=headers2)
        assert r.status_code == 401

        r = client.get(f"{API_URI}/admin/users/{uuid}", headers=headers2)
        assert r.status_code == 401

        r = client.post(f"{API_URI}/admin/users", data=data, headers=headers2)
        assert r.status_code == 401

        r = client.put(
            f"{API_URI}/admin/users/{uuid}",
            data={"name": faker.name()},
            headers=headers2,
        )
        assert r.status_code == 401

        r = client.delete(f"{API_URI}/admin/users/{uuid}", headers=headers2)
        assert r.status_code == 401

        # Users are not authorized to /admin/tokens
        # These two tests should be moved in test_endpoints_tokens.py
        r = client.get(f"{API_URI}/admin/tokens", headers=headers2)
        assert r.status_code == 401
        r = client.delete(f"{API_URI}/admin/tokens/xyz", headers=headers2)
        assert r.status_code == 401

        # let's delete the second user
        # Event 6: delete
        r = client.delete(f"{API_URI}/admin/users/{uuid2}", headers=headers)
        assert r.status_code == 204

        # Restore the default password, if it changed due to FORCE_FIRST_PASSWORD_CHANGE
        # or MAX_PASSWORD_VALIDITY errors
        r = client.get(f"{AUTH_URI}/profile", headers=headers)
        assert r.status_code == 200
        uuid = self.get_content(r).get("uuid")

        data = {
            "password": BaseAuthentication.default_password,
            # very important, otherwise the default user will lose its admin role
            "roles": json.dumps(["admin_root"]),
        }
        # Event 7: modify
        r = client.put(f"{API_URI}/admin/users/{uuid}", data=data, headers=headers)
        assert r.status_code == 204

        r = client.get(f"{AUTH_URI}/logout", headers=headers)
        assert r.status_code == 204

    def test_events_file(self):

        events = self.get_last_events(7, filters={"target_type": "User"})

        # A new User is created
        INDEX = 0
        assert events[INDEX].event == Events.create.value
        assert events[INDEX].user == BaseAuthentication.default_user
        assert events[INDEX].target_type == "User"
        assert "name" in events[INDEX].payload
        assert "surname" in events[INDEX].payload
        assert "email" in events[INDEX].payload

        # Another User is created
        INDEX = 1
        assert events[INDEX].event == Events.create.value
        assert events[INDEX].user == BaseAuthentication.default_user
        assert events[INDEX].target_type == "User"
        assert events[INDEX].target_id != events[0].target_id
        assert "name" in events[INDEX].payload
        assert "surname" in events[INDEX].payload
        assert "email" in events[INDEX].payload

        # User 1 modified (same target_id as above)
        INDEX = 2
        assert events[INDEX].event == Events.modify.value
        assert events[INDEX].user == BaseAuthentication.default_user
        assert events[INDEX].target_type == "User"
        assert events[INDEX].target_id == events[0].target_id
        assert "name" in events[INDEX].payload
        assert "surname" not in events[INDEX].payload
        assert "email" not in events[INDEX].payload
        assert "password" not in events[INDEX].payload

        # User 2 is deleted (same target_id as above)
        INDEX = 3
        assert events[INDEX].event == Events.delete.value
        assert events[INDEX].user == BaseAuthentication.default_user
        assert events[INDEX].target_type == "User"
        assert events[INDEX].target_id == events[0].target_id
        assert len(events[INDEX].payload) == 0

        # User 2 modified (same target_id as above)
        INDEX = 4
        assert events[INDEX].event == Events.modify.value
        assert events[INDEX].user == BaseAuthentication.default_user
        assert events[INDEX].target_type == "User"
        assert events[INDEX].target_id == events[1].target_id
        assert "name" not in events[INDEX].payload
        assert "surname" not in events[INDEX].payload
        assert "email" not in events[INDEX].payload
        assert "password" in events[INDEX].payload
        assert "email_notification" in events[INDEX].payload
        # Verify that the password is obfuscated in the log:
        assert events[INDEX].payload["password"] == OBSCURE_VALUE

        # User 2 is deleted (same target_id as above)
        INDEX = 5
        assert events[INDEX].event == Events.delete.value
        assert events[INDEX].user == BaseAuthentication.default_user
        assert events[INDEX].target_type == "User"
        assert events[INDEX].target_id == events[1].target_id
        assert len(events[INDEX].payload) == 0

        # Default user is modified
        INDEX = 6
        assert events[INDEX].event == Events.modify.value
        assert events[INDEX].user == BaseAuthentication.default_user
        assert events[INDEX].target_type == "User"
        assert events[INDEX].target_id != events[0].target_id
        assert events[INDEX].target_id != events[1].target_id
        assert "name" not in events[INDEX].payload
        assert "surname" not in events[INDEX].payload
        assert "email" not in events[INDEX].payload
        assert "password" in events[INDEX].payload
        assert "roles" in events[INDEX].payload
        assert "email_notification" not in events[INDEX].payload
        # Verify that the password is obfuscated in the log:
        assert events[INDEX].payload["password"] == OBSCURE_VALUE
