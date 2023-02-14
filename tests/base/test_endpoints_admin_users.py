import orjson
from faker import Faker
from flask import escape

from restapi.config import get_project_configuration
from restapi.connectors import Connector
from restapi.env import Env
from restapi.services.authentication import BaseAuthentication, Role
from restapi.tests import API_URI, AUTH_URI, BaseTests, FlaskClient
from restapi.utilities.logs import OBSCURE_VALUE, Events, log


class TestApp(BaseTests):
    def test_admin_users(self, client: FlaskClient, faker: Faker) -> None:
        if not Env.get_bool("MAIN_LOGIN_ENABLE") or not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping admin/users tests")
            return

        project_tile = get_project_configuration("project.title", default="YourProject")

        auth = Connector.get_authentication_instance()
        staff_role_enabled = Role.STAFF.value in [r.name for r in auth.get_roles()]

        for role in (
            Role.ADMIN,
            Role.STAFF,
        ):
            if not staff_role_enabled:  # pragma: no cover
                log.warning(
                    "Skipping tests of admin/users endpoints, role Staff not enabled"
                )
                continue
            else:
                log.warning("Testing admin/users endpoints as {}", role)

            if role == Role.ADMIN:
                user_email = BaseAuthentication.default_user
                user_password = BaseAuthentication.default_password
            elif role == Role.STAFF:
                _, user_data = self.create_user(client, roles=[Role.STAFF])
                user_email = user_data.get("email")
                user_password = user_data.get("password")

            headers, _ = self.do_login(client, user_email, user_password)
            r = client.get(f"{API_URI}/admin/users", headers=headers)
            assert r.status_code == 200

            schema = self.get_dynamic_input_schema(client, "admin/users", headers)
            data = self.buildData(schema)

            data["email_notification"] = True
            data["is_active"] = True
            data["expiration"] = None

            # Event 1: create
            r = client.post(f"{API_URI}/admin/users", json=data, headers=headers)
            assert r.status_code == 200
            uuid = self.get_content(r)
            assert isinstance(uuid, str)

            # A new User is created
            events = self.get_last_events(1, filters={"target_type": "User"})
            assert events[0].event == Events.create.value
            assert events[0].user == user_email
            assert events[0].target_type == "User"
            assert events[0].url == "/api/admin/users"
            assert "name" in events[0].payload
            assert "surname" in events[0].payload
            assert "email" in events[0].payload

            # Save it for the following tests
            event_target_id1 = events[0].target_id

            mail = self.read_mock_email()
            body = mail.get("body", "")

            # Subject: is a key in the MIMEText
            assert body is not None
            assert mail.get("headers") is not None
            assert f"Subject: {project_tile}: New credentials" in mail.get(
                "headers", ""
            )
            assert data.get("email", "MISSING").lower() in body
            assert (
                data.get("password", "MISSING") in body
                or escape(str(data.get("password"))) in body
            )

            # Test the differences between post and put schema
            post_schema = {s["key"]: s for s in schema}

            tmp_schema = self.get_dynamic_input_schema(
                client, f"admin/users/{uuid}", headers, method="put"
            )
            put_schema = {s["key"]: s for s in tmp_schema}

            assert "email" in post_schema
            assert post_schema["email"]["required"]
            assert "email" not in put_schema

            assert "name" in post_schema
            assert post_schema["name"]["required"]
            assert "name" in put_schema
            assert not put_schema["name"]["required"]

            assert "surname" in post_schema
            assert post_schema["surname"]["required"]
            assert "surname" in put_schema
            assert not put_schema["surname"]["required"]

            assert "password" in post_schema
            assert post_schema["password"]["required"]
            assert "password" in put_schema
            assert not put_schema["password"]["required"]

            assert "group" in post_schema
            assert post_schema["group"]["required"]
            assert "group" in put_schema
            assert not put_schema["group"]["required"]

            # Event 2: read
            r = client.get(f"{API_URI}/admin/users/{uuid}", headers=headers)
            assert r.status_code == 200
            users_list = self.get_content(r)
            assert isinstance(users_list, dict)
            assert len(users_list) > 0
            # email is saved lowercase
            assert users_list.get("email") == data.get("email", "MISSING").lower()

            # Access to the user
            events = self.get_last_events(1, filters={"target_type": "User"})
            assert events[0].event == Events.access.value
            assert events[0].user == user_email
            assert events[0].target_type == "User"
            assert events[0].target_id == event_target_id1
            assert events[0].url == f"/api/admin/users/{event_target_id1}"
            assert len(events[0].payload) == 0

            # Check duplicates
            r = client.post(f"{API_URI}/admin/users", json=data, headers=headers)
            assert r.status_code == 409
            assert (
                self.get_content(r)
                == f"A User already exists with email: {data['email']}"
            )

            data["email"] = BaseAuthentication.default_user
            r = client.post(f"{API_URI}/admin/users", json=data, headers=headers)
            assert r.status_code == 409
            assert (
                self.get_content(r)
                == f"A User already exists with email: {BaseAuthentication.default_user}"
            )

            # Create another user
            data2 = self.buildData(schema)
            data2["email_notification"] = True
            data2["is_active"] = True
            data2["expiration"] = None

            # Event 3: create
            r = client.post(f"{API_URI}/admin/users", json=data2, headers=headers)
            assert r.status_code == 200
            uuid2 = self.get_content(r)
            assert isinstance(uuid2, str)

            # Another User is created
            events = self.get_last_events(1, filters={"target_type": "User"})
            assert events[0].event == Events.create.value
            assert events[0].user == user_email
            assert events[0].target_type == "User"
            assert events[0].target_id != event_target_id1
            assert events[0].url == "/api/admin/users"
            assert "name" in events[0].payload
            assert "surname" in events[0].payload
            assert "email" in events[0].payload

            # Save it for the following tests
            event_target_id2 = events[0].target_id

            mail = self.read_mock_email()
            body = mail.get("body", "")
            # Subject: is a key in the MIMEText
            assert body is not None
            assert mail.get("headers") is not None
            assert f"Subject: {project_tile}: New credentials" in mail.get(
                "headers", ""
            )
            assert data2.get("email", "MISSING").lower() in body
            pwd = data2.get("password", "MISSING")
            assert pwd in body or escape(str(pwd)) in body

            # send and invalid user_id
            r = client.put(
                f"{API_URI}/admin/users/invalid",
                json={"name": faker.name()},
                headers=headers,
            )
            assert r.status_code == 404

            # Event 4: modify
            r = client.put(
                f"{API_URI}/admin/users/{uuid}",
                json={"name": faker.name()},
                headers=headers,
            )
            assert r.status_code == 204

            # User 1 modified (same target_id as above)
            events = self.get_last_events(1, filters={"target_type": "User"})
            assert events[0].event == Events.modify.value
            assert events[0].user == user_email
            assert events[0].target_type == "User"
            assert events[0].target_id == event_target_id1
            assert events[0].url == f"/api/admin/users/{event_target_id1}"
            assert "name" in events[0].payload
            assert "surname" not in events[0].payload
            assert "email" not in events[0].payload
            assert "password" not in events[0].payload

            # email cannot be modified
            new_data = {"email": data.get("email")}
            r = client.put(
                f"{API_URI}/admin/users/{uuid2}", json=new_data, headers=headers
            )
            # from webargs >= 6 this endpoint no longer return a 204 but a 400
            # because email is an unknown field
            # assert r.status_code == 204
            assert r.status_code == 400

            # Event 5: read
            r = client.get(f"{API_URI}/admin/users/{uuid2}", headers=headers)
            assert r.status_code == 200
            users_list = self.get_content(r)
            assert isinstance(users_list, dict)
            assert len(users_list) > 0
            # email is not modified -> still equal to data2, not data1
            assert users_list.get("email") != data.get("email", "MISSING").lower()
            assert users_list.get("email") == data2.get("email", "MISSING").lower()

            # Access to user 2
            events = self.get_last_events(1, filters={"target_type": "User"})
            assert events[0].event == Events.access.value
            assert events[0].user == user_email
            assert events[0].target_type == "User"
            assert events[0].target_id == event_target_id2
            assert events[0].url == f"/api/admin/users/{event_target_id2}"
            assert len(events[0].payload) == 0

            r = client.delete(f"{API_URI}/admin/users/invalid", headers=headers)
            assert r.status_code == 404

            # Event 6: delete
            r = client.delete(f"{API_URI}/admin/users/{uuid}", headers=headers)
            assert r.status_code == 204

            # User 1 is deleted (same target_id as above)
            events = self.get_last_events(1, filters={"target_type": "User"})
            assert events[0].event == Events.delete.value
            assert events[0].user == user_email
            assert events[0].target_type == "User"
            assert events[0].target_id == event_target_id1
            assert events[0].url == f"/api/admin/users/{event_target_id1}"
            assert len(events[0].payload) == 0

            r = client.get(f"{API_URI}/admin/users/{uuid}", headers=headers)
            assert r.status_code == 404

            # change password of user2
            # Event 7: modify
            newpwd = faker.password(strong=True)
            data = {"password": newpwd, "email_notification": True}
            r = client.put(f"{API_URI}/admin/users/{uuid2}", json=data, headers=headers)
            assert r.status_code == 204

            # User 2 modified (same target_id as above)
            events = self.get_last_events(1, filters={"target_type": "User"})
            assert events[0].event == Events.modify.value
            assert events[0].user == user_email
            assert events[0].target_type == "User"
            assert events[0].target_id == event_target_id2
            assert events[0].url == f"/api/admin/users/{event_target_id2}"
            assert "name" not in events[0].payload
            assert "surname" not in events[0].payload
            assert "email" not in events[0].payload
            assert "password" in events[0].payload
            assert "email_notification" in events[0].payload
            # Verify that the password is obfuscated in the log:
            assert events[0].payload["password"] == OBSCURE_VALUE

            mail = self.read_mock_email()
            # Subject: is a key in the MIMEText
            assert mail.get("body", "") is not None
            assert mail.get("headers", "") is not None
            assert f"Subject: {project_tile}: Password changed" in mail.get(
                "headers", ""
            )
            assert data2.get("email", "MISSING").lower() in mail.get("body", "")
            assert newpwd in mail.get("body", "") or escape(newpwd) in mail.get(
                "body", ""
            )

            # login with a newly created user
            headers2, _ = self.do_login(client, data2.get("email"), newpwd)

            # normal users cannot access to this endpoint
            r = client.get(f"{API_URI}/admin/users", headers=headers2)
            assert r.status_code == 401

            r = client.get(f"{API_URI}/admin/users/{uuid}", headers=headers2)
            assert r.status_code == 401

            r = client.post(f"{API_URI}/admin/users", json=data, headers=headers2)
            assert r.status_code == 401

            r = client.put(
                f"{API_URI}/admin/users/{uuid}",
                json={"name": faker.name()},
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
            # Event 8: delete
            r = client.delete(f"{API_URI}/admin/users/{uuid2}", headers=headers)
            assert r.status_code == 204

            # User 2 is deleted (same target_id as above)
            events = self.get_last_events(1, filters={"target_type": "User"})
            assert events[0].event == Events.delete.value
            assert events[0].user == user_email
            assert events[0].target_type == "User"
            assert events[0].target_id == event_target_id2
            assert events[0].url == f"/api/admin/users/{event_target_id2}"
            assert len(events[0].payload) == 0

            # Restore the default password (changed due to FORCE_FIRST_PASSWORD_CHANGE)
            # or MAX_PASSWORD_VALIDITY errors
            r = client.get(f"{AUTH_URI}/profile", headers=headers)
            assert r.status_code == 200
            content = self.get_content(r)
            assert isinstance(content, dict)
            uuid = str(content.get("uuid"))

            data = {
                "password": user_password,
                # very important, otherwise the default user will lose its role
                "roles": orjson.dumps([role]).decode("UTF8"),
            }
            # Event 9: modify
            r = client.put(f"{API_URI}/admin/users/{uuid}", json=data, headers=headers)
            assert r.status_code == 204

            # Default user is modified
            events = self.get_last_events(1, filters={"target_type": "User"})
            assert events[0].event == Events.modify.value
            assert events[0].user == user_email
            assert events[0].target_type == "User"
            assert events[0].target_id != event_target_id1
            assert events[0].target_id != event_target_id2
            assert events[0].url != f"/api/admin/users/{event_target_id1}"
            assert events[0].url != f"/api/admin/users/{event_target_id2}"
            assert "name" not in events[0].payload
            assert "surname" not in events[0].payload
            assert "email" not in events[0].payload
            assert "password" in events[0].payload
            assert "roles" in events[0].payload
            assert "email_notification" not in events[0].payload
            # Verify that the password is obfuscated in the log:
            assert events[0].payload["password"] == OBSCURE_VALUE

            r = client.get(f"{AUTH_URI}/logout", headers=headers)
            assert r.status_code == 204

    def test_staff_restrictions(self, client: FlaskClient, faker: Faker) -> None:
        if not Env.get_bool("MAIN_LOGIN_ENABLE") or not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping admin/users tests")
            return

        auth = Connector.get_authentication_instance()
        staff_role_enabled = Role.STAFF.value in [r.name for r in auth.get_roles()]

        if not staff_role_enabled:  # pragma: no cover
            log.warning(
                "Skipping tests of admin/users restrictions, role Staff not enabled"
            )
            return

        staff_uuid, staff_data = self.create_user(client, roles=[Role.STAFF])
        staff_email = staff_data.get("email")
        staff_password = staff_data.get("password")
        staff_headers, _ = self.do_login(client, staff_email, staff_password)

        user_uuid, _ = self.create_user(client, roles=[Role.USER])

        admin_headers, _ = self.do_login(client, None, None)

        r = client.get(f"{AUTH_URI}/profile", headers=admin_headers)
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, dict)
        admin_uuid = content.get("uuid")

        # Staff users are not allowed to retrieve Admins' data
        r = client.get(f"{API_URI}/admin/users/{user_uuid}", headers=admin_headers)
        assert r.status_code == 200

        r = client.get(f"{API_URI}/admin/users/{staff_uuid}", headers=admin_headers)
        assert r.status_code == 200

        r = client.get(f"{API_URI}/admin/users/{admin_uuid}", headers=admin_headers)
        assert r.status_code == 200

        r = client.get(f"{API_URI}/admin/users/{user_uuid}", headers=staff_headers)
        assert r.status_code == 200

        r = client.get(f"{API_URI}/admin/users/{staff_uuid}", headers=staff_headers)
        assert r.status_code == 200

        r = client.get(f"{API_URI}/admin/users/{admin_uuid}", headers=staff_headers)
        assert r.status_code == 404
        content = self.get_content(r)
        assert content == "This user cannot be found or you are not authorized"

        # Staff users are not allowed to edit Admins
        r = client.put(
            f"{API_URI}/admin/users/{admin_uuid}",
            json={
                "name": faker.name(),
                "roles": orjson.dumps([Role.STAFF]).decode("UTF8"),
            },
            headers=staff_headers,
        )
        assert r.status_code == 404
        content = self.get_content(r)
        assert content == "This user cannot be found or you are not authorized"

        r = client.put(
            f"{API_URI}/admin/users/{staff_uuid}",
            json={
                "name": faker.name(),
                "roles": orjson.dumps([Role.STAFF]).decode("UTF8"),
            },
            headers=staff_headers,
        )
        assert r.status_code == 204

        r = client.put(
            f"{API_URI}/admin/users/{user_uuid}",
            json={
                "name": faker.name(),
                "roles": orjson.dumps([Role.USER]).decode("UTF8"),
            },
            headers=staff_headers,
        )
        assert r.status_code == 204

        # Admin role is not allowed for Staff users
        tmp_schema = self.get_dynamic_input_schema(client, "admin/users", admin_headers)
        post_schema = {s["key"]: s for s in tmp_schema}
        assert "roles" in post_schema
        assert "options" in post_schema["roles"]
        assert "normal_user" in post_schema["roles"]["options"]
        assert "admin_root" in post_schema["roles"]["options"]

        tmp_schema = self.get_dynamic_input_schema(
            client, f"admin/users/{user_uuid}", admin_headers, method="put"
        )
        put_schema = {s["key"]: s for s in tmp_schema}

        assert "roles" in put_schema
        assert "options" in post_schema["roles"]
        assert "normal_user" in post_schema["roles"]["options"]
        assert "admin_root" in post_schema["roles"]["options"]

        tmp_schema = self.get_dynamic_input_schema(client, "admin/users", staff_headers)
        post_schema = {s["key"]: s for s in tmp_schema}
        assert "roles" in post_schema
        assert "options" in post_schema["roles"]
        assert "normal_user" in post_schema["roles"]["options"]
        assert "admin_root" not in post_schema["roles"]["options"]

        tmp_schema = self.get_dynamic_input_schema(
            client, f"admin/users/{user_uuid}", staff_headers, method="put"
        )
        put_schema = {s["key"]: s for s in tmp_schema}

        assert "roles" in put_schema
        assert "options" in post_schema["roles"]
        assert "normal_user" in post_schema["roles"]["options"]
        assert "admin_root" not in post_schema["roles"]["options"]

        # Staff can't send role admin on put
        r = client.put(
            f"{API_URI}/admin/users/{user_uuid}",
            json={
                "name": faker.name(),
                "roles": orjson.dumps([Role.ADMIN]).decode("UTF8"),
            },
            headers=staff_headers,
        )
        assert r.status_code == 400

        # Staff can't send role admin on post
        schema = self.get_dynamic_input_schema(client, "admin/users", staff_headers)
        data = self.buildData(schema)

        data["email_notification"] = True
        data["is_active"] = True
        data["expiration"] = None
        data["roles"] = orjson.dumps([Role.ADMIN]).decode("UTF8")

        r = client.post(f"{API_URI}/admin/users", json=data, headers=staff_headers)
        assert r.status_code == 400

        # Admin users are filtered out when asked from a Staff user
        r = client.get(f"{API_URI}/admin/users", headers=admin_headers)
        assert r.status_code == 200
        users_list = self.get_content(r)
        assert isinstance(users_list, list)
        assert len(users_list) > 0
        email_list = [u.get("email") for u in users_list]
        assert staff_email in email_list
        assert BaseAuthentication.default_user in email_list

        r = client.get(f"{API_URI}/admin/users", headers=staff_headers)
        assert r.status_code == 200
        users_list = self.get_content(r)
        assert isinstance(users_list, list)
        assert len(users_list) > 0
        email_list = [u.get("email") for u in users_list]
        assert staff_email in email_list
        assert BaseAuthentication.default_user not in email_list

        # Staff users are not allowed to delete Admins
        r = client.delete(f"{API_URI}/admin/users/{admin_uuid}", headers=staff_headers)
        assert r.status_code == 404
        content = self.get_content(r)
        assert content == "This user cannot be found or you are not authorized"

        r = client.delete(f"{API_URI}/admin/users/{user_uuid}", headers=staff_headers)
        assert r.status_code == 204
