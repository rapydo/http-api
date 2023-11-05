import orjson
import pytest
from faker import Faker

from restapi.connectors import Connector
from restapi.env import Env
from restapi.services.authentication import BaseAuthentication, Role
from restapi.tests import API_URI, AUTH_URI, BaseTests, FlaskClient
from restapi.utilities.logs import Events, log


def get_random_group_name(faker: Faker) -> str:
    # faker.company alone is not always enough and some
    # "Group already exists with shortname" occasionally occur during tests
    return f"{faker.company()}-{faker.pyint(2, 100)}"


class TestApp(BaseTests):
    def test_admin_groups(self, client: FlaskClient, faker: Faker) -> None:
        if not Env.get_bool("MAIN_LOGIN_ENABLE") or not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping admin/groups tests")
            return

        auth = Connector.get_authentication_instance()
        staff_role_enabled = Role.STAFF.value in [r.name for r in auth.get_roles()]
        for role in (
            Role.ADMIN,
            Role.STAFF,
        ):
            if not staff_role_enabled:  # pragma: no cover
                log.warning(
                    "Skipping tests of admin/groups endpoints, role Staff not enabled"
                )
                continue
            else:
                log.warning("Testing admin/groups endpoints as {}", role)

            if role == Role.ADMIN:
                user_email = BaseAuthentication.default_user
                user_password = BaseAuthentication.default_password
            elif role == Role.STAFF:
                _, user_data = self.create_user(client, roles=[Role.STAFF])
                user_email = user_data.get("email")
                user_password = user_data.get("password")

            headers, _ = self.do_login(client, user_email, user_password)

            r = client.get(f"{API_URI}/admin/groups", headers=headers)
            assert r.status_code == 200

            schema = self.get_dynamic_input_schema(client, "admin/groups", headers)
            data = self.buildData(schema)

            # Event 1: create
            r = client.post(f"{API_URI}/admin/groups", json=data, headers=headers)
            assert r.status_code == 200
            uuid = self.get_content(r)
            assert isinstance(uuid, str)

            events = self.get_last_events(1, filters={"target_type": "Group"})
            assert events[0].event == Events.create.value
            assert events[0].user == user_email
            assert events[0].target_type == "Group"
            assert events[0].url == "/api/admin/groups"
            assert "fullname" in events[0].payload
            assert "shortname" in events[0].payload

            # Save it for the following tests
            event_target_id = events[0].target_id

            r = client.get(f"{API_URI}/admin/groups", headers=headers)
            assert r.status_code == 200
            groups = self.get_content(r)
            assert isinstance(groups, list)
            assert len(groups) > 0

            assert "uuid" in groups[0]
            assert "shortname" in groups[0]
            assert "fullname" in groups[0]
            assert "members" in groups[0]
            assert len(groups[0]["members"]) > 0
            assert "coordinators" in groups[0]

            fullname = None
            for g in groups:
                if g.get("uuid") == uuid:
                    fullname = g.get("fullname")
                    break
            else:  # pragma: no cover
                pytest.fail("Group not found")

            assert fullname is not None

            newdata = {
                "shortname": get_random_group_name(faker),
                "fullname": get_random_group_name(faker),
            }

            # Test the differences between post and put schema
            post_schema = {s["key"]: s for s in schema}

            tmp_schema = self.get_dynamic_input_schema(
                client, f"admin/groups/{uuid}", headers, method="put"
            )
            put_schema = {s["key"]: s for s in tmp_schema}

            assert "shortname" in post_schema
            assert post_schema["shortname"]["required"]
            assert "shortname" in put_schema
            assert put_schema["shortname"]["required"]

            assert "fullname" in post_schema
            assert post_schema["fullname"]["required"]
            assert "fullname" in put_schema
            assert put_schema["fullname"]["required"]

            # Event 2: modify
            r = client.put(
                f"{API_URI}/admin/groups/{uuid}", json=newdata, headers=headers
            )
            assert r.status_code == 204

            events = self.get_last_events(1, filters={"target_type": "Group"})
            # Group modified (same target_id as above)
            assert events[0].event == Events.modify.value
            assert events[0].user == user_email
            assert events[0].target_type == "Group"
            assert events[0].target_id == event_target_id
            assert events[0].url == f"/api/admin/groups/{event_target_id}"
            assert "fullname" in events[0].payload
            assert "shortname" in events[0].payload

            r = client.get(f"{API_URI}/admin/groups", headers=headers)
            assert r.status_code == 200
            groups = self.get_content(r)
            assert isinstance(groups, list)
            for g in groups:
                if g.get("uuid") == uuid:
                    assert g.get("fullname") == newdata.get("fullname")
                    assert g.get("fullname") != data.get("fullname")
                    assert g.get("fullname") != fullname

            r = client.put(f"{API_URI}/admin/groups/xyz", json=data, headers=headers)
            assert r.status_code == 404

            # members = auth.get_group_members(group)
            # with pytest.raises(
            #     Forbidden,
            #     match=rf"Cannot delete this group, it is assigned to {len(members)} user(s)",
            # ):

            # Event 3: delete
            r = client.delete(f"{API_URI}/admin/groups/{uuid}", headers=headers)
            assert r.status_code == 204

            events = self.get_last_events(1, filters={"target_type": "Group"})
            # Group is deleted (same target_id as above)
            assert events[0].event == Events.delete.value
            assert events[0].user == user_email
            assert events[0].target_type == "Group"
            assert events[0].target_id == event_target_id
            assert events[0].url == f"/api/admin/groups/{event_target_id}"
            assert len(events[0].payload) == 0

            r = client.get(f"{API_URI}/admin/groups", headers=headers)
            assert r.status_code == 200
            groups = self.get_content(r)
            assert isinstance(groups, list)
            for g in groups:
                if g.get("uuid") == uuid:  # pragma: no cover
                    pytest.fail("Group not deleted!")

            r = client.delete(f"{API_URI}/admin/groups/xyz", headers=headers)
            assert r.status_code == 404

            # Create a group and assign it to the main user
            # Profile and AdminUsers will react to this change
            # Very important: admin_groups must be tested before admin_users and profile

            r = client.get(f"{AUTH_URI}/profile", headers=headers)
            assert r.status_code == 200
            content = self.get_content(r)
            assert isinstance(content, dict)
            user_uuid = content.get("uuid")

            data = {
                "fullname": "Default group",
                "shortname": get_random_group_name(faker),
            }

            # Event 4: create
            new_group_uuid, _ = self.create_group(client, data=data)

            events = self.get_last_events(1, filters={"target_type": "Group"})
            # A new group is created
            assert events[0].event == Events.create.value
            # Created via admin utility
            assert events[0].user == BaseAuthentication.default_user
            assert events[0].target_type == "Group"
            assert events[0].target_id != event_target_id
            assert events[0].url == "/api/admin/groups"
            assert "fullname" in events[0].payload
            assert "shortname" in events[0].payload
            # Save it for the following tests
            event_group_uuid = events[0].target_id

            data = {
                "group": new_group_uuid,
                # very important, otherwise the default user will lose its role
                # adding coordinator to enforce the role and use it for additional tests
                "roles": orjson.dumps([role, "group_coordinator"]).decode("UTF8"),
            }

            # a new login is required due to the use of create_group utility
            headers, _ = self.do_login(client, user_email, user_password)

            # Event 5: modify
            r = client.put(
                f"{API_URI}/admin/users/{user_uuid}", json=data, headers=headers
            )
            assert r.status_code == 204

            events = self.get_last_events(1, filters={"target_type": "User"})
            # User modified, payload contains the created group
            assert events[0].event == Events.modify.value
            assert events[0].user == user_email
            assert events[0].target_type == "User"
            assert events[0].target_id == user_uuid
            assert events[0].url == f"/api/admin/users/{user_uuid}"
            assert "fullname" not in events[0].payload
            assert "shortname" not in events[0].payload
            assert "group" in events[0].payload
            assert events[0].payload["group"] == event_group_uuid

            # Event 6: verify the assigned group
            r = client.get(f"{API_URI}/admin/users/{user_uuid}", headers=headers)
            assert r.status_code == 200
            users_list = self.get_content(r)
            assert isinstance(users_list, dict)
            assert len(users_list) > 0
            assert "group" in users_list
            assert "uuid" in users_list["group"]
            assert "fullname" in users_list["group"]
            assert "shortname" in users_list["group"]
            assert users_list["group"]["uuid"] == new_group_uuid

            # Verify coordinators:
            r = client.get(f"{API_URI}/admin/groups", headers=headers)
            assert r.status_code == 200
            groups = self.get_content(r)
            assert isinstance(groups, list)
            assert len(groups) > 0

            # Extract all coordinators:
            coordinators: set[str] = set()
            for group in groups:
                for coordinator in group["coordinators"]:
                    coordinators.add(coordinator["email"])

            assert user_email in coordinators

            if role == Role.ADMIN:
                assert BaseAuthentication.default_user in coordinators
            else:
                assert BaseAuthentication.default_user not in coordinators
