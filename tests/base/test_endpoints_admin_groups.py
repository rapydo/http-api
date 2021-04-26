import json

import pytest
from faker import Faker

from restapi.env import Env
from restapi.services.authentication import BaseAuthentication
from restapi.tests import API_URI, AUTH_URI, BaseTests, FlaskClient
from restapi.utilities.logs import Events, log


class TestApp(BaseTests):
    def test_admin_groups(self, client: FlaskClient, faker: Faker) -> None:

        if not Env.get_bool("MAIN_LOGIN_ENABLE") or not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping admin/users tests")
            return

        headers, _ = self.do_login(client, None, None)

        r = client.get(f"{API_URI}/admin/groups", headers=headers)
        assert r.status_code == 200

        schema = self.getDynamicInputSchema(client, "admin/groups", headers)
        data = self.buildData(schema)

        # Test the differences between post and put schema
        post_schema = {s["key"]: s for s in schema}

        tmp_schema = self.getDynamicInputSchema(
            client, "admin/groups/myuuid", headers, method="put"
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

        # Event 1: create
        r = client.post(f"{API_URI}/admin/groups", data=data, headers=headers)
        assert r.status_code == 200
        uuid = self.get_content(r)

        r = client.get(f"{API_URI}/admin/groups", headers=headers)
        assert r.status_code == 200
        groups = self.get_content(r)
        assert groups
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
            "shortname": faker.company(),
            "fullname": faker.company(),
        }
        # Event 2: modify
        r = client.put(f"{API_URI}/admin/groups/{uuid}", data=newdata, headers=headers)
        assert r.status_code == 204

        r = client.get(f"{API_URI}/admin/groups", headers=headers)
        assert r.status_code == 200
        groups = self.get_content(r)
        for g in groups:
            if g.get("uuid") == uuid:

                assert g.get("fullname") == newdata.get("fullname")
                assert g.get("fullname") != data.get("fullname")
                assert g.get("fullname") != fullname

        r = client.put(f"{API_URI}/admin/groups/xyz", data=data, headers=headers)
        assert r.status_code == 404

        # Event 3: delete
        r = client.delete(f"{API_URI}/admin/groups/{uuid}", headers=headers)
        assert r.status_code == 204

        r = client.get(f"{API_URI}/admin/groups", headers=headers)
        assert r.status_code == 200
        groups = self.get_content(r)
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
        user_uuid = self.get_content(r).get("uuid")

        data = {
            "fullname": "Default group",
            "shortname": faker.company(),
        }

        # Event 4: create
        uuid, _ = self.create_group(client, data=data)

        data = {
            "group": uuid,
            # very important, otherwise the default user will lose its admin role
            "roles": json.dumps(["admin_root"]),
        }
        headers, _ = self.do_login(client, None, None)
        # Event 5: modify
        r = client.put(f"{API_URI}/admin/users/{user_uuid}", data=data, headers=headers)
        assert r.status_code == 204

    def test_events_file(self) -> None:

        if not Env.get_bool("MAIN_LOGIN_ENABLE") or not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping admin/users tests")
            return

        events = self.get_last_events(4, filters={"target_type": "Group"})

        # A new group is created
        INDEX = 0
        assert events[INDEX].event == Events.create.value
        assert events[INDEX].user == BaseAuthentication.default_user
        assert events[INDEX].target_type == "Group"
        assert "fullname" in events[INDEX].payload
        assert "shortname" in events[INDEX].payload

        # Group modified (same target_id as above)
        INDEX = 1
        assert events[INDEX].event == Events.modify.value
        assert events[INDEX].user == BaseAuthentication.default_user
        assert events[INDEX].target_type == "Group"
        assert events[INDEX].target_id == events[0].target_id
        assert "fullname" in events[INDEX].payload
        assert "shortname" in events[INDEX].payload

        # Group is deleted (same target_id as above)
        INDEX = 2
        assert events[INDEX].event == Events.delete.value
        assert events[INDEX].user == BaseAuthentication.default_user
        assert events[INDEX].target_type == "Group"
        assert events[INDEX].target_id == events[0].target_id
        assert len(events[INDEX].payload) == 0

        # A new group is created
        INDEX = 3
        assert events[INDEX].event == Events.create.value
        assert events[INDEX].user == BaseAuthentication.default_user
        assert events[INDEX].target_type == "Group"
        assert events[INDEX].target_id != events[0].target_id
        assert "fullname" in events[INDEX].payload
        assert "shortname" in events[INDEX].payload
        group_uuid = events[INDEX].target_id

        events = self.get_last_events(1, filters={"target_type": "User"})

        # User modified, payload contains the created group
        INDEX = 0
        assert events[INDEX].event == Events.modify.value
        assert events[INDEX].user == BaseAuthentication.default_user
        assert events[INDEX].target_type == "User"
        assert "fullname" not in events[INDEX].payload
        assert "shortname" not in events[INDEX].payload
        assert "group" in events[INDEX].payload
        assert events[INDEX].payload["group"] == group_uuid
