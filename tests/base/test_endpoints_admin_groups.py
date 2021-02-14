import json

import pytest
from faker import Faker

from restapi.env import Env
from restapi.services.authentication import BaseAuthentication
from restapi.tests import API_URI, AUTH_URI, BaseTests, FlaskClient
from restapi.utilities.logs import log


class TestApp(BaseTests):
    def test_admin_groups(self, client: FlaskClient, faker: Faker) -> None:

        if not Env.get_bool("MAIN_LOGIN_ENABLE"):  # pragma: no cover
            log.warning("Skipping admin/users tests")
            return

        headers, _ = self.do_login(client, None, None)

        r = client.get(f"{API_URI}/admin/groups", headers=headers)
        assert r.status_code == 200

        schema = self.getDynamicInputSchema(client, "admin/groups", headers)
        data = self.buildData(schema)
        r = client.post(f"{API_URI}/admin/groups", data=data, headers=headers)
        assert r.status_code == 200
        uuid = self.get_content(r)

        r = client.get(f"{API_URI}/admin/groups", headers=headers)
        assert r.status_code == 200
        groups = self.get_content(r)
        assert groups
        assert len(groups) > 0

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

        uuid, _ = self.create_group(client, data=data)

        data = {
            "group": uuid,
            # very important, otherwise the default user will lose its admin role
            "roles": json.dumps(["admin_root"]),
        }
        r = client.put(f"{API_URI}/admin/users/{user_uuid}", data=data, headers=headers)
        assert r.status_code == 204

    def test_events_file(self):

        events = self.get_last_events(6)

        assert events[0].event == "login"
        assert events[0].user == BaseAuthentication.default_user
        assert events[0].target_type == ""
        assert events[0].target_id == ""
        assert len(events[0].payload) == 0

        # A new grup is created
        assert events[1].event == "create"
        assert events[1].user == BaseAuthentication.default_user
        assert events[1].target_type == "Group"
        assert "fullname" in events[1].payload
        assert "shortname" in events[1].payload

        # Group modified (same target_id as above)
        assert events[2].event == "modify"
        assert events[2].user == BaseAuthentication.default_user
        assert events[2].target_type == "Group"
        assert events[2].target_id == events[1].target_id
        assert "fullname" in events[2].payload
        assert "shortname" in events[2].payload

        # Group is deleted (same target_id as above)
        assert events[3].event == "delete"
        assert events[3].user == BaseAuthentication.default_user
        assert events[3].target_type == "Group"
        assert events[3].target_id == events[1].target_id
        assert len(events[3].payload) == 0

        # A new group is created
        assert events[4].event == "create"
        assert events[4].user == BaseAuthentication.default_user
        assert events[4].target_type == "Group"
        assert events[4].target_id != events[1].target_id
        assert "fullname" in events[4].payload
        assert "shortname" in events[4].payload

        # User modified, payload contains the created group
        assert events[5].event == "modify"
        assert events[5].user == BaseAuthentication.default_user
        assert events[5].target_type == "User"
        assert "fullname" not in events[5].payload
        assert "shortname" not in events[5].payload
        assert "group" in events[5].payload
        assert events[5].payload["group"] == events[4].target_id
