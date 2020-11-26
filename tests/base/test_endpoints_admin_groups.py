import json

import pytest

from restapi.env import Env
from restapi.tests import API_URI, AUTH_URI, BaseTests
from restapi.utilities.logs import log


class TestApp(BaseTests):
    def test_admin_groups(self, client, fake):

        # Adminer is always enabled during tests
        if Env.get_bool("ADMINER_DISABLED"):  # pragma: no cover
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
            "shortname": fake.company(),
            "fullname": fake.company(),
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
            "shortname": fake.company(),
        }
        r = client.post(f"{API_URI}/admin/groups", data=data, headers=headers)
        assert r.status_code == 200
        uuid = self.get_content(r)

        data = {
            "group": uuid,
            # very important, otherwise the default user will lose its admin role
            "roles": json.dumps(["admin_root"]),
        }
        r = client.put(f"{API_URI}/admin/users/{user_uuid}", data=data, headers=headers)
        assert r.status_code == 204
