import pytest

from restapi.services.detect import detector
from restapi.tests import API_URI, AUTH_URI, BaseTests

# from restapi.utilities.logs import log

if detector.check_availability("neo4j"):

    class TestApp(BaseTests):
        def test_admin_groups(self, client, fake):

            headers, _ = self.do_login(client, None, None)
            self._test_endpoint(
                client, "admin/groups", headers, 200, 400, 405, 405,
            )

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
            else:
                pytest.fail("Group not found")

            assert fullname is not None

            newdata = {
                "shortname": fake.company(),
                "fullname": fake.company(),
                # we should change the coordinator...
                # But set again the same coordinator is enough for now
                "coordinator": data.get("coordinator"),
            }
            r = client.put(
                f"{API_URI}/admin/groups/{uuid}", data=newdata, headers=headers
            )
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
                if g.get("uuid") == uuid:
                    pytest.fail("Group not deleted!")

            r = client.delete(f"{API_URI}/admin/groups/xyz", headers=headers)
            assert r.status_code == 404

            data = self.buildData(schema)
            data["coordinator"] = fake.ascii_email()
            r = client.post(f"{API_URI}/admin/groups", data=data, headers=headers)
            assert r.status_code == 400
            # Now error is: 'coordinator': ['Must be one of: ...
            # assert self.get_content(r) == 'User not found'

            # Create a group and assign it to the main user
            # Profile and AdminUsers will react to this change
            # Very important: admin_groups must be tested before admin_users and profile

            r = client.get(f"{AUTH_URI}/profile", headers=headers)
            assert r.status_code == 200
            user_uuid = self.get_content(r).get("uuid")

            data = {
                "fullname": "Default group",
                "shortname": fake.company(),
                "coordinator": user_uuid,
            }
            r = client.post(f"{API_URI}/admin/groups", data=data, headers=headers)
            assert r.status_code == 200
            uuid = self.get_content(r)

            data = {
                "group": uuid,
                # very important, otherwise the default user will lose its admin role
                "roles_admin_root": True,
            }
            r = client.put(
                f"{API_URI}/admin/users/{user_uuid}", data=data, headers=headers
            )
            assert r.status_code == 204
