# -*- coding: utf-8 -*-
import pytest
from restapi.tests import BaseTests, API_URI, AUTH_URI
from restapi.services.detect import detector
# from restapi.utilities.logs import log

if detector.check_availability('neo4j'):
    class TestApp(BaseTests):

        def test_admin_groups(self, client):

            headers, _ = self.do_login(client, None, None)
            endpoint = "admin/groups"
            url = API_URI + "/" + endpoint
            self._test_endpoint(
                client,
                endpoint,
                headers,
                200,
                400,
                405,
                405,
            )

            r = client.get(url, headers=headers)
            assert r.status_code == 200

            schema = self.getDynamicInputSchema(client, endpoint, headers)
            data = self.buildData(schema)
            r = client.post(url, data=data, headers=headers)
            assert r.status_code == 200
            uuid = self.get_content(r)

            r = client.get(url, headers=headers)
            assert r.status_code == 200
            groups = self.get_content(r)
            assert groups
            assert len(groups) > 0

            fullname = None
            for g in groups:
                if g.get('uuid') == uuid:

                    fullname = g.get('fullname')
                    break
            else:
                pytest.fail("Group not found")

            assert fullname is not None

            newdata = {
                'fullname': 'newfullname',
                # we should change the coordinator...
                # But set again the same coordinator is enough for now
                'coordinator': data.get('coordinator')
            }
            r = client.put(url + "/" + uuid, data=newdata, headers=headers)
            assert r.status_code == 204

            r = client.get(url, headers=headers)
            assert r.status_code == 200
            groups = self.get_content(r)
            for g in groups:
                if g.get('uuid') == uuid:

                    assert g.get('fullname') == newdata.get('fullname')
                    assert g.get('fullname') != data.get('fullname')
                    assert g.get('fullname') != fullname

            r = client.put(url + "/xyz", data=data, headers=headers)
            assert r.status_code == 404

            r = client.delete(url + "/" + uuid, headers=headers)
            assert r.status_code == 204

            r = client.get(url, headers=headers)
            assert r.status_code == 200
            groups = self.get_content(r)
            for g in groups:
                if g.get('uuid') == uuid:
                    pytest.fail("Group not deleted!")

            r = client.delete(url + "/xyz", headers=headers)
            assert r.status_code == 404

            # Create a group and assign it to the main user
            # Profile and AdminUsers will react to this change
            # Very important: admin_groups must be tested before admin_users and profile

            r = client.get(AUTH_URI + '/profile', headers=headers)
            assert r.status_code == 200
            user_uuid = self.get_content(r).get('uuid')

            data = {
                'fullname': 'Default group',
                'shortname': self.randomString(),
                'coordinator': user_uuid,
            }
            r = client.post(url, data=data, headers=headers)
            assert r.status_code == 200
            uuid = self.get_content(r)

            url = API_URI + "/admin/users/" + user_uuid
            data = {
                'group': uuid,
                # very important, otherwise the default user will lose its admin role
                'roles_admin_root': True
            }
            r = client.put(url, data=data, headers=headers)
            assert r.status_code == 204
