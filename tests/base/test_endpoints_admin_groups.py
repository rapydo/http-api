# -*- coding: utf-8 -*-
import pytest
from restapi.tests import BaseTests, API_URI
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

            data = {'fullname': 'newfullname'}
            r = client.put(url + "/" + uuid, data=data, headers=headers)
            assert r.status_code == 204

            r = client.get(url, headers=headers)
            assert r.status_code == 200
            groups = self.get_content(r)
            for g in groups:
                if g.get('uuid') == uuid:

                    assert g.get('fullname') == data.get('fullname')
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
