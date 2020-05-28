# -*- coding: utf-8 -*-
from restapi.tests import BaseTests, API_URI
# from restapi.utilities.logs import log


class TestApp(BaseTests):

    def test_GET_specs(self, client):

        # Check success
        r = client.get(f"{API_URI}/specs")
        assert r.status_code == 200
        content = self.get_content(r)
        assert 'host' in content
        assert 'info' in content
        assert 'swagger' in content
        assert 'schemes' in content
        assert 'paths' in content
        assert 'definitions' in content

        r = client.get(f"{API_URI}/swagger")
        assert r.status_code == 200
        content = self.get_content(r)
        assert 'host' in content
        assert 'info' in content
        assert 'swagger' in content
        assert 'schemes' in content
        assert 'paths' in content
        assert 'definitions' in content
        assert '/api/admin/users' not in content['paths']

        headers, _ = self.do_login(client, None, None)
        r = client.get(f"{API_URI}/swagger", headers=headers)
        assert r.status_code == 200
        content = self.get_content(r)
        assert 'host' in content
        assert 'info' in content
        assert 'swagger' in content
        assert 'schemes' in content
        assert 'paths' in content
        assert 'definitions' in content
        assert '/api/admin/users' in content['paths']
