# -*- coding: utf-8 -*-
import pytest

from restapi.tests import BaseTests, API_URI, AUTH_URI
from restapi.services.authentication import BaseAuthentication
from restapi.services.detect import detector
from restapi.utilities.logs import log


class TestApp(BaseTests):

    def test_admin_users(self, client):

        if detector.get_bool_from_os("ADMINER_DISABLED"):
            log.warning("Skipping admin/users tests")
            return

        headers, _ = self.do_login(client, None, None)
        endpoint = "admin/users"
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

        pytest.fail("Check email!")

        r = client.get(url + "/" + uuid, headers=headers)
        assert r.status_code == 200
        users_list = self.get_content(r)
        assert len(users_list) > 0
        # email is saved lowercase
        assert users_list[0].get("email") == data.get('email').lower()

        # Check duplicates
        r = client.post(url, data=data, headers=headers)
        assert r.status_code == 409

        # Create another user
        data2 = self.buildData(schema)
        r = client.post(url, data=data2, headers=headers)
        assert r.status_code == 200
        uuid2 = self.get_content(r)

        pytest.fail("Check email!")

        # send and invalid user_id
        r = client.put(url + "/invalid", data={'name': 'Changed'}, headers=headers)
        assert r.status_code == 404

        r = client.put(url + "/" + uuid, data={'name': 'Changed'}, headers=headers)
        assert r.status_code == 204

        # email cannot be modified
        new_data = {'email': data.get('email')}
        r = client.put(url + "/" + uuid2, data=new_data, headers=headers)
        assert r.status_code == 204

        r = client.get(url + "/" + uuid2, headers=headers)
        assert r.status_code == 200
        users_list = self.get_content(r)
        assert len(users_list) > 0
        # email is not modified -> still equal to data2, not data1
        assert users_list[0].get("email") != data.get('email').lower()
        assert users_list[0].get("email") == data2.get('email').lower()

        r = client.delete(url + "/invalid", headers=headers)
        assert r.status_code == 404

        r = client.delete(url + "/" + uuid, headers=headers)
        assert r.status_code == 204

        r = client.get(url + "/" + uuid, headers=headers)
        assert r.status_code == 404

        # change password of user2
        newpwd = "bB2=" + self.randomString()
        data = {'password': newpwd, 'email_notification': True}
        r = client.put(url + "/" + uuid2, data=data, headers=headers)
        assert r.status_code == 204

        pytest.fail("Check email!")

        # login with a newly created user
        headers2, _ = self.do_login(
            client,
            data2.get("email"),
            newpwd
        )

        # normal users cannot access to this endpoint
        r = client.get(url, headers=headers2)
        assert r.status_code == 401

        r = client.get(url + "/" + uuid, headers=headers2)
        assert r.status_code == 401

        r = client.post(url, data=data, headers=headers2)
        assert r.status_code == 401

        r = client.put(url + "/" + uuid, data={'name': 'Changed'}, headers=headers2)
        assert r.status_code == 401

        r = client.delete(url + "/" + uuid, headers=headers2)
        assert r.status_code == 401

        # Users are not authorized to /admin/tokens
        # These two tests should be moved in test_endpoints_tokens.py
        r = client.get(API_URI + "/admin/tokens", headers=headers2)
        assert r.status_code == 401
        r = client.delete(API_URI + "/admin/tokens/xyz", headers=headers2)
        assert r.status_code == 401

        # let's delete the second user
        r = client.delete(url + "/" + uuid2, headers=headers)
        assert r.status_code == 204

        # Restore the default password, if it changed due to FORCE_FIRST_PASSWORD_CHANGE
        # or MAX_PASSWORD_VALIDITY errors
        r = client.get(AUTH_URI + '/profile', headers=headers)
        assert r.status_code == 200
        uuid = self.get_content(r).get('uuid')

        data = {
            'password': BaseAuthentication.default_password,
            # very important, otherwise the default user will lose its admin role
            'roles_admin_root': True
        }
        r = client.put(url + "/" + uuid, data=data, headers=headers)
        assert r.status_code == 204

        r = client.get(AUTH_URI + '/logout', headers=headers)
        assert r.status_code == 204
