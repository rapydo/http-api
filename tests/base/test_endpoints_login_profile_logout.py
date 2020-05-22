# -*- coding: utf-8 -*-
import time
import base64
from restapi.tests import BaseTests, AUTH_URI, BaseAuthentication
from restapi.services.detect import detector
from restapi.utilities.logs import log


class TestApp(BaseTests):

    def test_01_login(self, client):
        """ Check that you can login and receive back your token """

        log.info("*** VERIFY CASE INSENSITIVE LOGIN")
        BaseAuthentication.load_default_user()
        BaseAuthentication.load_roles()
        USER = BaseAuthentication.default_user
        PWD = BaseAuthentication.default_password
        self.do_login(client, USER.upper(), PWD)

        # Off course PWD cannot be upper :D
        self.do_login(
            client, USER, PWD.upper(), status_code=401
        )

        log.info("*** VERIFY valid credentials")
        headers, _ = self.do_login(client, None, None)

        time.sleep(5)
        # Verify MAX_PASSWORD_VALIDITY, if set
        headers, _ = self.do_login(client, None, None)

        self.save("auth_header", headers)

        # Verify credentials
        r = client.get(AUTH_URI + '/status', headers=headers)
        assert r.status_code == 200
        c = self.get_content(r)
        assert isinstance(c, bool) and c

        # this check verifies a BUG with neo4j causing crash of auth module
        # when using a non-email-username to authenticate
        log.info("*** VERIFY with a non-email-username")

        self.do_login(
            client,
            'notanemail',
            '[A-Za-z0-9]+',
            status_code=400,
        )

        # Check failure
        log.info("*** VERIFY invalid credentials")

        self.do_login(
            client,
            'sample@nomail.org',
            'ABC-Random-Pass-XYZ',
            status_code=401,
        )

        # Testing Basic Authentication (not allowed)
        valid_credentials = base64.b64encode(
            b'{}:{}'.format(
                BaseAuthentication.default_user,
                BaseAuthentication.default_password,
            )
        ).decode('utf-8')

        headers = {'Authorization': 'Basic ' + valid_credentials}

        r = client.get(
            AUTH_URI + '/login',
            headers=headers
        )
        assert r.status_code == 401

        r = client.get(
            AUTH_URI + '/status',
            headers=headers
        )
        assert r.status_code == 401

        # Sending malformed tokens
        headers = {'Authorization': 'Bearer'}
        r = client.get(
            AUTH_URI + '/status',
            headers=headers
        )
        assert r.status_code == 401

        headers = {'Authorization': 'Bearer \'inject'}
        r = client.get(
            AUTH_URI + '/status',
            headers=headers
        )
        assert r.status_code == 401

    def test_02_GET_profile(self, client):
        """ Check if you can use your token for protected endpoints """

        endpoint = AUTH_URI + '/profile'

        # Check success
        log.info("*** VERIFY valid token")
        r = client.get(endpoint, headers=self.get("auth_header"))
        assert r.status_code == 200
        uuid = self.get_content(r).get('uuid')

        # Check failure
        log.info("*** VERIFY invalid token")
        r = client.get(endpoint)
        assert r.status_code == 401

        # Token created for a fake user
        token = self.get_crafted_token("f")
        headers = {'Authorization': 'Bearer {}'.format(token)}
        r = client.get(endpoint, headers=headers)
        assert r.status_code == 401

        # Token created for another user
        token = self.get_crafted_token("x")
        headers = {'Authorization': 'Bearer {}'.format(token)}
        r = client.get(endpoint, headers=headers)
        assert r.status_code == 401

        # Token created for another user
        token = self.get_crafted_token("f", wrong_algorithm=True)
        headers = {'Authorization': 'Bearer {}'.format(token)}
        r = client.get(endpoint, headers=headers)
        assert r.status_code == 401

        # Token created for another user
        token = self.get_crafted_token("f", wrong_secret=True)
        headers = {'Authorization': 'Bearer {}'.format(token)}
        r = client.get(endpoint, headers=headers)
        assert r.status_code == 401

        # token created for the correct user, but from outside the system!!
        token = self.get_crafted_token("f", user_id=uuid)
        headers = {'Authorization': 'Bearer {}'.format(token)}
        r = client.get(endpoint, headers=headers)
        assert r.status_code == 401

        # Immature token
        token = self.get_crafted_token("f", user_id=uuid, immature=True)
        headers = {'Authorization': 'Bearer {}'.format(token)}
        r = client.get(endpoint, headers=headers)
        assert r.status_code == 401

        # Expired token
        token = self.get_crafted_token("f", user_id=uuid, expired=True)
        headers = {'Authorization': 'Bearer {}'.format(token)}
        r = client.get(endpoint, headers=headers)
        assert r.status_code == 401

    def test_03_change_profile(self, client):

        if not detector.get_bool_from_os("MAIN_LOGIN_ENABLE"):
            log.warning("Profile is disabled, skipping tests")
            return True

        headers, _ = self.do_login(client, None, None)

        # update profile, no auth
        r = client.put(AUTH_URI + "/" + 'profile')
        assert r.status_code == 401
        # update profile, no auth
        r = client.patch(AUTH_URI + "/" + 'profile')
        assert r.status_code == 401

        # update profile, no data
        r = client.patch(AUTH_URI + "/" + 'profile', data={}, headers=headers)
        assert r.status_code == 204

        newname = 'newname'
        newuuid = 'newuuid'

        r = client.get(AUTH_URI + "/" + 'profile', headers=headers)
        assert r.status_code == 200
        c = self.get_content(r)
        assert c.get('name') is not None
        assert c.get('name') != newname
        assert c.get('uuid') is not None
        assert c.get('uuid') != newuuid

        # update profile
        data = {'name': newname, 'uuid': newuuid}
        r = client.patch(AUTH_URI + "/" + 'profile', data=data, headers=headers)
        assert r.status_code == 204

        r = client.get(AUTH_URI + "/" + 'profile', headers=headers)
        assert r.status_code == 200
        c = self.get_content(r)
        assert c.get('name') == newname
        assert c.get('uuid') != newuuid

        # change password, no data
        r = client.put(AUTH_URI + "/" + 'profile', data={}, headers=headers)
        assert r.status_code == 400
        # Sending a new password or a password confirmation without a password
        data = {'new_password': 'new_password'}
        r = client.put(AUTH_URI + "/" + 'profile', data=data, headers=headers)
        assert r.status_code == 400
        data = {'password_confirm': 'new_password'}
        r = client.put(AUTH_URI + "/" + 'profile', data=data, headers=headers)
        assert r.status_code == 400
        data = {'new_password': 'new_password', 'password_confirm': 'new_password'}
        r = client.put(AUTH_URI + "/" + 'profile', data=data, headers=headers)
        assert r.status_code == 400

        data = {}
        data['password'] = self.randomString(length=2)
        r = client.put(AUTH_URI + "/" + 'profile', data=data, headers=headers)
        assert r.status_code == 400

        data['new_password'] = self.randomString(length=2)
        r = client.put(AUTH_URI + "/" + 'profile', data=data, headers=headers)
        assert r.status_code == 400

        data['password_confirm'] = self.randomString(length=2)
        r = client.put(AUTH_URI + "/" + 'profile', data=data, headers=headers)
        assert r.status_code == 400

        data['password'] = BaseAuthentication.default_password
        r = client.put(AUTH_URI + "/" + 'profile', data=data, headers=headers)
        assert r.status_code == 400

        # Passwords are too short
        data['password_confirm'] = data['new_password']
        r = client.put(AUTH_URI + "/" + 'profile', data=data, headers=headers)
        assert r.status_code == 400

        # Trying to set new password == password... it is not permitted!
        data['password_confirm'] = data['password']
        data['new_password'] = data['password']
        r = client.put(AUTH_URI + "/" + 'profile', data=data, headers=headers)
        assert r.status_code == 409

        # Change the password
        data['new_password'] = "Aa1!{}".format(self.randomString())
        data['password_confirm'] = data['new_password']
        r = client.put(AUTH_URI + "/" + 'profile', data=data, headers=headers)
        assert r.status_code == 204

        # verify the new password
        headers, _ = self.do_login(
            client,
            BaseAuthentication.default_user,
            data['new_password']
        )

        # restore the previous password
        data['password'] = data['new_password']
        data['new_password'] = BaseAuthentication.default_password
        data['password_confirm'] = BaseAuthentication.default_password
        r = client.put(AUTH_URI + "/" + 'profile', data=data, headers=headers)
        assert r.status_code == 204

        # verify the new password
        headers, _ = self.do_login(
            client,
            BaseAuthentication.default_user,
            BaseAuthentication.default_password
        )

        self.save("auth_header", headers)

    def test_04_logout(self, client):
        """ Check that you can logout with a valid token """

        endpoint = AUTH_URI + '/logout'

        # Check success
        log.info("*** VERIFY valid token")
        r = client.get(endpoint, headers=self.get("auth_header"))
        assert r.status_code == 204

        # Check failure
        log.info("*** VERIFY invalid token")
        r = client.get(endpoint)
        assert r.status_code == 401
