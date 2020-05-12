# -*- coding: utf-8 -*-
from restapi.tests import BaseTests, AUTH_URI, BaseAuthentication
from restapi.services.detect import detector
from restapi.utilities.logs import log


class TestApp(BaseTests):

    def test_registration(self, client):

        if not detector.get_bool_from_os("ALLOW_REGISTRATION"):
            log.warning("User registration is disabled, skipping tests")
            return True

        # registration, empty input
        r = client.post(AUTH_URI + '/profile')
        assert r.status_code == 400
        assert self.get_content(r) == 'Empty input'

        # registration, missing information
        data = {'x': 'y'}
        r = client.post(AUTH_URI + '/profile', data=data)
        assert r.status_code == 400
        assert self.get_content(r) == 'Missing input: password'
        data = {}
        data['password'] = self.randomString()
        r = client.post(AUTH_URI + '/profile', data=data)
        assert r.status_code == 400
        assert self.get_content(r) == 'Missing input: email'
        data['email'] = BaseAuthentication.default_user
        r = client.post(AUTH_URI + '/profile', data=data)
        assert r.status_code == 400
        assert self.get_content(r) == 'Missing input: name'
        data['name'] = 'Mr'
        r = client.post(AUTH_URI + '/profile', data=data)
        assert r.status_code == 400
        assert self.get_content(r) == 'Missing input: surname'

        data['surname'] = 'Brown'
        r = client.post(AUTH_URI + '/profile', data=data)
        assert r.status_code == 400
        m = "This user already exists: {}".format(BaseAuthentication.default_user)
        assert self.get_content(r) == m

        data['email'] = 'mock@nomail.org'
        r = client.post(AUTH_URI + '/profile', data=data)
        # now the user is created, but inactive...
        # how to get the token sent via email???
        assert r.status_code == 200

        # profile activation
        r = client.put(AUTH_URI + '/profile/activate/thisisatoken')
        # this token is not valid
        assert r.status_code == 400

        # Ask a new activation link
        r = client.post(AUTH_URI + '/profile/activate')
        assert r.status_code == 400
        assert self.get_content(r) == 'Empty input'

        # activation, missing information
        r = client.post(AUTH_URI + '/profile/activate', data={'x': 'y'})
        assert r.status_code == 400
        assert self.get_content(r) == 'Missing required input: username'

        # activation, wrong username
        r = client.post(AUTH_URI + '/profile/activate', data={'username': 'y'})
        # return is 200, ma no mail will be sent... how to test this??
        assert r.status_code == 200