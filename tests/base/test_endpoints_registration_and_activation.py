# -*- coding: utf-8 -*-
from restapi.tests import BaseTests, AUTH_URI, API_URI, BaseAuthentication
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
        # now the user is created but INACTIVE, activation endpoint is needed
        assert r.status_code == 200

        # This will fail because the user is not active
        self.do_login(
            client,
            data['email'],
            data['password'],
            status_code=401,
            # error='Sorry, this account is not active'
        )
        # Also password reset is not allowed
        data = {'reset_email': 'mock@nomail.org'}
        r = client.post(AUTH_URI + '/reset', data=data)
        assert r.status_code == 403
        assert self.get_content(r) == 'Sorry, this account is not active'

        # Ask a new activation link
        r = client.post(AUTH_URI + '/profile/activate')
        assert r.status_code == 400
        assert self.get_content(r) == 'Empty input'

        # activation, missing information
        r = client.post(AUTH_URI + '/profile/activate', data={'x': 'y'})
        assert r.status_code == 400
        assert self.get_content(r) == 'Missing required input: username'

        headers, _ = self.do_login(client, None, None)

        # Save the current number of tokens to verify the creation of activation tokens
        r = client.get(API_URI + "/admin/tokens", headers=headers)
        assert r.status_code == 200
        tokens_snapshot = self.get_content(r)
        num_tokens = len(tokens_snapshot)

        activation_message = "We are sending an email to your email address where "
        activation_message += "you will find the link to activate your account"
        # request activation, wrong username
        r = client.post(AUTH_URI + '/profile/activate', data={'username': 'y'})
        # return is 200, but no token will be generated and no mail will be sent
        # but it respond with the activation msg and hides the non existence of the user
        assert r.status_code == 200
        assert self.get_content(r) == activation_message

        r = client.get(API_URI + "/admin/tokens", headers=headers)
        assert r.status_code == 200
        tokens = self.get_content(r)

        assert len(tokens) == num_tokens

        # request activation, correct username
        r = client.post(
            AUTH_URI + '/profile/activate', data={'username': data['email']})
        # return is 200, but no token will be generated and no mail will be sent
        assert r.status_code == 200
        assert self.get_content(r) == activation_message

        r = client.get(API_URI + "/admin/tokens", headers=headers)
        assert r.status_code == 200
        tokens = self.get_content(r)

        # to be enabled
        # assert len(tokens) == num_tokens + 1

        # profile activation
        r = client.put(AUTH_URI + '/profile/activate/thisisatoken')
        # this token is not valid
        assert r.status_code == 400
