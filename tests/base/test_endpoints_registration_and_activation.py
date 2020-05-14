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
        r = client.post(AUTH_URI + '/profile', data={'x': 'y'})
        assert r.status_code == 400
        assert self.get_content(r) == 'Missing input: password'
        registration_data = {}
        registration_data['password'] = self.randomString()
        r = client.post(AUTH_URI + '/profile', data=registration_data)
        assert r.status_code == 400
        assert self.get_content(r) == 'Missing input: email'
        registration_data['email'] = BaseAuthentication.default_user
        r = client.post(AUTH_URI + '/profile', data=registration_data)
        assert r.status_code == 400
        assert self.get_content(r) == 'Missing input: name'
        registration_data['name'] = 'Mr'
        r = client.post(AUTH_URI + '/profile', data=registration_data)
        assert r.status_code == 400
        assert self.get_content(r) == 'Missing input: surname'

        registration_data['surname'] = 'Brown'
        r = client.post(AUTH_URI + '/profile', data=registration_data)
        assert r.status_code == 400
        m = "This user already exists: {}".format(BaseAuthentication.default_user)
        assert self.get_content(r) == m

        registration_data['email'] = 'mock@nomail.org'
        r = client.post(AUTH_URI + '/profile', data=registration_data)
        # now the user is created but INACTIVE, activation endpoint is needed
        assert r.status_code == 200

        mail = self.read_mock_email()
        assert mail.get('body') is not None
        assert mail.get('headers') is not None
        # Subject: is a key in the MIMEText
        assert 'Subject: YourProject account activation' in mail.get("headers")
        activation_message = "Follow this link to activate your account: "
        activation_message += "http://localhost/public/register/"
        assert mail.get('body').startswith(activation_message)

        # This will fail because the user is not active
        self.do_login(
            client,
            registration_data['email'],
            registration_data['password'],
            status_code=403,
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

        assert self.read_mock_email() is None

        r = client.get(API_URI + "/admin/tokens", headers=headers)
        assert r.status_code == 200
        tokens = self.get_content(r)
        assert len(tokens) == num_tokens

        # request activation, correct username
        r = client.post(
            AUTH_URI + '/profile/activate',
            data={'username': registration_data['email']}
        )
        assert r.status_code == 200
        assert self.get_content(r) == activation_message

        r = client.get(API_URI + "/admin/tokens", headers=headers)
        assert r.status_code == 200
        tokens = self.get_content(r)

        # to be enabled
        # assert len(tokens) == num_tokens + 1

        mail = self.read_mock_email()
        body = mail.get('body')
        assert body is not None
        assert mail.get('headers') is not None
        # Subject: is a key in the MIMEText
        assert 'Subject: YourProject account activation' in mail.get("headers")
        activation_message = "Follow this link to activate your account: "
        activation_message += "http://localhost/public/register/"
        assert body.startswith(activation_message)

        token = body[1 + body.rfind("/"):]

        # profile activation
        r = client.put(AUTH_URI + '/profile/activate/thisisatoken')
        # this token is not valid
        assert r.status_code == 400

        # profile activation
        # r = client.put(AUTH_URI + '/profile/activate/{}'.format(token))
        # assert r.status_code == 200
        # assert self.get_content(r) == "Account activated"

        # # Activation token is no longer valid
        # r = client.put(AUTH_URI + '/profile/activate/{}'.format(token))
        # assert r.status_code == 200
        # assert self.get_content(r) == "Account activated"
