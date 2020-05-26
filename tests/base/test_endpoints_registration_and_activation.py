# -*- coding: utf-8 -*-
import re
import urllib.parse
from restapi.tests import BaseTests, AUTH_URI, API_URI, BaseAuthentication
from restapi.services.detect import detector
from restapi.confs import get_project_configuration
from restapi.utilities.logs import log


class TestApp(BaseTests):

    def test_registration(self, client, fake):

        if not detector.get_bool_from_os("ALLOW_REGISTRATION"):
            log.warning("User registration is disabled, skipping tests")
            return True

        project_tile = get_project_configuration(
            'project.title', default='YourProject'
        )

        # registration, empty input
        r = client.post(AUTH_URI + '/profile')
        assert r.status_code == 400

        # registration, missing information
        r = client.post(AUTH_URI + '/profile', data={'x': 'y'})
        assert r.status_code == 400
        registration_data = {}
        registration_data['password'] = fake.password(5)
        r = client.post(AUTH_URI + '/profile', data=registration_data)
        assert r.status_code == 400
        registration_data['email'] = BaseAuthentication.default_user
        r = client.post(AUTH_URI + '/profile', data=registration_data)
        assert r.status_code == 400
        registration_data['name'] = fake.first_name()
        r = client.post(AUTH_URI + '/profile', data=registration_data)
        assert r.status_code == 400

        registration_data['surname'] = fake.last_name()
        r = client.post(AUTH_URI + '/profile', data=registration_data)
        assert r.status_code == 400

        registration_data['password'] = fake.password(strong=True)
        r = client.post(AUTH_URI + '/profile', data=registration_data)
        assert r.status_code == 409
        m = "This user already exists: {}".format(BaseAuthentication.default_user)
        assert self.get_content(r) == m

        registration_data['email'] = fake.ascii_email()
        r = client.post(AUTH_URI + '/profile', data=registration_data)
        # now the user is created but INACTIVE, activation endpoint is needed
        assert r.status_code == 200

        mail = self.read_mock_email()
        body = mail.get('body')
        assert body is not None
        assert mail.get('headers') is not None
        # Subject: is a key in the MIMEText
        assert f'Subject: {project_tile} account activation' in mail.get("headers")
        assert "http://localhost/public/register/" in body
        plain = "Follow this link to activate your account: "
        html = ">click here</a> to activate your account"
        assert html in body or plain in body

        # This will fail because the user is not active
        self.do_login(
            client,
            registration_data['email'],
            registration_data['password'],
            status_code=403,
            # error='Sorry, this account is not active'
        )
        # Also password reset is not allowed
        data = {'reset_email': registration_data['email']}
        r = client.post(AUTH_URI + '/reset', data=data)
        assert r.status_code == 403
        assert self.get_content(r) == 'Sorry, this account is not active'

        # Activation, missing or wrong information
        r = client.post(AUTH_URI + '/profile/activate')
        assert r.status_code == 400
        r = client.post(AUTH_URI + '/profile/activate', data=fake.pydict(2))
        assert r.status_code == 400
        # It isn't an email
        invalid = fake.pystr(10)
        r = client.post(AUTH_URI + '/profile/activate', data={'username': invalid})
        assert r.status_code == 400

        headers, _ = self.do_login(client, None, None)

        # Save the current number of tokens to verify the creation of activation tokens
        r = client.get(API_URI + "/admin/tokens", headers=headers)
        assert r.status_code == 200
        tokens_snapshot = self.get_content(r)
        num_tokens = len(tokens_snapshot)

        activation_message = "We are sending an email to your email address where "
        activation_message += "you will find the link to activate your account"
        # request activation, wrong username
        r = client.post(
            AUTH_URI + '/profile/activate',
            data={'username': fake.ascii_email()}
        )
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
        assert f'Subject: {project_tile} account activation' in mail.get("headers")
        assert "http://localhost/public/register/" in body
        plain = "Follow this link to activate your account: "
        html = ">click here</a> to activate your account"
        assert html in body or plain in body

        if html in body:
            token = re.search(r".*https?://.*/register/(.*)\n", body)[1]
        else:
            token = body[1 + body.rfind("/"):]
        token = urllib.parse.unquote(token)

        # profile activation
        r = client.put(AUTH_URI + '/profile/activate/thisisatoken')
        # this token is not valid
        assert r.status_code == 400

        # profile activation
        r = client.put(AUTH_URI + '/profile/activate/{}'.format(token))
        assert r.status_code == 200
        assert self.get_content(r) == "Account activated"

        # Activation token is no longer valid
        r = client.put(AUTH_URI + '/profile/activate/{}'.format(token))
        assert r.status_code == 400
        assert self.get_content(r) == 'Invalid activation token'

        # Token created for another user
        token = self.get_crafted_token("a")
        r = client.put(AUTH_URI + '/profile/activate/{}'.format(token))
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == 'Invalid activation token'

        # Token created for another user
        token = self.get_crafted_token("a", wrong_algorithm=True)
        r = client.put(AUTH_URI + '/profile/activate/{}'.format(token))
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == 'Invalid activation token'

        # Token created for another user
        token = self.get_crafted_token("a", wrong_secret=True)
        r = client.put(AUTH_URI + '/profile/activate/{}'.format(token))
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == 'Invalid activation token'

        headers, _ = self.do_login(client, None, None)
        r = client.get(AUTH_URI + '/profile', headers=headers)
        assert r.status_code == 200
        uuid = self.get_content(r).get('uuid')

        token = self.get_crafted_token("x", user_id=uuid)
        r = client.put(AUTH_URI + '/profile/activate/{}'.format(token))
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == 'Invalid activation token'

        # token created for the correct user, but from outside the system!!
        token = self.get_crafted_token("a", user_id=uuid)
        r = client.put(AUTH_URI + '/profile/activate/{}'.format(token))
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == 'Invalid activation token'

        # Immature token
        token = self.get_crafted_token("a", user_id=uuid, immature=True)
        r = client.put(AUTH_URI + '/profile/activate/{}'.format(token))
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == 'Invalid activation token'

        # Expired token
        token = self.get_crafted_token("a", user_id=uuid, expired=True)
        r = client.put(AUTH_URI + '/profile/activate/{}'.format(token))
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == 'Invalid activation token: this request is expired'

        # Testing the following use case:
        # 1 - user registration
        # 2 - user activation using unconventional channel, e.g. by admins
        # 3 - user tries to activate and fails because already active

        registration_data['email'] = fake.ascii_email()
        r = client.post(AUTH_URI + '/profile', data=registration_data)
        # now the user is created but INACTIVE, activation endpoint is needed
        assert r.status_code == 200

        mail = self.read_mock_email()
        body = mail.get('body')
        assert body is not None
        assert mail.get('headers') is not None
        assert "http://localhost/public/register/" in body
        html = ">click here</a> to activate your account"

        if html in body:
            token = re.search(r".*https?://.*/register/(.*)\n", body)[1]
        else:
            token = body[1 + body.rfind("/"):]
        token = urllib.parse.unquote(token)

        headers, _ = self.do_login(client, None, None)

        r = client.get(API_URI + "/admin/users", headers=headers)
        assert r.status_code == 200
        users = self.get_content(r)
        uuid = None
        for u in users:
            if u.get('email') == registration_data['email']:
                uuid = u.get('uuid')
                break

        assert uuid is not None
        r = client.put(
            API_URI + "/admin/users/" + uuid,
            data={'is_active': True},
            headers=headers
        )
        assert r.status_code == 204

        r = client.put(AUTH_URI + '/profile/activate/{}'.format(token))
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == "Invalid activation token: this request is no longer valid"

        r = client.get(API_URI + "/admin/tokens", headers=headers)
        content = self.get_content(r)

        uuid = None
        for t in content:
            if t.get('token') == token:
                uuid = t.get(id)
                break
        # The token is invalidated by the error above => no user correspondance found
        assert uuid is None
