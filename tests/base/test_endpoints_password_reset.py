# -*- coding: utf-8 -*-
import os
import re
import urllib.parse

from restapi.tests import BaseTests, API_URI, AUTH_URI, BaseAuthentication
from restapi.services.detect import detector
from restapi.utilities.logs import log


class TestApp(BaseTests):

    def test_password_reset(self, client):

        if not detector.get_bool_from_os("ALLOW_PASSWORD_RESET"):
            log.warning("Password reset is disabled, skipping tests")
            return True

        # Request password reset, missing information
        r = client.post(AUTH_URI + '/reset')
        assert r.status_code == 400

        # Request password reset, missing information
        r = client.post(AUTH_URI + '/reset', data={'x': 'y'})
        assert r.status_code == 400

        headers, _ = self.do_login(client, None, None)

        # Save the current number of tokens to verify the creation of activation tokens
        r = client.get(API_URI + "/admin/tokens", headers=headers)
        assert r.status_code == 200
        tokens_snapshot = self.get_content(r)
        num_tokens = len(tokens_snapshot)

        # Request password reset, wrong email
        data = {'reset_email': 'sample@nomail.org'}
        r = client.post(AUTH_URI + '/reset', data=data)
        assert r.status_code == 400
        assert self.get_content(r) == 'Sorry, y is not recognized as a valid username'

        r = client.get(API_URI + "/admin/tokens", headers=headers)
        assert r.status_code == 200
        tokens = self.get_content(r)
        assert len(tokens) == num_tokens

        # Request password reset, correct email
        data = {'reset_email': BaseAuthentication.default_user}
        r = client.post(AUTH_URI + '/reset', data=data)
        assert r.status_code == 200
        resetmsg = "You will shortly receive an email with a link to a page where "
        resetmsg += "you can create a new password, please check your spam/junk folder."
        assert self.get_content(r) == resetmsg

        mail = self.read_mock_email()
        body = mail.get('body')
        assert body is not None
        assert mail.get('headers') is not None
        # Subject: is a key in the MIMEText
        assert 'Subject: YourProject Password Reset' in mail.get("headers")
        assert "http://localhost/public/reset/" in body
        plain = "Follow this link to reset your password: "
        html = ">click here</a> to reset your password"
        assert html in body or plain in body

        if html in body:
            token = re.search(r".*https?://.*/reset/(.*)\n", body)[1]
        else:
            token = body[1 + body.rfind("/"):]
        token = urllib.parse.unquote(token)

        r = client.get(API_URI + "/admin/tokens", headers=headers)
        assert r.status_code == 200
        tokens = self.get_content(r)
        assert len(tokens) == num_tokens + 1

        # Do password reset
        r = client.put(AUTH_URI + '/reset/thisisatoken')
        # this token is not valid
        assert r.status_code == 400

        # Check if token is valid
        r = client.put(AUTH_URI + '/reset/{}'.format(token))
        assert r.status_code == 204

        # Token is still valid because no password still sent
        r = client.put(AUTH_URI + '/reset/{}'.format(token))
        assert r.status_code == 204

        data = {}
        data['new_password'] = "Aa1!" + self.randomString(length=2)
        data['password_confirm'] = "Bb1!" + self.randomString(length=2)
        r = client.put(AUTH_URI + '/reset/{}'.format(token), data=data)
        assert r.status_code == 400
        assert self.get_content(r) == 'New password does not match with confirmation'

        min_pwd_len = int(os.getenv("AUTH_MIN_PASSWORD_LENGTH", 9999))

        data['password_confirm'] = data['new_password']
        r = client.put(AUTH_URI + '/reset/{}'.format(token), data=data)
        assert r.status_code == 409
        ret_text = self.get_content(r)
        assert ret_text == 'Password is too short, use at least {} characters'.format(
            min_pwd_len
        )

        new_pwd = "Cc!4" + self.randomString(length=min_pwd_len)
        data['new_password'] = new_pwd
        data['password_confirm'] = new_pwd
        r = client.put(AUTH_URI + '/reset/{}'.format(token), data=data)
        assert r.status_code == 200

        self.do_login(client, None, None, status_code=401)
        headers, _ = self.do_login(client, None, new_pwd)

        # Token is no longer valid
        r = client.put(AUTH_URI + '/reset/{}'.format(token))
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == 'Invalid reset token'

        # Restore the default password
        data['password'] = new_pwd
        data['new_password'] = BaseAuthentication.default_password
        data['password_confirm'] = data['new_password']
        r = client.put(AUTH_URI + "/" + 'profile', data=data, headers=headers)
        assert r.status_code == 204

        self.do_login(client, None, new_pwd, status_code=401)
        self.do_login(client, None, None)

        # Token created for another user
        token = self.get_crafted_token("r")
        r = client.put(AUTH_URI + '/reset/{}'.format(token))
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == 'Invalid reset token'

        # Token created for another user
        token = self.get_crafted_token("r", wrong_algorithm=True)
        r = client.put(AUTH_URI + '/reset/{}'.format(token))
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == 'Invalid reset token'

        # Token created for another user
        token = self.get_crafted_token("r", wrong_secret=True)
        r = client.put(AUTH_URI + '/reset/{}'.format(token))
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == 'Invalid reset token'

        headers, _ = self.do_login(client, None, None)
        r = client.get(AUTH_URI + '/profile', headers=headers)
        assert r.status_code == 200
        uuid = self.get_content(r).get('uuid')

        token = self.get_crafted_token("x", user_id=uuid)
        r = client.put(AUTH_URI + '/reset/{}'.format(token))
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == 'Invalid reset token'

        # token created for the correct user, but from outside the system!!
        token = self.get_crafted_token("r", user_id=uuid)
        r = client.put(AUTH_URI + '/reset/{}'.format(token))
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == 'Invalid reset token'

        # Immature token
        token = self.get_crafted_token("r", user_id=uuid, immature=True)
        r = client.put(AUTH_URI + '/reset/{}'.format(token))
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == 'Invalid reset token'

        # Expired token
        token = self.get_crafted_token("r", user_id=uuid, expired=True)
        r = client.put(AUTH_URI + '/reset/{}'.format(token))
        assert r.status_code == 400
        c = self.get_content(r)
        assert c == 'Invalid reset token: this request is expired'
