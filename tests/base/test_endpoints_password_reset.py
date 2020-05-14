# -*- coding: utf-8 -*-
import pytest

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
        assert r.status_code == 403
        assert self.get_content(r) == 'Invalid reset email'

        # Request password reset, missing information
        r = client.post(AUTH_URI + '/reset', data={'x': 'y'})
        assert r.status_code == 403
        assert self.get_content(r) == 'Invalid reset email'

        headers, _ = self.do_login(client, None, None)

        # Save the current number of tokens to verify the creation of activation tokens
        r = client.get(API_URI + "/admin/tokens", headers=headers)
        assert r.status_code == 200
        tokens_snapshot = self.get_content(r)
        num_tokens = len(tokens_snapshot)

        # Request password reset, wrong email
        data = {'reset_email': 'y'}
        r = client.post(AUTH_URI + '/reset', data=data)
        assert r.status_code == 403
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
        assert mail.get('body') is not None
        assert mail.get('headers') is not None
        # Subject: is a key in the MIMEText
        assert 'Subject: YourProject Password Reset' in mail.get("headers")
        activation_message = "Follow this link to reset your password: "
        activation_message += "http://localhost/public/reset/"
        assert mail.get('body').startswith(activation_message)

        token = activation_message[1 + activation_message.rfind("/"):]

        r = client.get(API_URI + "/admin/tokens", headers=headers)
        assert r.status_code == 200
        tokens = self.get_content(r)

        # to be enabled
        # assert len(tokens) == num_tokens + 1

        # Do password reset
        r = client.put(AUTH_URI + '/reset/thisisatoken')
        # this token is not valid
        assert r.status_code == 400

        # profile activation
        # r = client.put(AUTH_URI + '/reset/{}'.format(token))
        # assert r.status_code == 204
