# -*- coding: utf-8 -*-
from restapi.tests import BaseTests, AUTH_URI
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

        # Request password reset, wrong email
        r = client.post(AUTH_URI + '/reset', data={'reset_email': 'y'})
        assert r.status_code == 403
        assert self.get_content(r) == 'Sorry, y is not recognized as a valid username'

        # Do password reset
        r = client.put(AUTH_URI + '/reset/thisisatoken')
        # this token is not valid
        assert r.status_code == 400
