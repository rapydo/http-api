# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
import pytz

from restapi.rest.definition import EndpointResource
from restapi.exceptions import RestApiException
from restapi.flask_ext.flask_auth import HandleSecurity
from restapi import decorators as decorate
from restapi.confs import WRAP_RESPONSE

from restapi.utilities.htmlcodes import hcodes


class Login(EndpointResource):
    """ Let a user login by using the configured method """

    baseuri = "/auth"
    depends_on = ["MAIN_LOGIN_ENABLE"]
    labels = ["authentication"]

    POST = {
        "/login": {
            "summary": "Login with basic credentials",
            "description": "Normal credentials (username and password) login endpoint",
            "parameters": [
                {
                    "name": "credentials",
                    "in": "body",
                    "schema": {"$ref": "#/definitions/Credentials"},
                }
            ],
            "responses": {
                "200": {"description": "Credentials are valid"},
                "401": {"description": "Invalid username or password"},
            },
        }
    }

    def verify_information(self, user, security, totp_auth, totp_code, now=None):

        message = {
            'actions': [],
            'errors': []
        }

        if totp_auth and totp_code is None:
            message['actions'].append(self.auth.SECOND_FACTOR_AUTHENTICATION)
            message['errors'].append("You do not provided a valid second factor")

        epoch = datetime.fromtimestamp(0, pytz.utc)
        last_pwd_change = user.last_password_change
        if last_pwd_change is None or last_pwd_change == 0:
            last_pwd_change = epoch

        if self.auth.FORCE_FIRST_PASSWORD_CHANGE and last_pwd_change == epoch:

            message['actions'].append('FIRST LOGIN')
            message['errors'].append("Please change your temporary password")

            if totp_auth:

                qr_code = security.get_qrcode(user)

                message["qr_code"] = qr_code

        elif self.auth.MAX_PASSWORD_VALIDITY > 0:

            if last_pwd_change == epoch:
                expired = True
            else:
                valid_until = last_pwd_change + timedelta(
                    days=self.auth.MAX_PASSWORD_VALIDITY
                )

                if now is None:
                    now = datetime.now(pytz.utc)
                expired = valid_until < now

            if expired:

                message['actions'].append('PASSWORD EXPIRED')
                message['errors'].append("Your password is expired, please change it")

        if not message['errors']:
            return None

        return self.response(
            errors=message, code=hcodes.HTTP_BAD_FORBIDDEN
        )

    @decorate.catch_error()
    def post(self):

        jargs = self.get_input()

        username = jargs.get('username')
        if username is None:
            username = jargs.get('email')

        password = jargs.get('password')
        if password is None:
            password = jargs.get('pwd')

        # Now credentials are checked at every request
        if username is None or password is None:
            msg = "Missing username or password"
            raise RestApiException(msg, status_code=hcodes.HTTP_BAD_UNAUTHORIZED)

        username = username.lower()
        now = datetime.now(pytz.utc)

        new_password = jargs.get('new_password')
        password_confirm = jargs.get('password_confirm')

        totp_authentication = (
            self.auth.SECOND_FACTOR_AUTHENTICATION is not None
            and self.auth.SECOND_FACTOR_AUTHENTICATION == self.auth.TOTP
        )

        if totp_authentication:
            totp_code = jargs.get('totp_code')
        else:
            totp_code = None

        security = HandleSecurity(self.auth)
        # ##################################################
        # Authentication control
        security.verify_blocked_username(username)
        token, jti = self.auth.make_login(username, password)
        security.verify_token(username, token)
        user = self.auth.get_user()
        security.verify_blocked_user(user)
        security.verify_active_user(user)

        if totp_authentication and totp_code is not None:
            security.verify_totp(user, totp_code)

        # ##################################################
        # If requested, change the password
        if new_password is not None and password_confirm is not None:

            pwd_changed = security.change_password(
                user, password, new_password, password_confirm
            )

            if pwd_changed:
                password = new_password
                token, jti = self.auth.make_login(username, password)

        # ##################################################
        # Something is missing in the authentication, asking action to user
        ret = self.verify_information(
            user, security, totp_authentication, totp_code, now
        )
        if ret is not None:
            return ret

        # Everything is ok, let's save authentication information

        if user.first_login is None:
            user.first_login = now
        user.last_login = now
        self.auth.save_token(user, token, jti)

        if WRAP_RESPONSE:
            return self.response({'token': token})
        return self.response(token)
