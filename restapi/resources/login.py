from datetime import datetime, timedelta

import pytz
from flask_apispec import MethodResource, use_kwargs
from marshmallow import fields, validate

from restapi import decorators
from restapi.confs import TESTING
from restapi.exceptions import Forbidden
from restapi.models import InputSchema
from restapi.rest.definition import EndpointResource

auth = EndpointResource.load_authentication()


class Credentials(InputSchema):
    username = fields.Email(required=True)
    password = fields.Str(
        required=True,
        password=True,
        # Otherwise default testing password, like test, will fail
        # validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH)
    )
    new_password = fields.Str(
        required=False,
        password=True,
        validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
    )
    password_confirm = fields.Str(
        required=False,
        password=True,
        validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
    )
    totp_code = fields.Str(required=False)


class Login(MethodResource, EndpointResource):
    """ Let a user login by using the configured method """

    baseuri = "/auth"
    depends_on = ["MAIN_LOGIN_ENABLE"]
    labels = ["authentication"]

    _POST = {
        "/login": {
            "summary": "Login with basic credentials",
            "description": "Normal credentials (username and password) login endpoint",
            "responses": {
                "200": {"description": "Credentials are valid"},
                "401": {"description": "Invalid username or password"},
            },
        }
    }

    @decorators.catch_errors()
    @use_kwargs(Credentials)
    def post(
        self,
        username,
        password,
        new_password=None,
        password_confirm=None,
        totp_code=None,
    ):

        username = username.lower()

        now = datetime.now(pytz.utc)

        # ##################################################
        # Authentication control
        self.auth.verify_blocked_username(username)
        token, payload = self.auth.make_login(username, password)
        user = self.auth.get_user()

        self.auth.verify_blocked_user(user)
        self.auth.verify_active_user(user)

        if self.auth.SECOND_FACTOR_AUTHENTICATION == self.auth.TOTP:
            totp_authentication = True

            # if None will be verified later
            if totp_code is not None:
                self.auth.verify_totp(user, totp_code)

        else:
            totp_authentication = False
            totp_code = None

        # ##################################################
        # If requested, change the password
        if new_password is not None and password_confirm is not None:

            pwd_changed = self.auth.change_password(
                user, password, new_password, password_confirm
            )

            if pwd_changed:
                password = new_password
                token, payload = self.auth.make_login(username, password)

        # ##################################################
        # Check if something is missing in the authentication and ask additional actions
        # raises exceptions in case of errors
        self.verify_information(user, totp_authentication, totp_code)

        # Everything is ok, let's save authentication information

        if user.first_login is None:
            user.first_login = now
        user.last_login = now
        self.auth.save_token(user, token, payload)

        return self.response(token)

    def verify_information(self, user, totp_auth, totp_code):

        message = {"actions": [], "errors": []}

        if totp_auth and totp_code is None:
            message["actions"].append(self.auth.SECOND_FACTOR_AUTHENTICATION)
            message["errors"].append("You do not provided a valid second factor")

        epoch = datetime.fromtimestamp(0, pytz.utc)
        last_pwd_change = user.last_password_change
        if last_pwd_change is None or last_pwd_change == 0:
            last_pwd_change = epoch

        if self.auth.FORCE_FIRST_PASSWORD_CHANGE and last_pwd_change == epoch:

            message["actions"].append("FIRST LOGIN")
            message["errors"].append("Please change your temporary password")

            if totp_auth:

                qr_code = self.auth.get_qrcode(user)

                message["qr_code"] = qr_code

        elif self.auth.MAX_PASSWORD_VALIDITY > 0:

            if last_pwd_change == epoch:
                expired = True
            else:
                td = timedelta(days=self.auth.MAX_PASSWORD_VALIDITY)
                if TESTING:
                    td = timedelta(seconds=self.auth.MAX_PASSWORD_VALIDITY)

                valid_until = last_pwd_change + td

                # MySQL seems unable to save tz-aware datetimes...
                if last_pwd_change.tzinfo is None:
                    # Create a offset-naive datetime
                    now = datetime.now()
                else:
                    # Create a offset-aware datetime
                    now = datetime.now(pytz.utc)

                expired = valid_until < now

            if expired:

                message["actions"].append("PASSWORD EXPIRED")
                message["errors"].append("Your password is expired, please change it")

        if message["errors"]:
            raise Forbidden(message)
