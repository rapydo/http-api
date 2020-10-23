from datetime import datetime

import pytz

from restapi import decorators
from restapi.exceptions import Forbidden
from restapi.models import Schema, fields, validate
from restapi.rest.definition import EndpointResource
from restapi.utilities.time import EPOCH, get_now

auth = EndpointResource.load_authentication()


class Credentials(Schema):
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


class Login(EndpointResource):
    """ Let a user login by using the configured method """

    baseuri = "/auth"
    depends_on = ["MAIN_LOGIN_ENABLE"]
    labels = ["authentication"]

    @decorators.use_kwargs(Credentials)
    @decorators.endpoint(
        path="/login",
        summary="Login with basic credentials",
        description="Login with normal credentials (username and password)",
        responses={200: "Credentials are valid", 401: "Invalid username or password"},
    )
    def post(
        self,
        username,
        password,
        new_password=None,
        password_confirm=None,
        totp_code=None,
    ):

        username = username.lower()

        # ##################################################
        # Authentication control
        # self.auth.verify_blocked_username(username)
        token, payload, user = self.auth.make_login(username, password)

        self.auth.verify_blocked_user(user)
        self.auth.verify_active_user(user)

        totp_authentication = self.auth.SECOND_FACTOR_AUTHENTICATION == self.auth.TOTP

        if totp_authentication:

            if totp_code is None:
                message = self.check_password_validity(user, totp_authentication)
                message["actions"].append(self.auth.SECOND_FACTOR_AUTHENTICATION)
                message["errors"].append("You do not provided a valid second factor")
                if message["errors"]:
                    raise Forbidden(message)

            self.auth.verify_totp(user, totp_code)

        # ##################################################
        # If requested, change the password
        if new_password is not None and password_confirm is not None:

            pwd_changed = self.auth.change_password(
                user, password, new_password, password_confirm
            )

            if pwd_changed:
                password = new_password
                token, payload, user = self.auth.make_login(username, password)

        message = self.check_password_validity(user, totp_authentication)
        if message["errors"]:
            raise Forbidden(message)

        # Everything is ok, let's save authentication information

        now = datetime.now(pytz.utc)
        if user.first_login is None:
            user.first_login = now
        user.last_login = now
        self.auth.save_token(user, token, payload)

        return self.response(token)

    def check_password_validity(self, user, totp_authentication):

        # ##################################################
        # Check if something is missing in the authentication and ask additional actions
        # raises exceptions in case of errors

        message = {"actions": [], "errors": []}
        last_pwd_change = user.last_password_change
        if last_pwd_change is None or last_pwd_change == 0:
            last_pwd_change = EPOCH

        if self.auth.FORCE_FIRST_PASSWORD_CHANGE and last_pwd_change == EPOCH:

            message["actions"].append("FIRST LOGIN")
            message["errors"].append("Please change your temporary password")

            if totp_authentication:

                qr_url, qr_code = self.auth.get_qrcode(user)

                message["qr_code"] = qr_code
                message["qr_url"] = qr_url

        elif self.auth.MAX_PASSWORD_VALIDITY:

            valid_until = last_pwd_change + self.auth.MAX_PASSWORD_VALIDITY

            # offset-naive datetime to compare with MySQL
            now = get_now(last_pwd_change.tzinfo)

            expired = last_pwd_change == EPOCH or valid_until < now

            if expired:

                message["actions"].append("PASSWORD EXPIRED")
                message["errors"].append("Your password is expired, please change it")

        return message
