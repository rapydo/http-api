from datetime import datetime
from typing import Optional

import pytz

from restapi import decorators
from restapi.endpoints.schemas import Credentials
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import AuthMissingTOTP


class Login(EndpointResource):
    """Let a user login by using the configured method"""

    depends_on = ["MAIN_LOGIN_ENABLE", "AUTH_ENABLE"]
    labels = ["authentication"]

    @decorators.use_kwargs(Credentials)
    @decorators.endpoint(
        path="/auth/login",
        summary="Login by proving your credentials",
        description="Login with basic credentials (username and password)",
        responses={
            200: "Credentials are valid",
            401: "Invalid access credentials",
            403: "Access to this account is not allowed",
        },
    )
    def post(
        self,
        username: str,
        password: str,
        new_password: Optional[str] = None,
        password_confirm: Optional[str] = None,
        totp_code: Optional[str] = None,
    ) -> Response:

        username = username.lower()
        if not self.auth.SECOND_FACTOR_AUTHENTICATION:
            totp_code = None

        # ##################################################
        # Authentication control

        try:
            token, payload, user = self.auth.make_login(username, password, totp_code)
        except AuthMissingTOTP:
            user = self.auth.get_user(username=username)
            message = self.auth.check_password_validity(
                user,
                totp_authentication=self.auth.SECOND_FACTOR_AUTHENTICATION,
            )
            message["actions"].append("TOTP")
            message["errors"].append("You do not provided a valid verification code")
            if message["errors"]:
                return self.response(message, code=403)

        # ##################################################
        # If requested, change the password
        if new_password is not None and password_confirm is not None:

            pwd_changed = self.auth.change_password(
                user, password, new_password, password_confirm
            )

            if pwd_changed:
                password = new_password
                token, payload, user = self.auth.make_login(
                    username, password, totp_code
                )

        message = self.auth.check_password_validity(
            user, totp_authentication=self.auth.SECOND_FACTOR_AUTHENTICATION
        )
        if message["errors"]:
            return self.response(message, code=403)

        # Everything is ok, let's save authentication information

        now = datetime.now(pytz.utc)
        if user.first_login is None:
            user.first_login = now
        user.last_login = now
        self.auth.save_token(user, token, payload)

        self.auth.flush_failed_logins(username)

        return self.response(token)
