from typing import Optional

import jwt

from restapi import decorators
from restapi.config import get_frontend_url
from restapi.connectors import Connector
from restapi.connectors.smtp.notifications import send_password_reset_link
from restapi.env import Env
from restapi.exceptions import BadRequest, Forbidden, ServiceUnavailable
from restapi.models import fields, validate
from restapi.rest.definition import EndpointResource, Response
from restapi.utilities.logs import log

auth = Connector.get_authentication_instance()


# This endpoint require the server to send the reset token via email
if Connector.check_availability("smtp"):

    class RecoverPassword(EndpointResource):

        depends_on = ["MAIN_LOGIN_ENABLE", "ALLOW_PASSWORD_RESET", "AUTH_ENABLE"]
        labels = ["authentication"]

        @decorators.use_kwargs({"reset_email": fields.Email(required=True)})
        @decorators.endpoint(
            path="/auth/reset",
            summary="Request password reset via email",
            description="Request password reset via email",
            responses={
                200: "Reset email is valid",
                400: "Invalid reset email",
                403: "Account not found or already active",
            },
        )
        def post(self, reset_email: str) -> Response:

            reset_email = reset_email.lower()

            self.auth.verify_blocked_username(reset_email)

            user = self.auth.get_user(username=reset_email)

            if user is None:
                raise Forbidden(
                    f"Sorry, {reset_email} is not recognized as a valid username",
                )

            self.auth.verify_user_status(user)

            reset_token, payload = self.auth.create_temporary_token(
                user, self.auth.PWD_RESET
            )

            server_url = get_frontend_url()

            rt = reset_token.replace(".", "+")

            uri = Env.get("RESET_PASSWORD_URI", "/public/reset")
            complete_uri = f"{server_url}{uri}/{rt}"

            sent = send_password_reset_link(user, complete_uri, reset_email)

            if not sent:  # pragma: no cover
                raise ServiceUnavailable("Error sending email, please retry")

            ##################
            # Completing the reset task
            self.auth.save_token(
                user, reset_token, payload, token_type=self.auth.PWD_RESET
            )

            msg = "We'll send instructions to the email provided if it's associated "
            msg += "with an account. Please check your spam/junk folder."

            self.log_event(self.events.reset_password_request, user=user)
            return self.response(msg)

        @decorators.use_kwargs(
            {
                "new_password": fields.Str(
                    required=False,
                    validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
                    metadata={"password": True},
                ),
                "password_confirm": fields.Str(
                    required=False,
                    validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
                    metadata={"password": True},
                ),
            }
        )
        @decorators.endpoint(
            path="/auth/reset/<token>",
            summary="Change password as conseguence of a reset request",
            description="Change password as conseguence of a reset request",
            responses={
                200: "Reset token is valid, password changed",
                400: "Invalid reset token",
            },
        )
        def put(
            self,
            token: str,
            new_password: Optional[str] = None,
            password_confirm: Optional[str] = None,
        ) -> Response:

            token = token.replace("%2B", ".")
            token = token.replace("+", ".")

            try:
                # valid, token, jti, user
                _, _, jti, user = self.auth.verify_token(
                    token, raiseErrors=True, token_type=self.auth.PWD_RESET
                )

            # If token is expired
            except jwt.exceptions.ExpiredSignatureError:
                raise BadRequest("Invalid reset token: this request is expired")

            # if token is not active yet
            except jwt.exceptions.ImmatureSignatureError as e:
                log.info(e)
                raise BadRequest("Invalid reset token")
            # if token does not exist (or other generic errors)
            except Exception as e:
                log.info(e)
                raise BadRequest("Invalid reset token")

            if user is None:  # pragma: no cover
                raise BadRequest("Invalid activation token")

            # Recovering token object from jti
            tokens_obj = self.auth.get_tokens(token_jti=jti)
            # Can't happen because the token is refused from verify_token function
            if len(tokens_obj) == 0:  # pragma: no cover
                raise BadRequest("Invalid reset token: this request is no longer valid")

            token_obj = tokens_obj.pop(0)
            emitted = token_obj["emitted"]

            last_change = None
            # If user logged in after the token emission invalidate the token
            if user.last_login is not None:
                last_change = user.last_login
            # If user changed the pwd after the token emission invalidate the token
            # Can't happen because the change password also invalidated the token
            elif user.last_password_change is not None:  # pragma: no cover
                last_change = user.last_password_change

            if last_change is not None:

                # Can't happen because the change password also invalidated the token
                if last_change > emitted:  # pragma: no cover
                    self.auth.invalidate_token(token)
                    raise BadRequest(
                        "Invalid reset token: this request is no longer valid",
                    )

            # The reset token is valid, do something

            # No password to be changed, just a token verification
            if new_password is None and password_confirm is None:
                return self.empty_response()

            # Something is missing
            if new_password is None or password_confirm is None:
                raise BadRequest("Invalid password")

            if new_password != password_confirm:
                raise BadRequest("New password does not match with confirmation")

            self.auth.change_password(
                user, user.password, new_password, password_confirm
            )
            # I really don't know why this save is required... since it is already
            # in change_password ... But if I remove it the new pwd is not saved...
            self.auth.save_user(user)

            # Bye bye token (reset tokens are valid only once)
            self.auth.invalidate_token(token)

            return self.response("Password changed")
