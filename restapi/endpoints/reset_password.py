from typing import Optional

import jwt

from restapi import decorators
from restapi.config import get_frontend_url, get_project_configuration
from restapi.connectors import smtp
from restapi.env import Env
from restapi.exceptions import BadRequest, Forbidden, RestApiException
from restapi.models import fields, validate
from restapi.rest.definition import EndpointResource
from restapi.services.detect import detector
from restapi.utilities.logs import log
from restapi.utilities.templates import get_html_template

auth = detector.get_authentication_instance()


def send_password_reset_link(smtp, uri, title, reset_email):
    # Internal templating
    body: Optional[str] = f"Follow this link to reset your password: {uri}"
    html_body = get_html_template("reset_password.html", {"url": uri})
    if html_body is None:
        log.warning("Unable to find email template")
        html_body = body
        body = None
    subject = f"{title} Password Reset"

    # Internal email sending
    c = smtp.send(html_body, subject, reset_email, plain_body=body)
    # it cannot fail during tests, because the email sending is mocked
    if not c:  # pragma: no cover
        raise RestApiException("Error sending email, please retry")


# This endpoint require the server to send the reset token via email
if detector.check_availability("smtp"):

    class RecoverPassword(EndpointResource):

        baseuri = "/auth"
        depends_on = ["MAIN_LOGIN_ENABLE", "ALLOW_PASSWORD_RESET"]
        labels = ["authentication"]

        @decorators.use_kwargs({"reset_email": fields.Email(required=True)})
        @decorators.endpoint(
            path="/reset",
            summary="Request password reset via email",
            description="Request password reset via email",
            responses={
                200: "Reset email is valid",
                401: "Invalid reset email",
                403: "Account not found or already active",
            },
        )
        def post(self, reset_email):

            reset_email = reset_email.lower()

            user = self.auth.get_user(username=reset_email)

            if user is None:
                raise Forbidden(
                    f"Sorry, {reset_email} is not recognized as a valid username",
                )

            if user.is_active is not None and not user.is_active:
                # Beware, frontend leverages on this exact message,
                # do not modified it without fix also on frontend side
                raise Forbidden("Sorry, this account is not active")

            title = get_project_configuration("project.title", default="Unkown title")

            reset_token, payload = self.auth.create_temporary_token(
                user, self.auth.PWD_RESET
            )

            server_url = get_frontend_url()

            rt = reset_token.replace(".", "+")

            uri = Env.get("RESET_PASSWORD_URI", "/public/reset")
            complete_uri = f"{server_url}{uri}/{rt}"

            smtp_client = smtp.get_instance()
            send_password_reset_link(smtp_client, complete_uri, title, reset_email)

            ##################
            # Completing the reset task
            self.auth.save_token(
                user, reset_token, payload, token_type=self.auth.PWD_RESET
            )

            msg = "We'll send instructions to the email provided if it's associated "
            msg += "with an account. Please check your spam/junk folder."
            return self.response(msg)

        @decorators.use_kwargs(
            {
                "new_password": fields.Str(
                    required=False,
                    password=True,
                    validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
                ),
                "password_confirm": fields.Str(
                    required=False,
                    password=True,
                    validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
                ),
            }
        )
        @decorators.endpoint(
            path="/reset/<token>",
            summary="Change password as conseguence of a reset request",
            description="Change password as conseguence of a reset request",
            responses={
                200: "Reset token is valid, password changed",
                401: "Invalid reset token",
            },
        )
        def put(self, token, new_password=None, password_confirm=None):

            token = token.replace("%2B", ".")
            token = token.replace("+", ".")
            try:
                unpacked_token = self.auth.verify_token(
                    token, raiseErrors=True, token_type=self.auth.PWD_RESET
                )

            # If token is expired
            except jwt.exceptions.ExpiredSignatureError:
                raise BadRequest("Invalid reset token: this request is expired")

            # if token is not yet active
            except jwt.exceptions.ImmatureSignatureError as e:
                log.info(e)
                raise BadRequest("Invalid reset token")
            # if token does not exist (or other generic errors)
            except BaseException as e:
                log.info(e)
                raise BadRequest("Invalid reset token")

            # Recovering token object from jti
            jti = unpacked_token[2]
            token_obj = self.auth.get_tokens(token_jti=jti)
            if len(token_obj) == 0:
                raise BadRequest("Invalid reset token: this request is no longer valid")

            token_obj = token_obj.pop(0)
            emitted = token_obj["emitted"]
            user = unpacked_token[3]

            last_change = None
            # If user logged in after the token emission invalidate the token
            if user.last_login is not None:
                last_change = user.last_login
            # If user changed the pwd after the token emission invalidate the token
            elif user.last_password_change is not None:
                last_change = user.last_password_change

            if last_change is not None:

                if last_change > emitted:
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
