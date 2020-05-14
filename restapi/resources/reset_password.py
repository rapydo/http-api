# -*- coding: utf-8 -*-

import os
import jwt
import pytz

from restapi.rest.definition import EndpointResource
from restapi import decorators
from restapi.exceptions import RestApiException
from restapi.services.detect import detector
from restapi.services.mail import send_mail, send_mail_is_active
from restapi.confs import PRODUCTION, get_project_configuration
from restapi.connectors.authentication import HandleSecurity
from restapi.utilities.templates import get_html_template

from restapi.utilities.logs import log


def send_password_reset_link(uri, title, reset_email):
    # Internal templating
    body = "Follow this link to reset your password: {}".format(uri)
    html_body = get_html_template("reset_password.html", {"url": uri})
    if html_body is None:
        log.warning("Unable to find email template")
        html_body = body
        body = None
    subject = "{} Password Reset".format(title)

    # Internal email sending
    c = send_mail(html_body, subject, reset_email, plain_body=body)
    # it cannot fail during tests, because the email sending is mocked
    if not c:  # pragma: no cover
        raise RestApiException("Error sending email, please retry")


class RecoverPassword(EndpointResource):

    baseuri = "/auth"
    depends_on = ["MAIN_LOGIN_ENABLE", "ALLOW_PASSWORD_RESET"]
    labels = ["authentication"]

    POST = {
        "/reset": {
            "summary": "Request password reset via email",
            "description": "Request password reset via email",
            "responses": {
                "200": {"description": "Reset email is valid"},
                "401": {"description": "Invalid reset email"},
            },
        }
    }
    PUT = {
        "/reset/<token_id>": {
            "summary": "Change password as conseguence of a reset request",
            "description": "Change password as conseguence of a reset request",
            "responses": {
                "200": {"description": "Reset token is valid, password changed"},
                "401": {"description": "Invalid reset token"},
                "503": {"description": "Server misconfiguration, password cannot be reset"},
            },
        }
    }

    @decorators.catch_errors()
    def post(self):

        # always active (and mocked) during tests, cannot be tested
        if not send_mail_is_active():  # pragma: no cover
            log.error("Send mail is not active")
            raise RestApiException(
                {'Server misconfiguration': 'Password cannot be reset'},
                status_code=503,
            )

        reset_email = self.get_input(single_parameter='reset_email')

        if reset_email is None:
            raise RestApiException(
                'Invalid reset email',
                # FORBIDDEN
                status_code=403
            )

        reset_email = reset_email.lower()

        user = self.auth.get_user_object(username=reset_email)

        if user is None:
            raise RestApiException(
                'Sorry, {} is not recognized as a valid username'.format(reset_email),
                # FORBIDDEN
                status_code=403,
            )

        if user.is_active is not None and not user.is_active:
            # Beware, frontend leverages on this exact message,
            # do not modified it without fix also on frontend side
            raise RestApiException(
                "Sorry, this account is not active",
                status_code=403,
            )

        title = get_project_configuration(
            "project.title", default='Unkown title'
        )

        reset_token, payload = self.auth.create_temporary_token(
            user, self.auth.PWD_RESET)

        domain = os.environ.get("DOMAIN")
        protocol = 'https' if PRODUCTION else 'http'

        rt = reset_token.replace(".", "+")

        var = "RESET_PASSWORD_URI"
        uri = detector.get_global_var(key=var, default='/public/reset')
        complete_uri = "{}://{}{}/{}".format(protocol, domain, uri, rt)

        send_password_reset_link(complete_uri, title, reset_email)

        ##################
        # Completing the reset task
        self.auth.save_token(
            user, reset_token, payload, token_type=self.auth.PWD_RESET)

        msg = "You will shortly receive an email with a link to a page where "
        msg += "you can create a new password, please check your spam/junk folder."

        return self.response(msg)

    @decorators.catch_errors()
    def put(self, token_id):

        token_id = token_id.replace("+", ".")
        try:
            # Unpack and verify token. If ok, self.auth will be added with
            # auth._user auth._token and auth._jti
            valid = self.auth.verify_token(
                token_id, raiseErrors=True, token_type=self.auth.PWD_RESET
            )
            if not valid:
                raise RestApiException("Invalid activation token", status_code=403)

        # If token is expired
        except jwt.exceptions.ExpiredSignatureError:
            raise RestApiException(
                'Invalid reset token: this request is expired',
                status_code=400,
            )

        # if token is not yet active
        except jwt.exceptions.ImmatureSignatureError:
            raise RestApiException(
                'Invalid reset token', status_code=400
            )

        # if token does not exist (or other generic errors)
        except Exception:
            raise RestApiException(
                'Invalid reset token', status_code=400
            )

        # Recovering token object from jti
        token = self.auth.get_tokens(token_jti=self.auth._jti)
        if len(token) == 0:
            raise RestApiException(
                'Invalid reset token: this request is no longer valid',
                status_code=400,
            )

        token = token.pop(0)
        emitted = token["emitted"]

        last_change = None
        # If user logged in after the token emission invalidate the token
        if self.auth._user.last_login is not None:
            last_change = self.auth._user.last_login
        # If user changed the pwd after the token emission invalidate the token
        elif self.auth._user.last_password_change is not None:
            last_change = self.auth._user.last_password_change

        if last_change is not None:

            try:
                expired = last_change >= emitted
            except TypeError:
                # pymongo has problems here:
                # http://api.mongodb.com/python/current/examples/
                #  datetimes.html#reading-time
                log.debug("Localizing last password change")
                expired = pytz.utc.localize(last_change) >= emitted

            if expired:
                self.auth.invalidate_token(token_id)
                raise RestApiException(
                    'Invalid reset token: this request is no longer valid',
                    status_code=400,
                )

        # The reset token is valid, do something
        data = self.get_input()
        new_password = data.get("new_password")
        password_confirm = data.get("password_confirm")

        # No password to be changed, just a token verification
        if new_password is None and password_confirm is None:
            return self.empty_response()

        # Something is missing
        if new_password is None or password_confirm is None:
            raise RestApiException(
                'Invalid password', status_code=400
            )

        if new_password != password_confirm:
            raise RestApiException(
                'New password does not match with confirmation',
                status_code=400,
            )

        security = HandleSecurity(self.auth)

        security.change_password(self.auth._user, None, new_password, password_confirm)
        # I really don't know why this save is required... since it is already
        # in change_password ... But if I remove it the new pwd is not saved...
        self.auth.save_user(self.auth._user)

        # Bye bye token (reset tokens are valid only once)
        self.auth.invalidate_token(token_id)

        return self.response("Password changed")
