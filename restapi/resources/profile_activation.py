# -*- coding: utf-8 -*-
import os
import jwt

from flask_apispec import MethodResource
from flask_apispec import use_kwargs
from marshmallow import fields

from restapi.rest.definition import EndpointResource
from restapi import decorators
from restapi.exceptions import RestApiException
from restapi.services.mail import send_mail
from restapi.confs import PRODUCTION, get_project_configuration
from restapi.utilities.templates import get_html_template

from restapi.utilities.logs import log


def send_activation_link(auth, user):

    title = get_project_configuration(
        "project.title", default='Unkown title'
    )

    activation_token, payload = auth.create_temporary_token(
        user, auth.ACTIVATE_ACCOUNT
    )

    domain = os.getenv("DOMAIN")
    protocol = 'https' if PRODUCTION else 'http'

    rt = activation_token.replace(".", "+")
    log.debug("Activation token: {}", rt)
    url = "{}://{}/public/register/{}".format(protocol, domain, rt)
    body = "Follow this link to activate your account: {}".format(url)

    # customized template
    template_file = "activate_account.html"
    html_body = get_html_template(template_file, {"url": url})
    if html_body is None:
        html_body = body
        body = None

    default_subject = "{} account activation".format(title)
    subject = os.getenv('EMAIL_ACTIVATION_SUBJECT', default_subject)

    sent = send_mail(html_body, subject, user.email, plain_body=body)
    if not sent:  # pragma: no cover
        raise BaseException("Error sending email, please retry")

    auth.save_token(
        user, activation_token, payload, token_type=auth.ACTIVATE_ACCOUNT)


class ProfileActivation(MethodResource, EndpointResource):
    depends_on = ["not PROFILE_DISABLED", "ALLOW_REGISTRATION"]
    baseuri = "/auth"
    labels = ["base", "profiles"]

    _POST = {
        "/profile/activate": {
            "summary": "Ask a new activation link",
            "responses": {
                "200": {"description": "A new activation link has been sent"}
            },
        }
    }
    _PUT = {
        "/profile/activate/<token>": {
            "summary": "Activate your account by providing the activation token",
            "responses": {
                "200": {"description": "Account successfully activated"}
            },
        }
    }

    @decorators.catch_errors()
    def put(self, token):

        token = token.replace("%2B", ".")
        token = token.replace("+", ".")
        try:
            self.auth.verify_token(
                token,
                raiseErrors=True,
                token_type=self.auth.ACTIVATE_ACCOUNT
            )

        # If token is expired
        except jwt.exceptions.ExpiredSignatureError:
            raise RestApiException(
                'Invalid activation token: this request is expired',
                status_code=400,
            )

        # if token is not yet active
        except jwt.exceptions.ImmatureSignatureError:
            raise RestApiException(
                'Invalid activation token', status_code=400
            )

        # if token does not exist (or other generic errors)
        except BaseException:
            raise RestApiException(
                'Invalid activation token', status_code=400
            )

        # Recovering token object from jti
        token_obj = self.auth.get_tokens(token_jti=self.auth._jti)
        # Cannot be tested, this is an extra test to prevent any unauthorized access...
        # but invalid tokens are already refused above, with auth.verify_token
        if len(token_obj) == 0:  # pragma: no cover
            raise RestApiException(
                'Invalid activation token: this request is no longer valid',
                status_code=400,
            )

        # If user logged is already active, invalidate the token
        if self.auth._user.is_active:
            self.auth.invalidate_token(token)
            raise RestApiException(
                'Invalid activation token: this request is no longer valid',
                status_code=400,
            )

        # The activation token is valid, do something
        self.auth._user.is_active = True
        self.auth.save_user(self.auth._user)

        # Bye bye token (activation tokens are valid only once)
        self.auth.invalidate_token(token)

        return self.response("Account activated")

    @decorators.catch_errors()
    @use_kwargs({'username': fields.Email(required=True)})
    def post(self, username):

        user = self.auth.get_user_object(username=username)

        # if user is None this endpoint does nothing but the response
        # remain the same to prevent any user guessing
        if user is not None:
            send_activation_link(self.auth, user)
        msg = (
            "We are sending an email to your email address where "
            "you will find the link to activate your account"
        )
        return self.response(msg)
